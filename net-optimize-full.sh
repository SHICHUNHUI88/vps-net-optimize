#!/usr/bin/env bash
# net-optimize-full.v2.3.sh
# 安全基线 + 可选开关（MSS/conntrack/nginx/fq_pie），幂等可回滚，容错增强
set -euo pipefail

# === 自动自更新 + 自动保存副本（含 curl/wget & sha256 兜底）===
SCRIPT_PATH="/usr/local/sbin/net-optimize-full.sh"
REMOTE_URL="https://raw.githubusercontent.com/SHICHUNHUI88/vps-net-optimize/main/net-optimize-full.sh"

fetch_raw() {
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$1"
  elif command -v wget >/dev/null 2>&1; then
    wget -qO- "$1"
  else
    echo "curl/wget 不可用，跳过在线更新" >&2
    return 1
  fi
}

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum | cut -d' ' -f1
  elif command -v openssl >/dev/null 2>&1; then
    openssl dgst -sha256 | awk '{print $2}'
  else
    cat >/dev/null
    echo ""
  fi
}

remote_buf="$(fetch_raw "$REMOTE_URL" || true)"
if [ -n "${remote_buf:-}" ]; then
  remote_hash="$(printf "%s" "$remote_buf" | sha256_of)"
  local_hash="$( [ -f "$SCRIPT_PATH" ] && sha256sum "$SCRIPT_PATH" 2>/dev/null | cut -d' ' -f1 || echo "" )"

  if [ -n "$remote_hash" ] && [ "$remote_hash" != "$local_hash" ]; then
    echo "🌀 检测到 GitHub 上有新版本，正在自动更新..."
    printf "%s" "$remote_buf" > "$SCRIPT_PATH"
    chmod +x "$SCRIPT_PATH"
    echo "✅ 已更新到最新版，重新执行..."
    exec "$SCRIPT_PATH" "$@"
    exit 0
  fi
fi

# 首次运行或本地执行时，将当前脚本同步到系统路径，便于以后直接调用
install -Dm755 "$0" "$SCRIPT_PATH" 2>/dev/null || true
echo "💾 当前脚本已同步到 $SCRIPT_PATH"

# —— 错误追踪：打印出错行与命令 —— #
trap 'code=$?; echo "❌ 出错：第 ${BASH_LINENO[0]} 行 -> ${BASH_COMMAND} (退出码 $code)"; exit $code' ERR

echo "🚀 开始执行全局网络优化（TCP/UDP/ulimit/MSS/可选项）..."
echo "------------------------------------------------------------"

# ============== 基础 & 工具函数 ==============
require_root() { [[ ${EUID:-$(id -u)} -eq 0 ]] || { echo "❌ 请用 root 运行"; exit 1; }; }
have_cmd() { command -v "$1" >/dev/null 2>&1; }
has_sysctl_key(){ local p="/proc/sys/${1//./\/}"; [[ -e "$p" ]]; }
get_sysctl(){ sysctl -n "$1" 2>/dev/null || echo "N/A"; }

detect_distro() {
  local id codename
  if [ -r /etc/os-release ]; then
    . /etc/os-release
    id="${ID:-unknown}"
    codename="${VERSION_CODENAME:-${UBUNTU_CODENAME:-unknown}}"
  else
    id="unknown"
    codename="unknown"
  fi
  echo "${id}:${codename}"
}

require_root
interactive=0
[ -t 0 ] && interactive=1

# ⚙️ 全局功能开关（默认全部开启）
: "${ENABLE_FQ_PIE:=1}"              # 1: 使用 fq_pie（推荐）
: "${ENABLE_MTU_PROBE:=1}"           # 1: 稳妥模式 MTU Probing
: "${ENABLE_MSS_CLAMP:=1}"           # 1: 开启 MSS Clamp
: "${CLAMP_IFACE:=}"                 # 自动识别出口网卡
: "${MSS_VALUE:=1452}"               # 通用保守值

: "${ENABLE_CONNTRACK_TUNE:=1}"      # 1: 开启 conntrack 调优
: "${NFCT_MAX:=262144}"
: "${NFCT_UDP_TO:=30}"
: "${NFCT_UDP_STREAM_TO:=180}"

: "${ENABLE_NGINX_REPO:=1}"          # 1: 使用 nginx.org 官方源
: "${APPLY_AT_BOOT:=1}"              # 1: 开机自动恢复所有调优
: "${SKIP_APT:=0}"                   # 0: 允许 apt 自动安装依赖

CONFIG_DIR="/etc/net-optimize"
CONFIG_FILE="$CONFIG_DIR/config"
APPLY_SCRIPT="/usr/local/sbin/net-optimize-apply"

# ============== 工具安装（apt 系列，其他发行版自动跳过） ==============
maybe_install_tools() {
  if [ "$SKIP_APT" = "1" ]; then
    echo "⏭️ 跳过工具安装（SKIP_APT=1）"
    return 0
  fi
  if have_cmd apt-get; then
    echo "🧰 安装必要工具（apt）..."
    DEBIAN_FRONTEND=noninteractive apt-get update -y || echo "⚠️ apt-get update 失败，继续执行基线优化"
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      ca-certificates ethtool iproute2 irqbalance chrony nftables conntrack curl gpg lsb-release iptables \
      || echo "⚠️ apt-get install 失败，某些可选功能可能不可用"
    systemctl enable --now irqbalance chrony nftables >/dev/null 2>&1 || true
  else
    echo "ℹ️ 非 apt 系统，跳过工具安装"
  fi
}

# ============== 清理旧状态（只清理我们管的内容） ==============
clean_old_config() {
  echo "🧹 清理旧配置..."
  rm -f /etc/systemd/system/net-optimize.service 2>/dev/null || true
  if have_cmd iptables; then
    iptables -t mangle -S 2>/dev/null | grep TCPMSS | sed 's/^-A/iptables -t mangle -D/' | bash 2>/dev/null || true
  fi
}

# ============== 拥塞控制 & 队列 ==============
setup_tcp_congestion() {
  echo "📶 设置 TCP 拥塞算法和队列..."
  local cc_algo="cubic"
  if sysctl net.ipv4.tcp_available_congestion_control 2>/dev/null | grep -qw bbrplus; then
    cc_algo="bbrplus"
  elif sysctl net.ipv4.tcp_available_congestion_control 2>/dev/null | grep -qw bbr; then
    cc_algo="bbr"
  fi
  has_sysctl_key net.ipv4.tcp_congestion_control && sysctl -w net.ipv4.tcp_congestion_control="$cc_algo" >/dev/null

  local qdisc="fq"
  if lsmod | grep -qw fq_pie && [ "$ENABLE_FQ_PIE" = "1" ]; then
    qdisc="fq_pie"
  fi
  has_sysctl_key net.core.default_qdisc && sysctl -w net.core.default_qdisc="$qdisc" >/dev/null
}

# ============== ulimit（limits.d + systemd） ==============
setup_ulimit() {
  echo "📂 设置 ulimit ..."
  install -d /etc/security/limits.d
  cat > /etc/security/limits.d/99-nofile.conf <<'EOF'
* soft nofile 1048576
* hard nofile 1048576
root soft nofile 1048576
root hard nofile 1048576
EOF

  if ! grep -q '^DefaultLimitNOFILE' /etc/systemd/system.conf 2>/dev/null; then
    echo 'DefaultLimitNOFILE=1048576' >> /etc/systemd/system.conf
  else
    sed -i 's/^DefaultLimitNOFILE.*/DefaultLimitNOFILE=1048576/' /etc/systemd/system.conf
  fi
  systemctl daemon-reload >/dev/null

  for f in /etc/pam.d/common-session /etc/pam.d/common-session-noninteractive; do
    [ -f "$f" ] && grep -q pam_limits.so "$f" || echo "session required pam_limits.so" >> "$f"
  done
}

# ============== MTU 探测 ==============
enable_mtu_probe() {
  echo "🌐 启用 TCP MTU 探测（值：$ENABLE_MTU_PROBE）..."
  has_sysctl_key net.ipv4.tcp_mtu_probing && sysctl -w net.ipv4.tcp_mtu_probing="$ENABLE_MTU_PROBE" >/dev/null || true
}

# ============== MSS Clamping（纯 iptables 方案，Ubuntu + Debian 通用） ==============
detect_iface() {
  local iface="${CLAMP_IFACE:-}"
  if [ -z "$iface" ]; then
    iface=$(ip route get 1.1.1.1 2>/dev/null \
      | awk '{for(i=1;i<=NF;i++) if ($i=="dev") print $(i+1)}' \
      | head -n1)
    [ -z "$iface" ] && iface=$(ip -6 route get 240c::6666 2>/dev/null \
      | awk '{for(i=1;i<=NF;i++) if ($i=="dev") print $(i+1)}' \
      | head -n1)
  fi
  echo -n "$iface"
}

apply_mss_iptables() {
  local iface="$1" mss="$2"

  if ! have_cmd iptables; then
    echo "⚠️ 系统未安装 iptables，跳过 MSS Clamping"
    return 0
  fi

  modprobe ip_tables 2>/dev/null || true
  modprobe iptable_mangle 2>/dev/null || true

  if [ -n "$iface" ]; then
    iptables -t mangle -D POSTROUTING -o "$iface" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS 2>/dev/null || true
    iptables -t mangle -A POSTROUTING -o "$iface" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "$mss"
  else
    iptables -t mangle -D POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS 2>/dev/null || true
    iptables -t mangle -A POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "$mss"
  fi
}

setup_mss_clamping() {
  if [ "$ENABLE_MSS_CLAMP" != "1" ]; then
    echo "⏭️ 跳过 MSS Clamping（未开启）"
    return 0
  fi

  echo "📡 设置 MSS Clamping..."
  local iface; iface="$(detect_iface)"

  if [ -n "$iface" ]; then
    echo "🔎 检测到出口接口：$iface"
  else
    echo "⚠️ 未找到出口接口，将使用全局 MSS 规则（不限接口）"
  fi

  apply_mss_iptables "$iface" "$MSS_VALUE"

  install -d "$CONFIG_DIR"
  cat > "$CONFIG_FILE" <<EOF
ENABLE_MSS_CLAMP=1
CLAMP_IFACE=$iface
MSS_VALUE=$MSS_VALUE
EOF
}

# ============== conntrack（可选，写到 sysctl.d） ==============
nf_conntrack_optimize() {
  if [ "$ENABLE_CONNTRACK_TUNE" != "1" ]; then
    echo "⏭️ 跳过 conntrack 调优（未开启）"
    return 0
  fi
  echo "🧩 启用 nf_conntrack 并持久化 ..."
  modprobe nf_conntrack 2>/dev/null || true
  echo nf_conntrack > /etc/modules-load.d/nf_conntrack.conf
  install -d /etc/sysctl.d
  {
    echo "net.netfilter.nf_conntrack_max = ${NFCT_MAX}"
    echo "net.netfilter.nf_conntrack_udp_timeout = ${NFCT_UDP_TO}"
    echo "net.netfilter.nf_conntrack_udp_timeout_stream = ${NFCT_UDP_STREAM_TO}"
  } >> /etc/sysctl.d/99-net-optimize.conf
}

# ============== sysctl.d 持久化（统一落盘，容忍未知键） ==============
write_sysctl_conf() {
  echo "📊 写入 sysctl 参数到 /etc/sysctl.d/99-net-optimize.conf ..."
  install -d /etc/sysctl.d
  local f="/etc/sysctl.d/99-net-optimize.conf"

  {
    echo "# ===== Network Optimize (managed by net-optimize-full.v2.3.sh) ====="
    has_sysctl_key net.core.default_qdisc && echo "net.core.default_qdisc = $(get_sysctl net.core.default_qdisc | sed 's/ /_/g')"
    has_sysctl_key net.ipv4.tcp_congestion_control && echo "net.ipv4.tcp_congestion_control = $(get_sysctl net.ipv4.tcp_congestion_control | sed 's/ /_/g')"

    echo "net.core.netdev_max_backlog = 250000"
    echo "net.core.somaxconn = 65535"
    echo "net.ipv4.tcp_max_syn_backlog = 8192"
    echo "net.ipv4.tcp_syncookies = 1"
    echo "net.ipv4.tcp_fin_timeout = 15"
    echo "net.ipv4.ip_local_port_range = 1024 65535"

    has_sysctl_key net.ipv4.tcp_mtu_probing && echo "net.ipv4.tcp_mtu_probing = ${ENABLE_MTU_PROBE}"

    echo "net.core.rmem_max = 67108864"
    echo "net.core.wmem_max = 67108864"
    echo "net.core.rmem_default = 2621440"
    echo "net.core.wmem_default = 2621440"
    echo "net.ipv4.udp_rmem_min = 16384"
    echo "net.ipv4.udp_wmem_min = 16384"
    echo "net.ipv4.udp_mem = 65536 131072 262144"

    echo "net.ipv4.conf.all.rp_filter = 1"
    echo "net.ipv4.conf.default.rp_filter = 1"
    echo "net.ipv4.icmp_echo_ignore_broadcasts = 1"
    echo "net.ipv4.icmp_ignore_bogus_error_responses = 1"
  } > "$f"

  sysctl -e --system >/dev/null || echo "⚠️ 部分 sysctl 键内核不支持，已跳过但不影响其他项"
}

# ============== Nginx 官方源（强制启用，Ubuntu + Debian 兼容 + 每月自动更新） ==============
fix_nginx_repo() {
  if [ "$ENABLE_NGINX_REPO" != "1" ]; then
    echo "⏭️ 跳过 Nginx 源变更（未开启）"
    return 0
  fi

  echo "🔧 正在配置 nginx.org 官方源..."

  have_cmd apt-get || { 
    echo "⚠️ 非 apt 系统（不是 Debian/Ubuntu），跳过 Nginx 配置"; 
    return 0; 
  }

  local distro codename pkg_url
  IFS=":" read -r distro codename <<<"$(detect_distro)"

  case "$distro" in
    ubuntu) pkg_url="http://nginx.org/packages/ubuntu/";;
    debian) pkg_url="http://nginx.org/packages/debian/";;
    *)      echo "⚠️ 未识别发行版：$distro，将使用 Debian 通用源"; pkg_url="http://nginx.org/packages/debian/";;
  esac

  if [ -z "$codename" ] || [ "$codename" = "unknown" ]; then
    codename="$(lsb_release -sc 2>/dev/null || echo stable)"
  fi

  echo "📌 系统类型: $distro"
  echo "📌 Codename: $codename"
  echo "📌 使用 Nginx 源: ${pkg_url}${codename}"

  DEBIAN_FRONTEND=noninteractive apt-get install -y \
    software-properties-common apt-transport-https gnupg2 ca-certificates lsb-release curl \
    || echo "⚠️ 安装依赖失败，继续尝试配置源"

  rm -f /etc/apt/sources.list.d/nginx.list

  cat > /etc/apt/sources.list.d/nginx.list <<EOF
deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] ${pkg_url} ${codename} nginx
deb-src [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] ${pkg_url} ${codename} nginx
EOF

  curl -fsSL https://nginx.org/keys/nginx_signing.key \
    | gpg --dearmor --yes -o /usr/share/keyrings/nginx-archive-keyring.gpg || true

  cat > /etc/apt/preferences.d/99nginx <<'EOF'
Package: nginx*
Pin: origin nginx.org
Pin-Priority: 1001
EOF

  apt-get update -y || true
  apt-get remove -y nginx-core nginx-common nginx-full nginx-light >/dev/null 2>&1 || true

  echo "📦 正在安装 nginx.org 最新版..."
  DEBIAN_FRONTEND=noninteractive apt-get install -y nginx || {
    echo "❌ 安装 nginx.org 失败，请手动检查网络或源";
    return 1;
  }

  systemctl restart nginx || true
  systemctl status nginx | grep Active || true

  local cron_job="0 3 1 * * /bin/bash -c 'DEBIAN_FRONTEND=noninteractive apt-get update -y && apt-get install -y nginx'"
  local tmpfile
  tmpfile="$(mktemp)"
  crontab -l -u root 2>/dev/null > "$tmpfile" || true
  grep -Fq "$cron_job" "$tmpfile" || echo "$cron_job" >> "$tmpfile"
  crontab -u root "$tmpfile" || true
  rm -f "$tmpfile"

  echo "✅ 已配置 nginx.org 官方源并安装最新 Nginx（含每月自动更新）"
}

# ============== 开机自恢复（sysctl + MSS） ==============
install_apply_script() {
  install -d "$CONFIG_DIR"
  cat > "$APPLY_SCRIPT" <<'EOS'
#!/usr/bin/env bash
set -euo pipefail
CONFIG_DIR="/etc/net-optimize"
CONFIG_FILE="$CONFIG_DIR/config"
have_cmd(){ command -v "$1" >/dev/null 2>&1; }

/usr/sbin/sysctl -e --system >/dev/null || true

if [ -f "$CONFIG_FILE" ]; then
  . "$CONFIG_FILE"
  if [ "${ENABLE_MSS_CLAMP:-0}" = "1" ]; then
    IFACE="${CLAMP_IFACE:-}"
    MSS="${MSS_VALUE:-1452}"
    if have_cmd iptables; then
      modprobe ip_tables 2>/dev/null || true
      modprobe iptable_mangle 2>/dev/null || true
      if [ -n "$IFACE" ]; then
        iptables -t mangle -D POSTROUTING -o "$IFACE" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS 2>/dev/null || true
        iptables -t mangle -A POSTROUTING -o "$IFACE" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "$MSS"
      else
        iptables -t mangle -D POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS 2>/dev/null || true
        iptables -t mangle -A POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "$MSS"
      fi
    fi
  fi
fi
EOS
  chmod +x "$APPLY_SCRIPT"

  cat > /etc/systemd/system/net-optimize-apply.service <<'EOL'
[Unit]
Description=Apply network optimization at boot (sysctl.d + MSS clamp)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/net-optimize-apply

[Install]
WantedBy=multi-user.target
EOL
  systemctl daemon-reload
  systemctl enable net-optimize-apply.service >/dev/null 2>&1 || true
}

# ============== 状态输出 ==============
print_status() {
  echo "------------------------------------------------------------"
  echo "✅ 拥塞算法：$(get_sysctl net.ipv4.tcp_congestion_control)"
  echo "✅ 默认队列：$(get_sysctl net.core.default_qdisc)"
  echo "✅ MTU 探测：$(get_sysctl net.ipv4.tcp_mtu_probing)"
  echo "✅ UDP rmem_min：$(get_sysctl net.ipv4.udp_rmem_min)"
  if [ -f /proc/sys/net/netfilter/nf_conntrack_max ]; then
    echo "✅ nf_conntrack_max：$(get_sysctl net.netfilter.nf_conntrack_max)"
  else
    echo "ℹ️ nf_conntrack 未启用（按需 ENABLE_CONNTRACK_TUNE=1 可开启）"
  fi
  echo "✅ 当前 ulimit：$(ulimit -n)"

  echo "✅ MSS Clamping 规则："
  local found=0
  if have_cmd nft; then
    nft list ruleset 2>/dev/null | grep -E 'maxseg|TCPMSS' && found=1 || true
  fi
  if have_cmd iptables; then
    iptables -t mangle -L -n -v | grep -E 'TCPMSS' && found=1 || true
  fi
  if [ "$found" != "1" ]; then
    echo "⚠️ 未检测到 MSS 规则"
  fi

  echo "✅ UDP 监听："
  ss -u -l -n -p | grep -E 'LISTEN|UNCONN' || echo "⚠️ 无 UDP 监听"
  if have_cmd conntrack; then
    echo "✅ UDP 活跃连接数：$(conntrack -L -p udp 2>/dev/null | wc -l)"
  else
    echo "ℹ️ 未安装 conntrack（可 apt install conntrack）"
  fi
  echo "------------------------------------------------------------"
}

ask_reboot() {
  if [ "$interactive" = "1" ]; then
    read -r -p "🔁 是否立即重启以使优化生效？(y/N): " answer
    if [[ "$answer" =~ ^[Yy]$ ]]; then
      echo "🌀 正在重启..."
      (sleep 1; reboot) &
    else
      echo "📌 请稍后手动重启以生效所有配置"
    fi
  else
    echo "📌 非交互模式执行，未触发重启，建议手动重启"
  fi
}

# ============== 主流程 ==============
main() {
  maybe_install_tools
  clean_old_config
  setup_tcp_congestion
  setup_ulimit
  enable_mtu_probe
  setup_mss_clamping
  write_sysctl_conf
  nf_conntrack_optimize
  fix_nginx_repo
  install_apply_script
  print_status
  ask_reboot
  echo "🎉 网络优化完成：sysctl.d 持久化 + MSS/conntrack/nginx/fq_pie + nginx 源，开机自动应用。"
}

main