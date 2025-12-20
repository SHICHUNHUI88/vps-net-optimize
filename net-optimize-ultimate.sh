#!/usr/bin/env bash
# ==============================================================================
# 🚀 Net-Optimize-Ultimate v3.2.2 (最终整合版)
# 功能：深度整合优化 + UDP活跃修复 + 智能检测 + 安全持久化
# 关键修复：
#   1) conntrack 检测不依赖 lsmod（兼容内建）
#   2) qdisc 判断用“真实写入尝试”而不是 lsmod
#   3) sysctl 权威收敛：自动扫描 /etc/sysctl.d/*.conf（保留指定文件）
#   4) MSS Clamping 三后端一致：iptables / iptables-nft / iptables-legacy
#   5) 修复你之前遇到的：grep -c 输出 0\n0 + 算术爆炸、MSS 返回码反了、count 写法错误
# ==============================================================================

set -euo pipefail

# === 1. 自动更新机制 ===
SCRIPT_PATH="/usr/local/sbin/net-optimize-ultimate.sh"
REMOTE_URL="https://raw.githubusercontent.com/SHICHUNHUI88/vps-net-optimize/main/net-optimize-ultimate.sh"

fetch_raw() {
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$1"
  elif command -v wget >/dev/null 2>&1; then
    wget -qO- "$1"
  else
    return 1
  fi
}

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum | cut -d' ' -f1
  elif command -v openssl >/dev/null 2>&1; then
    openssl dgst -sha256 | awk '{print $2}'
  else
    echo ""
  fi
}

remote_buf="$(fetch_raw "$REMOTE_URL" || true)"
if [ -n "${remote_buf:-}" ]; then
  remote_hash="$(printf "%s" "$remote_buf" | sha256_of)"
  local_hash="$([ -f "$SCRIPT_PATH" ] && sha256sum "$SCRIPT_PATH" 2>/dev/null | cut -d' ' -f1 || echo "")"
  if [ -n "$remote_hash" ] && [ "$remote_hash" != "$local_hash" ]; then
    echo "🌀 检测到新版本，正在更新..."
    printf "%s" "$remote_buf" >"$SCRIPT_PATH"
    chmod +x "$SCRIPT_PATH"
    exec "$SCRIPT_PATH" "$@"
    exit 0
  fi
fi

# 当你用 bash <(curl ...) 运行时，$0 可能是 /dev/fd/*，这里允许失败
install -Dm755 "$0" "$SCRIPT_PATH" 2>/dev/null || true

trap 'code=$?; echo "❌ 出错：第 ${BASH_LINENO[0]} 行 -> ${BASH_COMMAND} (退出码 $code)"; exit $code' ERR

echo "🚀 Net-Optimize-Ultimate v3.2.2 开始执行..."
echo "========================================================"

# === 2. 全局配置开关 ===
: "${ENABLE_FQ_PIE:=1}"
: "${ENABLE_MTU_PROBE:=1}"
: "${ENABLE_MSS_CLAMP:=1}"
: "${MSS_VALUE:=1452}"
: "${ENABLE_CONNTRACK_TUNE:=1}"
: "${NFCT_MAX:=262144}"
: "${ENABLE_NGINX_REPO:=1}"
: "${SKIP_APT:=1}"
: "${APPLY_AT_BOOT:=1}"

# 路径定义
CONFIG_DIR="/etc/net-optimize"
CONFIG_FILE="$CONFIG_DIR/config"
MODULES_FILE="$CONFIG_DIR/modules.list"
APPLY_SCRIPT="/usr/local/sbin/net-optimize-apply"

# === 3. 核心工具函数 ===
require_root() {
  [[ ${EUID:-$(id -u)} -eq 0 ]] || {
    echo "❌ 请使用 root 用户运行"
    exit 1
  }
}

have_cmd() { command -v "$1" >/dev/null 2>&1; }

has_sysctl_key() {
  local p="/proc/sys/${1//.//}"
  [[ -e "$p" ]]
}

get_sysctl() { sysctl -n "$1" 2>/dev/null || echo "N/A"; }

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

check_dpkg_clean() {
  if have_cmd dpkg && dpkg --audit 2>/dev/null | grep -q .; then
    echo "⚠️ 检测到 dpkg 状态异常，请先执行修复："
    echo "  dpkg --configure -a"
    echo "  apt-get --fix-broken install -y"
    exit 1
  fi
}

# === v3.2.2：conntrack 可用性检测（不依赖 lsmod）===
conntrack_available() {
  has_sysctl_key net.netfilter.nf_conntrack_max && return 0

  if [ -d /proc/sys/net/netfilter ] && ls /proc/sys/net/netfilter/nf_conntrack* >/dev/null 2>&1; then
    return 0
  fi

  [ -f /proc/net/nf_conntrack ] && return 0
  return 1
}

# === v3.2.2：qdisc 真实可设置探测（不依赖 lsmod）===
try_set_qdisc() {
  local q="$1"
  has_sysctl_key net.core.default_qdisc || return 1
  sysctl -w net.core.default_qdisc="$q" >/dev/null 2>&1
}

# === 3.5 Sysctl 权威收敛（避免多脚本互相覆盖）===
SYSCTL_BACKUP_DIR="/etc/net-optimize/sysctl-backup"
SYSCTL_AUTH_FILE="/etc/sysctl.d/99-net-optimize.conf"

backup_and_disable_sysctl_file() {
  local f="$1"
  [ -f "$f" ] || return 0

  # 只对“写冲突键”的文件动手，避免误伤
  if ! grep -Eq '^\s*net\.core\.default_qdisc\s*=|^\s*net\.core\.rmem_default\s*=|^\s*net\.core\.wmem_default\s*=|^\s*net\.ipv4\.tcp_congestion_control\s*=|^\s*net\.ipv4\.conf\.(all|default)\.rp_filter\s*=' "$f"; then
    return 0
  fi

  mkdir -p "$SYSCTL_BACKUP_DIR"
  local ts
  ts="$(date +%F-%H%M%S)"

  echo "🧯 发现冲突 sysctl 文件：$f"
  cp -a "$f" "$SYSCTL_BACKUP_DIR/$(basename "$f").bak-$ts"
  mv "$f" "$f.disabled-by-net-optimize-$ts"
  echo "  ✅ 已备份并禁用：$f"
}

converge_sysctl_authority() {
  echo "🧠 收敛 sysctl 权威（只保留 v3.x 的配置生效）..."

  local keep1="$SYSCTL_AUTH_FILE"
  local keep2="/etc/sysctl.d/zzz-bbrplus.conf"

  shopt -s nullglob
  local f
  for f in /etc/sysctl.d/*.conf; do
    [ "$f" = "$keep1" ] && continue
    [ "$f" = "$keep2" ] && continue
    backup_and_disable_sysctl_file "$f"
  done
  shopt -u nullglob

  if [ -f "$keep2" ]; then
    echo "✅ 保留 bbrplus 权威文件：$keep2（不做处理）"
  else
    echo "⚠️ 未发现 $keep2（如需 fq_pie/bbrplus 兜底请确认 bbrplus 脚本）"
  fi
}

# === 4. 清理旧配置 ===
clean_old_config() {
  echo "🧹 清理旧配置..."

  # 清理旧服务
  systemctl stop net-optimize.service 2>/dev/null || true
  systemctl disable net-optimize.service 2>/dev/null || true
  rm -f /etc/systemd/system/net-optimize.service

  # 清理旧规则（只动当前默认后端的 iptables）
  if have_cmd iptables; then
    iptables -t mangle -S POSTROUTING 2>/dev/null | grep -E '(^-A POSTROUTING .*TCPMSS| TCPMSS )' | while read -r rule; do
      del_rule="${rule/-A POSTROUTING/-D POSTROUTING}"
      # shellcheck disable=SC2086
      iptables -t mangle $del_rule 2>/dev/null || true
    done
  fi

  # 不要 rm -rf 整个目录（否则 sysctl-backup 也会被删）
  mkdir -p "$CONFIG_DIR"
  rm -f "$CONFIG_FILE" "$MODULES_FILE"
}

# === 5. 工具安装（可选）===
maybe_install_tools() {
  if [ "$SKIP_APT" = "1" ]; then
    echo "⏭️ 跳过工具安装（SKIP_APT=1）"
    return 0
  fi

  if ! have_cmd apt-get; then
    echo "ℹ️ 非APT系统，跳过工具安装"
    return 0
  fi

  echo "🧰 安装必要工具..."
  check_dpkg_clean

  DEBIAN_FRONTEND=noninteractive apt-get update -y || echo "⚠️ apt update 失败"

  local packages=""
  packages+=" ca-certificates curl wget gnupg2 lsb-release"
  packages+=" ethtool iproute2 irqbalance chrony"
  packages+=" nftables conntrack iptables"
  packages+=" software-properties-common apt-transport-https"

  # shellcheck disable=SC2086
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends $packages || echo "⚠️ 部分包安装失败"

  systemctl enable --now irqbalance chrony 2>/dev/null || true
}

# === 6. Ulimit 优化 ===
setup_ulimit() {
  echo "📂 优化文件描述符限制..."

  install -d /etc/security/limits.d
  cat > /etc/security/limits.d/99-net-optimize.conf <<'EOF'
# Net-Optimize Ultimate - File Descriptor Limits
*    soft nofile 1048576
*    hard nofile 1048576
root soft nofile 1048576
root hard nofile 1048576
EOF

  if ! grep -q '^DefaultLimitNOFILE=' /etc/systemd/system.conf 2>/dev/null; then
    echo 'DefaultLimitNOFILE=1048576' >> /etc/systemd/system.conf
  else
    sed -i 's/^DefaultLimitNOFILE=.*/DefaultLimitNOFILE=1048576/' /etc/systemd/system.conf
  fi

  for pam_file in /etc/pam.d/common-session /etc/pam.d/common-session-noninteractive; do
    if [ -f "$pam_file" ] && ! grep -q "pam_limits.so" "$pam_file"; then
      echo "session required pam_limits.so" >> "$pam_file"
    fi
  done

  systemctl daemon-reload >/dev/null 2>&1 || true
  echo "✅ ulimit 配置完成"
}

# === 7. 拥塞控制与队列算法（真实验证版）===
setup_tcp_congestion() {
  echo "📶 设置TCP拥塞算法和队列..."

  # qdisc：真实尝试写入
  if [ "$ENABLE_FQ_PIE" = "1" ] && try_set_qdisc fq_pie; then
    :
  elif try_set_qdisc fq; then
    :
  elif try_set_qdisc pie; then
    :
  else
    :
  fi

  # 拥塞算法：BBRplus > BBR > Cubic
  local target_cc="cubic"
  local available_cc
  available_cc=$(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null || echo "cubic")

  if echo "$available_cc" | grep -qw bbrplus; then
    target_cc="bbrplus"
  elif echo "$available_cc" | grep -qw bbr; then
    target_cc="bbr"
  fi

  if has_sysctl_key net.ipv4.tcp_congestion_control; then
    sysctl -w net.ipv4.tcp_congestion_control="$target_cc" >/dev/null 2>&1 || true
  fi

  local current_cc current_qdisc
  current_cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "unknown")
  current_qdisc=$(sysctl -n net.core.default_qdisc 2>/dev/null || echo "unknown")

  echo "✅ 最终生效拥塞算法: $current_cc"
  echo "✅ 最终生效队列算法: $current_qdisc"

  if [[ "$target_cc" == "bbr"* ]] && [[ "$current_cc" != "$target_cc" ]]; then
    echo "⚠️ 提示: 尝试启用 $target_cc 失败，系统自动回退到了 $current_cc"
  fi
}

# === 8. Sysctl 深度整合（写入文件）===
write_sysctl_conf() {
  echo "📊 写入内核参数配置文件..."

  local sysctl_file="$SYSCTL_AUTH_FILE"
  install -d /etc/sysctl.d

  {
    echo "# ========================================================="
    echo "# 🚀 Net-Optimize Ultimate v3.2.2 - Kernel Parameters"
    echo "# Generated: $(date)"
    echo "# ========================================================="
    echo

    echo "# === 基础网络设置 ==="
    echo "net.core.netdev_max_backlog = 250000"
    echo "net.core.somaxconn = 1000000"
    echo "net.ipv4.tcp_max_syn_backlog = 819200"
    echo "net.ipv4.tcp_syncookies = 1"
    echo

    echo "# === 连接生命周期 ==="
    echo "net.ipv4.tcp_fin_timeout = 15"
    echo "net.ipv4.tcp_keepalive_time = 600"
    echo "net.ipv4.tcp_keepalive_intvl = 15"
    echo "net.ipv4.tcp_keepalive_probes = 2"
    echo "net.ipv4.tcp_max_tw_buckets = 5000"
    echo "net.ipv4.ip_local_port_range = 1024 65535"
    echo

    echo "# === TCP算法优化 ==="
    echo "net.ipv4.tcp_mtu_probing = $ENABLE_MTU_PROBE"
    echo "net.ipv4.tcp_slow_start_after_idle = 0"
    echo "net.ipv4.tcp_no_metrics_save = 0"
    echo "net.ipv4.tcp_ecn = 1"
    echo "net.ipv4.tcp_ecn_fallback = 1"
    echo "net.ipv4.tcp_notsent_lowat = 16384"
    echo "net.ipv4.tcp_fastopen = 3"
    echo "net.ipv4.tcp_timestamps = 1"
    echo "net.ipv4.tcp_autocorking = 0"
    echo "net.ipv4.tcp_low_latency = 1"
    echo "net.ipv4.tcp_orphan_retries = 1"
    echo "net.ipv4.tcp_retries2 = 5"
    echo "net.ipv4.tcp_synack_retries = 1"
    echo "net.ipv4.tcp_rfc1337 = 0"
    echo

    echo "# === 内存缓冲区优化（64MB方案）==="
    echo "net.core.rmem_max = 67108864"
    echo "net.core.wmem_max = 67108864"
    echo "net.core.rmem_default = 67108864"
    echo "net.core.wmem_default = 67108864"
    echo "net.core.optmem_max = 65536"
    echo "net.ipv4.tcp_rmem = 4096 87380 67108864"
    echo "net.ipv4.tcp_wmem = 4096 65536 67108864"
    echo "net.ipv4.udp_rmem_min = 16384"
    echo "net.ipv4.udp_wmem_min = 16384"
    echo "net.ipv4.udp_mem = 65536 131072 262144"
    echo

    echo "# === UDP连接优化 ==="
    echo "net.ipv4.ip_forward = 1"
    echo "net.ipv4.conf.all.forwarding = 1"
    echo "net.ipv4.conf.default.forwarding = 1"
    echo "net.ipv4.conf.all.route_localnet = 1"
    echo "net.ipv4.conf.all.rp_filter = 0"
    echo "net.ipv4.conf.default.rp_filter = 0"
    echo

    echo "# === 安全加固 ==="
    echo "net.ipv4.conf.all.accept_redirects = 0"
    echo "net.ipv4.conf.default.accept_redirects = 0"
    echo "net.ipv4.conf.all.secure_redirects = 0"
    echo "net.ipv4.conf.default.secure_redirects = 0"
    echo "net.ipv4.conf.all.send_redirects = 0"
    echo "net.ipv4.conf.default.send_redirects = 0"
    echo "net.ipv4.icmp_echo_ignore_broadcasts = 1"
    echo "net.ipv4.icmp_ignore_bogus_error_responses = 1"
    echo "net.ipv4.icmp_echo_ignore_all = 0"
    echo

    echo "# === IPv6优化 ==="
    echo "net.ipv6.conf.all.disable_ipv6 = 0"
    echo "net.ipv6.conf.default.disable_ipv6 = 0"
    echo "net.ipv6.conf.all.forwarding = 1"
    echo "net.ipv6.conf.default.forwarding = 1"
    echo "net.ipv6.conf.all.accept_ra = 2"
    echo "net.ipv6.conf.default.accept_ra = 2"
    echo "net.ipv6.conf.all.use_tempaddr = 2"
    echo "net.ipv6.conf.default.use_tempaddr = 2"
    echo "net.ipv6.conf.all.accept_redirects = 0"
    echo "net.ipv6.conf.default.accept_redirects = 0"
    echo

    echo "# === 邻居表调优 ==="
    echo "net.ipv4.neigh.default.gc_thresh1 = 2048"
    echo "net.ipv4.neigh.default.gc_thresh2 = 4096"
    echo "net.ipv4.neigh.default.gc_thresh3 = 8192"
    echo "net.ipv6.neigh.default.gc_thresh1 = 2048"
    echo "net.ipv6.neigh.default.gc_thresh2 = 4096"
    echo "net.ipv6.neigh.default.gc_thresh3 = 8192"
    echo "net.ipv4.neigh.default.unres_qlen = 10000"
    echo

    echo "# === 内核安全 ==="
    echo "kernel.kptr_restrict = 1"
    echo "kernel.yama.ptrace_scope = 1"
    echo "kernel.sysrq = 176"
    echo "vm.mmap_min_addr = 65536"
    echo "vm.max_map_count = 1048576"
    echo "vm.swappiness = 1"
    echo "vm.overcommit_memory = 1"
    echo "kernel.pid_max = 4194304"
    echo

    echo "# === 文件系统保护 ==="
    echo "fs.protected_fifos = 1"
    echo "fs.protected_hardlinks = 1"
    echo "fs.protected_regular = 2"
    echo "fs.protected_symlinks = 1"
    echo

    if [ "$ENABLE_CONNTRACK_TUNE" = "1" ]; then
      echo "# === 连接跟踪优化 ==="
      echo "net.netfilter.nf_conntrack_max = $NFCT_MAX"
      echo "net.netfilter.nf_conntrack_udp_timeout = 30"
      echo "net.netfilter.nf_conntrack_udp_timeout_stream = 180"
      echo "net.netfilter.nf_conntrack_tcp_timeout_established = 432000"
      echo "net.netfilter.nf_conntrack_tcp_timeout_time_wait = 120"
      echo "net.netfilter.nf_conntrack_tcp_timeout_close_wait = 60"
      echo "net.netfilter.nf_conntrack_tcp_timeout_fin_wait = 120"
      echo
    fi
  } >"$sysctl_file"

  sysctl -e --system >/dev/null 2>&1 || echo "⚠️ 部分参数不支持，但不影响其他项"
  echo "✅ sysctl 参数已写入并应用"
}

# === 9. 连接跟踪模块加载 ===
setup_conntrack() {
  if [ "$ENABLE_CONNTRACK_TUNE" != "1" ]; then
    echo "⏭️ 跳过连接跟踪调优"
    return 0
  fi

  echo "🔗 加载连接跟踪模块..."

  local modules=("nf_conntrack" "nf_conntrack_ipv4" "nf_conntrack_ipv6" "nf_conntrack_ftp")
  local loaded_modules=()

  for mod in "${modules[@]}"; do
    if modprobe "$mod" 2>/dev/null; then
      loaded_modules+=("$mod")
      echo "  ✅ 加载: $mod"
    fi
  done

  if [ ${#loaded_modules[@]} -gt 0 ]; then
    install -d /etc/modules-load.d
    printf "%s\n" "${loaded_modules[@]}" | sort -u > /etc/modules-load.d/net-optimize.conf
  fi

  printf "%s\n" "${loaded_modules[@]}" | sort -u >"$MODULES_FILE"
  echo "✅ 连接跟踪模块配置完成"
}

# === 10. MSS Clamping 依赖：出口接口探测 ===
detect_outbound_iface() {
  local iface=""
  iface=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev") {print $(i+1); exit}}' | head -n1 || true)
  if [ -z "$iface" ]; then
    iface=$(ip -6 route get 2001:4860:4860::8888 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev") {print $(i+1); exit}}' | head -n1 || true)
  fi
  if [ -z "$iface" ]; then
    iface=$(ip route show default 2>/dev/null | awk '/default/ {print $5}' | head -n1 || true)
  fi
  echo "$iface"
}

# === 10. MSS Clamping（三后端去重版：避免 iptables/iptables-nft 重复叠加）===
setup_mss_clamping() {
    if [ "${ENABLE_MSS_CLAMP:-0}" != "1" ]; then
        echo "⏭️ 跳过MSS Clamping"
        return 0
    fi

    echo "📡 设置MSS Clamping (MSS=${MSS_VALUE})..."

    # 你脚本里已有 detect_outbound_iface() 的话就用它
    # 如果没有，会走到 fallback（全局规则）
    local iface=""
    if declare -F detect_outbound_iface >/dev/null 2>&1; then
        iface="$(detect_outbound_iface || true)"
    fi

    if [ -z "${iface:-}" ]; then
        echo "⚠️ 无法确定出口接口，将使用全局规则"
        iface=""
    else
        echo "✅ 检测到出口接口: $iface"
    fi

    # 保存配置（供开机脚本读取）
    mkdir -p "$(dirname "$CONFIG_FILE")"
    cat > "$CONFIG_FILE" <<EOF
ENABLE_MSS_CLAMP=1
CLAMP_IFACE=$iface
MSS_VALUE=$MSS_VALUE
EOF

    # 收集可用 iptables 命令，并做“后端去重”
    # 关键：iptables 和 iptables-nft 很可能指向同一套规则，不去重就会写两遍
    declare -A seen_sig
    local ipt_cmds=()

    _sig_of_backend() {
        local cmd="$1"
        # 用规则输出做 hash：同后端（同表）时输出几乎一致
        # 若失败则退回 cmd 名称（不影响）
        "$cmd" -t mangle -S 2>/dev/null | sha256sum 2>/dev/null | awk '{print $1}' || echo "$cmd"
    }

    _add_backend() {
        local cmd="$1"
        have_cmd "$cmd" || return 0
        local sig
        sig="$(_sig_of_backend "$cmd")"
        if [ -n "${seen_sig[$sig]:-}" ]; then
            echo "ℹ️ [$cmd] 与 [${seen_sig[$sig]}] 指向同一后端，跳过避免重复写"
            return 0
        fi
        seen_sig[$sig]="$cmd"
        ipt_cmds+=("$cmd")
    }

    _add_backend iptables
    _add_backend iptables-nft
    _add_backend iptables-legacy

    if [ "${#ipt_cmds[@]}" -eq 0 ]; then
        echo "⚠️ iptables 不可用，跳过 MSS 规则设置"
        return 0
    fi

    echo "✅ MSS 将写入的后端：${ipt_cmds[*]}"

    # 尽量加载相关模块（内建/不存在都不致命）
    echo "🛠️ 尝试加载 iptables 相关模块..."
    for module in ip_tables iptable_filter iptable_mangle x_tables; do
        modprobe "$module" 2>/dev/null || true
    done

    # 清理 TCPMSS：对每个“去重后的后端”都清理一次
    _mss_clear_one_backend() {
        local cmd="$1"
        echo "🧹 [$cmd] 清理旧 MSS 规则..."

        # 只删 POSTROUTING 链里的 TCPMSS，避免误删别的链
        # 循环删到没有为止
        local line
        while :; do
            line="$("$cmd" -t mangle -S POSTROUTING 2>/dev/null | grep -E '^-A POSTROUTING .*TCPMSS' | head -n1 || true)"
            [ -z "$line" ] && break
            "$cmd" -t mangle ${line/-A POSTROUTING/-D POSTROUTING} 2>/dev/null || true
        done
    }

    # 写入 TCPMSS：先 -C 检测避免重复
    _mss_apply_one_backend() {
        local cmd="$1"
        echo "➕ [$cmd] 写入 MSS 规则..."

        if [ -n "$iface" ] && [ "$iface" != "unknown" ]; then
            if "$cmd" -t mangle -C POSTROUTING -o "$iface" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "$MSS_VALUE" 2>/dev/null; then
                echo "  ✅ [$cmd] 已存在：iface=$iface MSS=$MSS_VALUE"
                return 0
            fi
            if "$cmd" -t mangle -A POSTROUTING -o "$iface" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "$MSS_VALUE" 2>/dev/null; then
                echo "  ✅ [$cmd] 已添加：iface=$iface MSS=$MSS_VALUE"
                return 0
            fi
            echo "  ⚠️ [$cmd] 写入失败（iface 规则）"
            return 1
        else
            if "$cmd" -t mangle -C POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "$MSS_VALUE" 2>/dev/null; then
                echo "  ✅ [$cmd] 已存在：global MSS=$MSS_VALUE"
                return 0
            fi
            if "$cmd" -t mangle -A POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "$MSS_VALUE" 2>/dev/null; then
                echo "  ✅ [$cmd] 已添加：global MSS=$MSS_VALUE"
                return 0
            fi
            echo "  ⚠️ [$cmd] 写入失败（global 规则）"
            return 1
        fi
    }

    # 1) 清理
    for cmd in "${ipt_cmds[@]}"; do
        _mss_clear_one_backend "$cmd"
    done

    # 2) 写入
    local ok_any=0
    for cmd in "${ipt_cmds[@]}"; do
        if _mss_apply_one_backend "$cmd"; then
            ok_any=1
        fi
    done

    # 3) 验证（逐后端）
    echo "🔍 验证 MSS 规则（逐后端）..."
    for cmd in "${ipt_cmds[@]}"; do
        echo "---- [$cmd] ----"
        "$cmd" -t mangle -L POSTROUTING -n -v 2>/dev/null | grep -E 'Chain|pkts|bytes|TCPMSS' || echo "  (none)"
        echo "count: $("$cmd" -t mangle -S POSTROUTING 2>/dev/null | grep -c TCPMSS || true)"
    done

    if [ "$ok_any" -eq 1 ]; then
        echo "✅ MSS Clamping 设置完成（已避免重复叠加）"
        return 0
    fi

    echo "❌ MSS Clamping 设置失败（所有后端都未成功写入）"
    return 1
}

# === 11. Nginx官方源 + 自动更新（APT 可跳过，cron 永远可用）===
fix_nginx_repo() {
    if [ "$ENABLE_NGINX_REPO" != "1" ]; then
        echo "⏭️ 跳过Nginx配置"
        return 0
    fi

    # ========= 1. 自动更新 cron（无论 SKIP_APT）=========
    local cron_file="/etc/cron.d/net-optimize-nginx-update"
    if [ ! -f "$cron_file" ]; then
        cat > "$cron_file" <<'CRON_JOB'
# Net-Optimize: monthly nginx upgrade
0 3 1 * * root DEBIAN_FRONTEND=noninteractive apt-get update && apt-get install --only-upgrade -y nginx > /var/log/nginx-auto-upgrade.log 2>&1
CRON_JOB
        chmod 644 "$cron_file"
        echo "✅ 已创建 Nginx 自动更新 cron（每月一次）"
    else
        echo "ℹ️ Nginx 自动更新 cron 已存在"
    fi

    # ========= 2. 若 SKIP_APT=1，到此为止 =========
    if [ "$SKIP_APT" = "1" ]; then
        echo "⏭️ SKIP_APT=1，跳过 Nginx 源与安装，仅保留自动更新 cron"
        return 0
    fi

    # ========= 3. 以下才是真正的 APT 操作 =========
    if ! have_cmd apt-get; then
        echo "⚠️ 非APT系统，跳过Nginx源配置"
        return 0
    fi

    echo "🔧 配置 nginx.org 官方源..."

    local distro codename
    distro="$(. /etc/os-release; echo "$ID")"
    codename="$(. /etc/os-release; echo "${VERSION_CODENAME:-stable}")"

    local base="http://nginx.org/packages"
    [ "$distro" = "ubuntu" ] && base="$base/ubuntu" || base="$base/debian"

    curl -fsSL https://nginx.org/keys/nginx_signing.key \
      | gpg --dearmor -o /usr/share/keyrings/nginx-archive-keyring.gpg

    cat > /etc/apt/sources.list.d/nginx-official.list <<EOF
deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] $base $codename nginx
EOF

    cat > /etc/apt/preferences.d/99-nginx-official <<'EOF'
Package: nginx*
Pin: origin nginx.org
Pin-Priority: 1001
EOF

    apt-get update -y
    apt-get install -y nginx

    systemctl enable nginx >/dev/null 2>&1 || true
    systemctl restart nginx >/dev/null 2>&1 || true

    echo "✅ Nginx 官方源 + 安装完成"
}

# === 12. 开机自启服务（同步三后端 MSS 写入）===
install_boot_service() {
  if [ "$APPLY_AT_BOOT" != "1" ]; then
    echo "⏭️ 跳过开机自启配置"
    return 0
  fi

  echo "🛠️ 配置开机自启动服务..."

  cat >"$APPLY_SCRIPT" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

MODULES_FILE="/etc/net-optimize/modules.list"
if [ -f "$MODULES_FILE" ]; then
  while IFS= read -r module; do
    [ -n "$module" ] && modprobe "$module" 2>/dev/null || true
  done <"$MODULES_FILE"
fi

sysctl -e --system >/dev/null 2>&1 || true

CONFIG_FILE="/etc/net-optimize/config"
if [ -f "$CONFIG_FILE" ]; then
  . "$CONFIG_FILE"

  if [ "${ENABLE_MSS_CLAMP:-0}" = "1" ]; then
    MSS="${MSS_VALUE:-1452}"
    IFACE="${CLAMP_IFACE:-}"

    # 三后端一致：iptables / iptables-nft / iptables-legacy
    ipt_cmds=()
    for c in iptables iptables-nft iptables-legacy; do
      command -v "$c" >/dev/null 2>&1 && ipt_cmds+=("$c")
    done

    if [ "${#ipt_cmds[@]}" -gt 0 ]; then
      modprobe ip_tables 2>/dev/null || true
      modprobe iptable_mangle 2>/dev/null || true

      for cmd in "${ipt_cmds[@]}"; do
        # 清理旧 TCPMSS
        rules="$("$cmd" -t mangle -S POSTROUTING 2>/dev/null | grep -E '(^-A POSTROUTING .*TCPMSS| TCPMSS )' || true)"
        if [ -n "$rules" ]; then
          while IFS= read -r rule; do
            [ -z "$rule" ] && continue
            del="${rule/-A POSTROUTING/-D POSTROUTING}"
            read -r -a parts <<<"$del"
            "$cmd" -t mangle "${parts[@]}" 2>/dev/null || true
          done <<<"$rules"
        fi

        # 写入新规则（避免重复）
        if [ -n "$IFACE" ] && [ "$IFACE" != "unknown" ]; then
          "$cmd" -t mangle -C POSTROUTING -o "$IFACE" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "$MSS" 2>/dev/null \
            || "$cmd" -t mangle -A POSTROUTING -o "$IFACE" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "$MSS" 2>/dev/null || true
        else
          "$cmd" -t mangle -C POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "$MSS" 2>/dev/null \
            || "$cmd" -t mangle -A POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "$MSS" 2>/dev/null || true
        fi
      done
    fi
  fi
fi

echo "[$(date)] Net-Optimize 开机优化完成"
EOF

  chmod +x "$APPLY_SCRIPT"

  cat > /etc/systemd/system/net-optimize.service <<'EOF'
[Unit]
Description=Net-Optimize Ultimate Boot Optimization
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/net-optimize-apply
RemainAfterExit=yes
StandardOutput=journal
TimeoutSec=30

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable net-optimize.service >/dev/null 2>&1

  echo "✅ 开机自启服务配置完成"
}

# === 13. 状态检查（完整）===
print_status() {
  echo ""
  echo "==================== 优化状态报告 ===================="

  echo "📊 基础状态:"
  echo "  TCP拥塞算法: $(get_sysctl net.ipv4.tcp_congestion_control)"
  echo "  默认队列: $(get_sysctl net.core.default_qdisc)"
  echo "  文件句柄限制: $(ulimit -n)"
  echo "  内存缓冲区: $(get_sysctl net.core.rmem_default) bytes"
  echo ""

  echo "🌐 网络状态:"
  echo "  IP转发: $(get_sysctl net.ipv4.ip_forward)"
  echo "  路由过滤: $(get_sysctl net.ipv4.conf.all.rp_filter)"
  echo "  IPv6状态: $(get_sysctl net.ipv6.conf.all.disable_ipv6)"
  echo "  TCP ECN: $(get_sysctl net.ipv4.tcp_ecn)"
  echo "  TCP FastOpen: $(get_sysctl net.ipv4.tcp_fastopen)"
  echo ""

  echo "🔗 连接跟踪:"
  if conntrack_available; then
    echo "  ✅ conntrack 可用（模块或内建）"
    echo "  最大连接数: $(get_sysctl net.netfilter.nf_conntrack_max)"

    if [ -f /proc/net/nf_conntrack ]; then
      udp_count="$(grep -c '^udp' /proc/net/nf_conntrack 2>/dev/null || true)"
      tcp_count="$(grep -c '^tcp' /proc/net/nf_conntrack 2>/dev/null || true)"

      udp_count="${udp_count%%$'\n'*}"; udp_count="${udp_count:-0}"
      tcp_count="${tcp_count%%$'\n'*}"; tcp_count="${tcp_count:-0}"

      echo "  UDP连接: $udp_count"
      echo "  TCP连接: $tcp_count"
      echo "  总连接数: $((udp_count + tcp_count))"
    else
      echo "  ℹ️ /proc/net/nf_conntrack 不存在（可能是 nftables / 内核暴露差异）"
    fi
  else
    echo "  ⚠️ conntrack 不可用（内核未启用 netfilter conntrack）"
  fi
  echo ""

  echo "📡 MSS Clamping规则（默认后端 iptables）:"
  if have_cmd iptables && iptables -t mangle -L POSTROUTING -n 2>/dev/null | grep -q TCPMSS; then
    iptables -t mangle -L POSTROUTING -n -v 2>/dev/null | grep TCPMSS || true
  else
    echo "  ⚠️ 未找到MSS规则（可能当前默认后端不是 iptables；用 iptables-nft/legacy 看）"
  fi
  echo ""

  echo "💻 系统信息:"
  echo "  内核版本: $(uname -r)"
  echo "  发行版: $(detect_distro)"
  echo "  内存: $(free -h | awk '/^Mem:/ {print $2}')"
  echo "  可用内存: $(free -h | awk '/^Mem:/ {print $7}')"

  echo "======================================================"
  echo ""
}

# === 14. 主流程 ===
main() {
  require_root

  echo "🚀 Net-Optimize-Ultimate v3.2.2 启动..."
  echo "========================================================"

  clean_old_config
  maybe_install_tools
  setup_ulimit
  setup_tcp_congestion
  converge_sysctl_authority
  write_sysctl_conf
  setup_conntrack
  setup_mss_clamping
  fix_nginx_repo
  install_boot_service

  print_status

  echo "✅ 所有优化配置完成！"
  echo ""
  echo "📌 重要提示："
  echo "  1. 64MB缓冲区需要重启后完全生效"
  echo "  2. 检查状态: systemctl status net-optimize"
  echo "  3. 查看连接: cat /proc/net/nf_conntrack | head -20"
  echo "  4. 验证MSS: iptables -t mangle -L -n -v / iptables-nft ... / iptables-legacy ..."
  echo ""

  if [ -t 0 ]; then
    read -r -p "🔄 是否立即重启以生效所有优化？(y/N): " answer
    if [[ "$answer" =~ ^[Yy]$ ]]; then
      echo "🌀 系统将在3秒后重启..."
      sleep 3
      reboot
    else
      echo "📌 请稍后手动重启以应用所有优化"
    fi
  else
    echo "📌 非交互模式，请手动重启以应用优化"
  fi
}

# === 15. 执行 ===
main