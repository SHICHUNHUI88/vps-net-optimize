cat > setup-tools.sh <<'EOF'
#!/bin/bash
set -uo pipefail

DO_UPGRADE=0
if [ "${1:-}" = "--upgrade" ]; then
  DO_UPGRADE=1
fi

# ==== 基础环境检测（root / sudo） ====
if [ "$(id -u)" -eq 0 ]; then
  SUDO=""
else
  if command -v sudo >/dev/null 2>&1; then
    SUDO="sudo"
  else
    echo "❌ 当前不是 root 且系统没有 sudo，请先切换 root 或安装 sudo 再运行本脚本。"
    exit 1
  fi
fi

APT="$SUDO apt-get"
export DEBIAN_FRONTEND=noninteractive

FAILED_PKGS=()

install_one() {
  local pkg="$1"
  if dpkg -s "$pkg" >/dev/null 2>&1; then
    echo "✅ $pkg 已安装，跳过"
    return 0
  fi
  echo "🔹 安装 $pkg ..."
  if $APT install -y "$pkg"; then
    return 0
  else
    echo "⚠️  安装失败：$pkg（继续执行）"
    FAILED_PKGS+=("$pkg")
    return 1
  fi
}

install_if_missing() {
  for pkg in "$@"; do
    install_one "$pkg" || true
  done
}

echo "🔹 更新软件包索引..."
$APT update -y || { echo "❌ apt update 失败，退出"; exit 1; }

# ==== 先确保 ping 支持 -M do（你要求显式加入） ====
echo "🔹 安装 iputils-ping（支持 -M do 测 MTU）..."
$SUDO apt-get install -y iputils-ping || FAILED_PKGS+=("iputils-ping")
# ================================================

echo "🔹 安装编辑器和基础工具..."
install_if_missing \
  nano vim less wget curl unzip tar zip git rsync screen tmux \
  build-essential ca-certificates software-properties-common

# 如果不是 root，又想后面还能用 sudo，这里顺手装一下 sudo（有些极简系统缺）
if [ -n "$SUDO" ]; then
  install_if_missing sudo
fi

echo "🔹 安装网络和监控工具（原有 + 增强）..."
install_if_missing \
  iptables iproute2 net-tools traceroute htop iftop nload \
  netcat-openbsd tcpdump mtr bmon conntrack \
  iputils-ping iputils-tracepath ufw \
  dnsutils bind9-host jq socat nmap whois ipset wireguard-tools

echo "🔹 安装系统排障/磁盘/性能工具..."
install_if_missing \
  iotop ncdu tree bash-completion time logrotate \
  ethtool sysstat lsof unattended-upgrades \
  p7zip-full xz-utils zstd openssl rclone fail2ban

# dool / dstat 自动兼容（Debian bookworm 常见没有 dool）
echo "🔹 安装 dool/dstat（自动兼容）..."
if apt-cache show dool >/dev/null 2>&1; then
  install_if_missing dool
else
  install_if_missing dstat
fi

echo "🔹 安装 cron 和 systemd 工具..."
install_if_missing cron
$SUDO systemctl enable cron >/dev/null 2>&1 || true
$SUDO systemctl start cron >/dev/null 2>&1 || true

echo "🔹 安装 Python 环境..."
install_if_missing python3 python3-pip

echo "🔹 配置 unattended-upgrades 自动安全更新..."
$SUDO dpkg-reconfigure --priority=low unattended-upgrades >/dev/null 2>&1 || true

# fail2ban 装了就尽量启用（失败不影响脚本）
$SUDO systemctl enable fail2ban >/dev/null 2>&1 || true
$SUDO systemctl start fail2ban >/dev/null 2>&1 || true

echo "🔹 清理缓存..."
$APT autoremove -y || true
$APT clean || true

# ===== 最后再做升级（可选） =====
if [ "$DO_UPGRADE" -eq 1 ]; then
  echo "🔹 最后执行系统升级（upgrade）..."
  $APT upgrade -y || echo "⚠️ upgrade 失败（继续执行）"
  echo "ℹ️ 如提示需要重启：建议你手动择时重启（reboot）"
else
  echo "ℹ️ 工具已安装完成；默认未 upgrade。需要升级请运行：./setup-tools.sh --upgrade"
fi
# ===============================

echo "✅ VPS 工具安装流程结束！"
echo "   - 已智能跳过已安装的软件"
echo "   - netcat 使用 netcat-openbsd"
echo "   - dool 若不可用会自动装 dstat"

if [ "${#FAILED_PKGS[@]}" -gt 0 ]; then
  echo "⚠️ 以下软件包安装失败（不影响脚本跑完）："
  printf '   - %s\n' "${FAILED_PKGS[@]}"
  echo "   你把失败列表发我，我帮你逐个适配/替换包名。"
fi
EOF

chmod +x setup-tools.sh
./setup-tools.sh