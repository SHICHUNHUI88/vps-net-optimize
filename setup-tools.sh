cat > setup-tools.sh <<'EOF'
#!/bin/bash
set -euo pipefail

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

install_if_missing() {
  for pkg in "$@"; do
    if dpkg -s "$pkg" >/dev/null 2>&1; then
      echo "✅ $pkg 已安装，跳过"
    else
      echo "🔹 安装 $pkg ..."
      $APT install -y "$pkg"
    fi
  done
}

echo "🔹 更新软件包索引..."
$APT update -y

if [ "$DO_UPGRADE" -eq 1 ]; then
  echo "🔹 执行系统升级（upgrade）..."
  $APT upgrade -y
else
  echo "ℹ️ 默认不执行 upgrade（更稳）。如需升级：./setup-tools.sh --upgrade"
fi

# ==== 你要求显式加的两行（确保 ping 支持 -M do） ====
echo "🔹 安装 iputils-ping（支持 -M do 测 MTU）..."
$SUDO apt-get update -y
$SUDO apt-get install -y iputils-ping
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
# netcat 指定 openbsd 实现，避免虚拟包报错
install_if_missing \
  iptables iproute2 net-tools traceroute htop iftop nload \
  netcat-openbsd tcpdump mtr bmon conntrack \
  iputils-ping iputils-tracepath ufw \
  dnsutils bind9-host jq socat nmap whois ipset wireguard-tools

echo "🔹 安装系统排障/磁盘/性能工具..."
install_if_missing \
  iotop dool ncdu tree bash-completion time logrotate \
  ethtool sysstat lsof unattended-upgrades \
  p7zip-full xz-utils zstd openssl rclone fail2ban

echo "🔹 安装 cron 和 systemd 工具..."
install_if_missing cron
$SUDO systemctl enable cron >/dev/null 2>&1 || true
$SUDO systemctl start cron >/dev/null 2>&1 || true

echo "🔹 安装 Python 环境..."
install_if_missing python3 python3-pip

echo "🔹 配置 unattended-upgrades 自动安全更新..."
$SUDO dpkg-reconfigure --priority=low unattended-upgrades || true

# fail2ban 装了就尽量启用（失败不影响脚本）
$SUDO systemctl enable fail2ban >/dev/null 2>&1 || true
$SUDO systemctl start fail2ban >/dev/null 2>&1 || true

echo "🔹 清理缓存..."
$APT autoremove -y
$APT clean

echo "✅ VPS 工具安装完成！"
echo "   - 已智能跳过已安装的软件"
echo "   - netcat 已指定为 openbsd 版本（netcat-openbsd）"
echo "   - 默认不 upgrade；需要升级请加参数：--upgrade"
EOF

chmod +x setup-tools.sh
./setup-tools.sh