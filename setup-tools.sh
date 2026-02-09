cat > setup-tools.sh <<'EOF'
#!/bin/bash
set -uo pipefail

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

ask_yn() {
  local prompt="$1"
  local ans
  while true; do
    read -r -p "$prompt (y/n): " ans || ans=""
    case "${ans,,}" in
      y|yes) return 0 ;;
      n|no)  return 1 ;;
      *) echo "请输入 y 或 n" ;;
    esac
  done
}

echo "🔹 更新软件包索引..."
$APT update -y || { echo "❌ apt update 失败，退出"; exit 1; }

# ==== 显式安装：iputils-ping（支持 -M do 测 MTU） ====
echo "🔹 安装 iputils-ping（支持 -M do 测 MTU）..."
$SUDO apt-get install -y iputils-ping || FAILED_PKGS+=("iputils-ping")

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

echo "✅ 工具安装已完成。"

# ===== 工具装完后：询问是否升级 =====
if ask_yn "是否现在进行系统升级（apt upgrade）？"; then
  echo "🔹 执行系统升级（upgrade）..."
  if $APT upgrade -y; then
    echo "✅ 系统升级完成。"
  else
    echo "⚠️ 系统升级失败（继续往下）。"
  fi
else
  echo "ℹ️ 已跳过系统升级。"
fi

# ===== 升级后：如需要重启则询问 =====
REBOOT_FLAG=0
if [ -f /var/run/reboot-required ] || [ -f /run/reboot-required ]; then
  REBOOT_FLAG=1
fi

if [ "$REBOOT_FLAG" -eq 1 ]; then
  echo "⚠️ 检测到系统提示需要重启（reboot-required）。"
  if ask_yn "是否现在重启系统？"; then
    echo "🔁 正在重启..."
    $SUDO reboot
  else
    echo "ℹ️ 已选择不重启。你可以稍后手动执行：reboot"
  fi
else
  echo "✅ 未检测到必须重启的标记。"
fi

echo "✅ VPS 工具脚本执行结束！"
echo "   - netcat 使用 netcat-openbsd"
echo "   - dool 若不可用会自动装 dstat"

if [ "${#FAILED_PKGS[@]}" -gt 0 ]; then
  echo "⚠️ 以下软件包安装失败（不影响脚本跑完）："
  printf '   - %s\n' "${FAILED_PKGS[@]}"
fi
EOF

chmod +x setup-tools.sh
./setup-tools.sh