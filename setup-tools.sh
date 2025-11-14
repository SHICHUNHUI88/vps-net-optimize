cat > setup-tools.sh <<'EOF'
#!/bin/bash
set -e

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

# 统一用 apt-get，避免交互提示
APT="$SUDO apt-get"
export DEBIAN_FRONTEND=noninteractive

# 检查并安装软件函数
install_if_missing() {
    for pkg in "$@"; do
        if ! dpkg -s "$pkg" >/dev/null 2>&1; then
            echo "🔹 安装 $pkg ..."
            $APT install -y "$pkg"
        else
            echo "✅ $pkg 已安装，跳过"
        fi
    done
}

echo "🔹 更新系统..."
$APT update -y
$APT upgrade -y

echo "🔹 安装编辑器和基础工具..."
install_if_missing \
    nano vim less wget curl unzip tar zip git rsync screen tmux \
    build-essential ca-certificates software-properties-common

# 如果不是 root，又想后面还能用 sudo，这里顺手装一下 sudo
if [ -n "$SUDO" ]; then
    install_if_missing sudo
fi

echo "🔹 安装网络和监控工具..."
# netcat 指定安装 openbsd 实现，避免虚拟包报错
install_if_missing \
    iptables iproute2 net-tools traceroute htop iftop nload \
    netcat-openbsd tcpdump mtr bmon conntrack \
    iputils-ping iputils-tracepath ufw

echo "🔹 安装 cron 和 systemd 工具..."
install_if_missing cron
$SUDO systemctl enable cron >/dev/null 2>&1 || true
$SUDO systemctl start cron >/dev/null 2>&1 || true

echo "🔹 安装 Python 环境..."
install_if_missing python3 python3-pip

echo "🔹 安装性能调优和运维工具..."
install_if_missing ethtool sysstat lsof unattended-upgrades

echo "🔹 配置 unattended-upgrades 自动安全更新..."
$SUDO dpkg-reconfigure --priority=low unattended-upgrades || true

echo "🔹 清理缓存..."
$APT autoremove -y
$APT clean

echo "✅ VPS 工具安装完成！"
echo "   - 已智能跳过已安装的软件"
echo "   - netcat 已指定为 openbsd 版本（netcat-openbsd）"
EOF

chmod +x setup-tools.sh
./setup-tools.sh