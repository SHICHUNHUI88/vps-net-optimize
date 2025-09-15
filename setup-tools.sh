cat > setup-tools.sh <<'EOF'
#!/bin/bash
set -e

# 检查并安装软件函数
install_if_missing() {
    for pkg in "$@"; do
        if ! dpkg -s "$pkg" >/dev/null 2>&1; then
            echo "🔹 安装 $pkg ..."
            sudo apt install -y "$pkg"
        else
            echo "✅ $pkg 已安装，跳过"
        fi
    done
}

echo "🔹 更新系统..."
sudo apt update -y && sudo apt upgrade -y

echo "🔹 安装编辑器和基础工具..."
install_if_missing nano vim less wget curl unzip tar zip git sudo rsync screen tmux build-essential ca-certificates software-properties-common

echo "🔹 安装网络和监控工具..."
# netcat 指定安装 openbsd 实现，避免虚拟包报错
install_if_missing iptables iproute2 net-tools traceroute htop iftop nload netcat-openbsd tcpdump mtr bmon conntrack iputils-ping iputils-tracepath ufw

echo "🔹 安装 cron 和 systemd 工具..."
install_if_missing cron
sudo systemctl enable cron
sudo systemctl start cron

echo "🔹 安装 Python 环境..."
install_if_missing python3 python3-pip

echo "🔹 安装性能调优工具..."
install_if_missing ethtool sysstat lsof unattended-upgrades

echo "🔹 配置 unattended-upgrades 自动更新..."
sudo dpkg-reconfigure --priority=low unattended-upgrades || true

echo "🔹 清理缓存..."
sudo apt autoremove -y
sudo apt clean

echo "✅ VPS 工具安装完成！智能跳过已安装的软件，netcat 已指定 openbsd 版本。"
EOF

chmod +x setup-tools.sh
./setup-tools.sh
