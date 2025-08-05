cat > /root/net-optimize-full.sh << 'EOF'
#!/bin/bash
set -e

echo "🚀 开始执行全局网络优化（TCP+UDP+IPv6+WiFi+ulimit）..."
echo "------------------------------------------------------------"

# 检测是否交互模式
interactive=0
[ -t 0 ] && interactive=1

# === 1. 清理旧配置 ===
rm -f /etc/rc.local 2>/dev/null
sed -i '/^\* soft nofile/d;/^\* hard nofile/d' /etc/security/limits.conf
sed -i '/^DefaultLimitNOFILE=/d' /etc/systemd/system.conf /etc/systemd/user.conf
rm -f /etc/systemd/system.conf.d/99-nofile.conf /etc/systemd/system/ssh.service.d/override.conf 2>/dev/null
sed -i '/nginx.org/ s/^/#/' /etc/apt/sources.list /etc/apt/sources.list.d/*.list 2>/dev/null
apt update


# === 2. 设置 TCP 拥塞控制算法和队列算法 ===
echo "📶 设置 TCP 拥塞算法和队列算法..."
if sysctl net.ipv4.tcp_available_congestion_control | grep -q bbrplus; then
    cc_algo="bbrplus"
elif sysctl net.ipv4.tcp_available_congestion_control | grep -q bbr; then
    cc_algo="bbr"
else
    echo "❌ 未检测到 BBR/BBRplus，退出"
    exit 1
fi
sysctl -w net.ipv4.tcp_congestion_control=$cc_algo
sysctl -w net.core.default_qdisc=fq_pie

# === 3. 设置 ulimit ===
echo "📂 设置 ulimit ..."
echo "* soft nofile 1048576" >> /etc/security/limits.conf
echo "* hard nofile 1048576" >> /etc/security/limits.conf
echo "DefaultLimitNOFILE=1048576" >> /etc/systemd/system.conf
echo "DefaultLimitNOFILE=1048576" >> /etc/systemd/user.conf
mkdir -p /etc/systemd/system/sshd.service.d
cat > /etc/systemd/system/sshd.service.d/override.conf <<EOF1
[Service]
LimitNOFILE=1048576
EOF1
grep -q pam_limits.so /etc/pam.d/common-session || echo "session required pam_limits.so" >> /etc/pam.d/common-session
grep -q 'ulimit -n 1048576' ~/.bashrc || echo 'ulimit -n 1048576' >> ~/.bashrc

# === 4. 启用 TCP MTU 探测 ===
echo "🌐 启用 TCP MTU 探测..."
sed -i '/^net.ipv4.tcp_mtu_probing/d' /etc/sysctl.conf
echo "net.ipv4.tcp_mtu_probing = 2" >> /etc/sysctl.conf
sysctl -w net.ipv4.tcp_mtu_probing=2

# === 5. MSS Clamping 设置 ===
echo "📡 设置 MSS Clamping..."
modprobe ip_tables || true
modprobe iptable_mangle || true
iface=$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}')
[ -z "$iface" ] && iface=$(ip -6 route get 240c::6666 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}')
mtu=$(cat /sys/class/net/${iface}/mtu 2>/dev/null)
[ -z "$mtu" ] && mtu=1500
mss=$((mtu - 40))
[ "$mss" -lt 1000 ] && mss=1360
for chain in OUTPUT INPUT FORWARD; do
    iptables -t mangle -D $chain -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss $mss 2>/dev/null || true
    iptables -t mangle -C $chain -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss $mss 2>/dev/null || \
    iptables -t mangle -A $chain -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss $mss
done

# === 6. 保存 iptables 规则 ===
echo "💾 保存 iptables..."
DEBIAN_FRONTEND=noninteractive apt-get update -y >/dev/null
DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent netfilter-persistent >/dev/null
netfilter-persistent save || echo "⚠️ 保存 iptables 失败"
systemctl enable netfilter-persistent || true

# === 7. UDP 优化 ===
echo "📡 优化 UDP 参数..."
fix_param() {
  key="$1"; val="$2"
  cur=$(sysctl -n "$key" 2>/dev/null || echo "")
  if [[ "$cur" != "$val" ]]; then
    sed -i "/^$key/d" /etc/sysctl.conf
    echo "$key = $val" >> /etc/sysctl.conf
    sysctl -w "$key=$val" >/dev/null
  fi
}
fix_param net.ipv4.udp_rmem_min 16384
fix_param net.ipv4.udp_wmem_min 16384
fix_param net.ipv4.udp_mem "65536 131072 262144"
fix_param net.core.rmem_max 67108864
fix_param net.core.wmem_max 67108864
fix_param net.core.rmem_default 2500000
fix_param net.core.wmem_default 2500000

# === 8. nf_conntrack 优化 ===
echo "🧩 启用 nf_conntrack ..."
modprobe nf_conntrack || true
echo nf_conntrack > /etc/modules-load.d/nf_conntrack.conf
fix_param net.netfilter.nf_conntrack_max 262144
fix_param net.netfilter.nf_conntrack_udp_timeout 30
fix_param net.netfilter.nf_conntrack_udp_timeout_stream 180

# === 9. 写入 sysctl 参数（含 IPv4 + IPv6）===
echo "📊 写入其他 sysctl 参数..."
cat >> /etc/sysctl.conf <<EOF2
net.core.default_qdisc = fq_pie
net.ipv4.tcp_congestion_control = $cc_algo
net.core.netdev_max_backlog = 250000
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
net.ipv6.conf.default.forwarding = 1
net.ipv6.conf.all.accept_ra = 2
net.ipv6.conf.default.accept_ra = 2
EOF2
sysctl -p

# === 10. 修复 nginx.org 源 & 安装新版 Nginx ===
echo "🔧 修复 nginx.org 源并安装新版 Nginx..."
nginx_source_fix=0
grep -E '^[^#].*nginx.org.*noble' /etc/apt/sources.list /etc/apt/sources.list.d/*.list 2>/dev/null && nginx_source_fix=1
if [ "$nginx_source_fix" = "1" ]; then
    sed -i '/^[^#].*nginx.org.*noble/ s/^/#/' /etc/apt/sources.list /etc/apt/sources.list.d/*.list 2>/dev/null || true
    echo "✅ 已禁用无效的 nginx.org 源"
fi
apt-get install -y software-properties-common gnupg2 ca-certificates lsb-release curl >/dev/null 2>&1
if ! grep -qr "ondrej/nginx" /etc/apt/; then
    add-apt-repository -y ppa:ondrej/nginx >/dev/null 2>&1
fi
apt-get update -y >/dev/null 2>&1
apt-get install -y nginx >/dev/null 2>&1 && \
    echo "✅ 已安装新版 Nginx（来自 ondrej/nginx）" || \
    echo "⚠️ 安装 Nginx 失败（可忽略）"

# === 11. 安装 conntrack 工具 ===
echo "🔧 安装 conntrack 工具..."
apt-get install -y conntrack >/dev/null 2>&1

# === 12. 开机自动恢复 ===
echo "🛠 配置开机自动恢复 ..."
cat > /root/net-optimize-boot.sh <<EOL
#!/bin/bash
iface=\$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if(\$i=="dev") print \$(i+1)}')
[ -z "\$iface" ] && iface=\$(ip -6 route get 240c::6666 2>/dev/null | awk '{for(i=1;i<=NF;i++) if(\$i=="dev") print \$(i+1)}')
mtu=\$(cat /sys/class/net/\${iface}/mtu 2>/dev/null)
[ -z "\$mtu" ] && mtu=1500
mss=\$((mtu - 40))
[ "\$mss" -lt 1000 ] && mss=1360
for chain in OUTPUT INPUT FORWARD; do
    iptables -t mangle -D \$chain -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss \$mss 2>/dev/null || true
    iptables -t mangle -C \$chain -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss \$mss 2>/dev/null || \
    iptables -t mangle -A \$chain -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss \$mss
done
sysctl -p
ulimit -n 1048576
exit 0
EOL

chmod +x /root/net-optimize-boot.sh
cat > /etc/systemd/system/net-optimize.service <<EOL
[Unit]
Description=Network Optimization Restore at Boot
After=network.target

[Service]
Type=oneshot
ExecStart=/root/net-optimize-boot.sh
RemainAfterExit=true

[Install]
WantedBy=multi-user.target
EOL

systemctl daemon-reload
systemctl daemon-reexec
systemctl enable net-optimize.service

# === 13. 状态输出 ===
echo "------------------------------------------------------------"
echo "✅ 拥塞算法：$(sysctl -n net.ipv4.tcp_congestion_control)"
echo "✅ 默认队列：$(sysctl -n net.core.default_qdisc)"
echo "✅ MTU 探测：$(sysctl -n net.ipv4.tcp_mtu_probing)"
echo "✅ UDP rmem_min：$(sysctl -n net.ipv4.udp_rmem_min)"
echo "✅ nf_conntrack_max：$(sysctl -n net.netfilter.nf_conntrack_max)"
echo "✅ 当前 ulimit：$(ulimit -n)"
echo "✅ MSS Clamping："
iptables -t mangle -L -n -v | grep TCPMSS || echo "⚠️ 未检测到"
echo "✅ UDP 监听："
ss -u -l -n -p | grep -E 'LISTEN|UNCONN' || echo "⚠️ 无监听"
echo "✅ UDP 活跃连接数：$(conntrack -L -p udp 2>/dev/null | wc -l)"
echo "------------------------------------------------------------"

# === 14. 重启提示 ===
if [ "$interactive" = "1" ]; then
    read -p "🔁 是否立即重启以使优化生效？(y/N): " answer
    if [[ "$answer" =~ ^[Yy]$ ]]; then
        echo "🌀 正在重启..."
        (sleep 1; reboot) &
    else
        echo "📌 请稍后手动重启以生效所有配置"
    fi
else
    echo "📌 已在非交互模式执行，未触发重启，建议手动重启"
fi

echo "🎉 网络优化完成，重启后将自动恢复设置！"
EOF

chmod +x /root/net-optimize-full.sh
bash /root/net-optimize-full.sh


