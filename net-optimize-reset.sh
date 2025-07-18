cat > /root/net-optimize-reset.sh << 'EOF'
#!/bin/bash
set -e

echo "🧹 开始还原网络优化设置..."

# === 1. 清除 sysctl.conf 参数 ===
echo "🔁 清除 /etc/sysctl.conf 中添加的优化项..."
params=(
  net.core.default_qdisc
  net.ipv4.tcp_congestion_control
  net.core.netdev_max_backlog
  net.core.somaxconn
  net.ipv4.tcp_max_syn_backlog
  net.ipv4.tcp_syncookies
  net.ipv4.tcp_tw_reuse
  net.ipv4.tcp_fin_timeout
  net.ipv4.ip_local_port_range
  net.ipv4.tcp_mtu_probing
  net.ipv4.udp_rmem_min
  net.ipv4.udp_wmem_min
  net.ipv4.udp_mem
  net.core.rmem_max
  net.core.wmem_max
  net.core.rmem_default
  net.core.wmem_default
  net.netfilter.nf_conntrack_max
  net.netfilter.nf_conntrack_udp_timeout
  net.netfilter.nf_conntrack_udp_timeout_stream
  net.ipv6.conf.all.forwarding
  net.ipv6.conf.default.forwarding
  net.ipv6.conf.all.accept_ra
  net.ipv6.conf.default.accept_ra
)

for p in "${params[@]}"; do
  sed -i "/^$p/d" /etc/sysctl.conf
done

sysctl -p

# === 2. 恢复 ulimit 和 systemd 限制 ===
echo "🔁 恢复 ulimit 设置..."
sed -i '/\* soft nofile/d;/\* hard nofile/d' /etc/security/limits.conf
sed -i '/DefaultLimitNOFILE/d' /etc/systemd/system.conf /etc/systemd/user.conf
sed -i '/ulimit -n 1048576/d' ~/.bashrc
rm -f /etc/systemd/system/sshd.service.d/override.conf
rm -rf /etc/systemd/system/sshd.service.d

# === 3. 删除 iptables MSS Clamping 规则 ===
echo "🔁 清除 MSS Clamping 规则..."
for chain in OUTPUT INPUT FORWARD; do
  iptables -t mangle -D $chain -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1360 2>/dev/null || true
  iptables -t mangle -F $chain || true
done
netfilter-persistent save || true

# === 4. 移除 nf_conntrack 自动加载 ===
echo "🔁 删除 nf_conntrack 自动加载设置..."
rm -f /etc/modules-load.d/nf_conntrack.conf

# === 5. 移除开机启动服务和脚本 ===
echo "🔁 删除 systemd 网络优化服务..."
systemctl disable net-optimize.service 2>/dev/null || true
rm -f /etc/systemd/system/net-optimize.service
rm -f /root/net-optimize-boot.sh

# === 6. 移除 nginx noble 源注释（可选）===
# echo "🔁 还原 nginx noble 源（如之前被注释）..."
# sed -i '/nginx.org.*noble/ s/^#//' /etc/apt/sources.list /etc/apt/sources.list.d/*.list || true

# === 7. 删除主优化脚本本体 ===
rm -f /root/net-optimize-full.sh

echo "✅ 网络优化已成功还原，请手动重启以确保完全恢复效果。"
EOF

chmod +x /root/net-optimize-reset.sh
bash /root/net-optimize-reset.sh
