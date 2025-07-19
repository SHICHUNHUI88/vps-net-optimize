cat > /root/net-optimize-reset.sh << 'EOF'
#!/bin/bash
set -e

echo "🧹 开始还原网络优化设置..."
echo "------------------------------------------------------------"

# === 1. 清除 sysctl.conf 中添加的优化项 ===
echo "🔁 清除 /etc/sysctl.conf 中的优化项..."
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
  net.ipv4.ip_forward
  net.ipv6.conf.all.forwarding
  net.ipv6.conf.default.forwarding
  net.ipv6.conf.all.accept_ra
  net.ipv6.conf.default.accept_ra
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
)

for key in "${params[@]}"; do
  sed -i "/^$key/d" /etc/sysctl.conf
done

sysctl -p || true

# === 2. 恢复 ulimit 限制 ===
echo "🔁 还原 ulimit 配置..."
sed -i '/\* soft nofile/d;/\* hard nofile/d' /etc/security/limits.conf
sed -i '/^DefaultLimitNOFILE=/d' /etc/systemd/system.conf /etc/systemd/user.conf
rm -f /etc/systemd/system/sshd.service.d/override.conf
rm -rf /etc/systemd/system/sshd.service.d/
sed -i '/pam_limits.so/d' /etc/pam.d/common-session
sed -i '/ulimit -n/d' ~/.bashrc

# === 3. 清除 MSS Clamping 设置 ===
echo "🔁 清除 MSS Clamping ..."
for chain in OUTPUT INPUT FORWARD; do
    iptables -t mangle -D $chain -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1360 2>/dev/null || true
done

# === 4. 删除 systemd 启动项和脚本 ===
echo "🔁 删除开机自启服务和脚本..."
systemctl disable net-optimize.service 2>/dev/null || true
rm -f /etc/systemd/system/net-optimize.service
rm -f /root/net-optimize-boot.sh

# === 5. 清除模块加载配置 ===
echo "🔁 清除 nf_conntrack 模块设置..."
rm -f /etc/modules-load.d/nf_conntrack.conf

# === 6. 清除 nginx.org noble 源注释 ===
echo "🔁 恢复 nginx.org noble 源注释..."
sed -i '/nginx.org.*noble/ s/^#//' /etc/apt/sources.list /etc/apt/sources.list.d/*.list 2>/dev/null || true

# === 7. 重载 systemd 并更新 ulimit 生效 ===
systemctl daemon-reexec
systemctl daemon-reload

# === 8. 输出结果 ===
echo "------------------------------------------------------------"
echo "✅ 所有优化配置已清除，系统已恢复默认状态"
echo "📌 建议手动重启系统以确保彻底生效"
EOF

chmod +x /root/net-optimize-reset.sh
bash /root/net-optimize-reset.sh
