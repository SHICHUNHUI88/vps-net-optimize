cat > /root/net-optimize-check.sh << 'EOF'
#!/bin/bash
set -e

echo "🔍 开 始 检 测 网 络 优 化 状 态 （TCP+UDP+IPv6+WiFi+ulimit）..."
echo "------------------------------------------------------------"

# 拥塞算法
algo=$(sysctl -n net.ipv4.tcp_congestion_control)
echo "✅ 拥塞算法：$algo"

# 队列算法
qdisc=$(sysctl -n net.core.default_qdisc)
echo "✅ 默认队列算法：$qdisc"

# MTU 探测
mtu_probe=$(sysctl -n net.ipv4.tcp_mtu_probing)
echo "✅ TCP MTU 探测：$mtu_probe"

# UDP 缓冲设置
echo "✅ UDP 缓冲参数："
echo "  🔹 udp_rmem_min = $(sysctl -n net.ipv4.udp_rmem_min)"
echo "  🔹 udp_wmem_min = $(sysctl -n net.ipv4.udp_wmem_min)"
echo "  🔹 udp_mem      = $(sysctl -n net.ipv4.udp_mem)"

# conntrack 设置
echo "✅ nf_conntrack 参数："
echo "  🔸 nf_conntrack_max               = $(sysctl -n net.netfilter.nf_conntrack_max)"
echo "  🔸 nf_conntrack_udp_timeout       = $(sysctl -n net.netfilter.nf_conntrack_udp_timeout)"
echo "  🔸 nf_conntrack_udp_timeout_stream = $(sysctl -n net.netfilter.nf_conntrack_udp_timeout_stream)"

# ulimit
echo "✅ 当前 ulimit -n：$(ulimit -n)"

# MSS Clamping 状态
echo "✅ MSS Clamping 设置："
iptables -t mangle -L -n -v | grep TCPMSS || echo "⚠️ 未检测到 TCPMSS 规则"

# UDP 监听端口
echo "✅ UDP 监听端口："
ss -u -l -n -p | grep -E 'LISTEN|UNCONN' || echo "⚠️ 无 UDP 监听"

# UDP 活跃连接数
udp_conn=$(conntrack -L -p udp 2>/dev/null | wc -l)
echo "✅ 当前 UDP 活跃连接数：$udp_conn"

echo "------------------------------------------------------------"
echo "🎉 检测完毕，请确认各项优化是否已正确生效。"
EOF

chmod +x /root/net-optimize-check.sh
bash /root/net-optimize-check.sh