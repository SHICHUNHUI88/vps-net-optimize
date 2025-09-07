cat > /root/system-check.sh << 'EOF'
#!/bin/bash
set -e

# 颜色定义
GREEN="\033[32m"
RED="\033[31m"
YELLOW="\033[33m"
NC="\033[0m" # 清除颜色

echo -e "${YELLOW}🔍 开 始 系 统 状 态 检 测 （网络优化 + Nginx）...${NC}"
echo "============================================================"

############################
# 网络优化检测
############################
echo -e "${GREEN}🌐 [1] 网络优化状态检测${NC}"
echo "------------------------------------------------------------"

# 拥塞算法
algo=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "未设置")
echo -e "✅ 拥塞算法：${GREEN}$algo${NC}"

# 队列算法
qdisc=$(sysctl -n net.core.default_qdisc 2>/dev/null || echo "未设置")
echo -e "✅ 默认队列算法：${GREEN}$qdisc${NC}"

# MTU 探测
mtu_probe=$(sysctl -n net.ipv4.tcp_mtu_probing 2>/dev/null || echo "未设置")
echo -e "✅ TCP MTU 探测：${GREEN}$mtu_probe${NC}"

# UDP 缓冲设置
echo "✅ UDP 缓冲参数："
echo -e "  🔹 udp_rmem_min = ${GREEN}$(sysctl -n net.ipv4.udp_rmem_min 2>/dev/null || echo N/A)${NC}"
echo -e "  🔹 udp_wmem_min = ${GREEN}$(sysctl -n net.ipv4.udp_wmem_min 2>/dev/null || echo N/A)${NC}"
echo -e "  🔹 udp_mem      = ${GREEN}$(sysctl -n net.ipv4.udp_mem 2>/dev/null || echo N/A)${NC}"

# conntrack 设置
echo "✅ nf_conntrack 参数："
echo -e "  🔸 nf_conntrack_max               = ${GREEN}$(sysctl -n net.netfilter.nf_conntrack_max 2>/dev/null || echo N/A)${NC}"
echo -e "  🔸 nf_conntrack_udp_timeout       = ${GREEN}$(sysctl -n net.netfilter.nf_conntrack_udp_timeout 2>/dev/null || echo N/A)${NC}"
echo -e "  🔸 nf_conntrack_udp_timeout_stream = ${GREEN}$(sysctl -n net.netfilter.nf_conntrack_udp_timeout_stream 2>/dev/null || echo N/A)${NC}"

# ulimit
echo -e "✅ 当前 ulimit -n：${GREEN}$(ulimit -n)${NC}"

# MSS Clamping 状态
echo "✅ MSS Clamping 设置："
if iptables -t mangle -L -n -v 2>/dev/null | grep -q TCPMSS; then
    iptables -t mangle -L -n -v | grep TCPMSS
else
    echo -e "${YELLOW}⚠️ 未检测到 TCPMSS 规则${NC}"
fi

# UDP 监听端口
echo "✅ UDP 监听端口："
if ss -u -l -n -p 2>/dev/null | grep -E 'LISTEN|UNCONN' >/dev/null; then
    ss -u -l -n -p | grep -E 'LISTEN|UNCONN'
else
    echo -e "${YELLOW}⚠️ 无 UDP 监听${NC}"
fi

# UDP 活跃连接数
udp_conn=$(conntrack -L -p udp 2>/dev/null | wc -l)
echo -e "✅ 当前 UDP 活跃连接数：${GREEN}$udp_conn${NC}"

echo "------------------------------------------------------------"
echo -e "${GREEN}🎉 网络优化检测完成。${NC}"
echo

############################
# 检查 Nginx 源
if apt-cache policy nginx 2>/dev/null | grep -q "nginx.org"; then
    echo "✅ Nginx 源：已指向 nginx.org"
else
    echo "❌ Nginx 源未指向官方源"
fi

# 检查 Nginx 服务状态
if systemctl is-active --quiet nginx; then
    nginx_ver=$(nginx -v 2>&1)
    echo "✅ Nginx 服务：运行中 ($nginx_ver)"
else
    echo "❌ Nginx 服务未运行"
fi

# 检查 Nginx 定时更新任务
if crontab -l 2>/dev/null | grep -q "apt-get -y install nginx"; then
    echo "✅ 定时任务：存在 (Nginx 自动更新)"
else
    echo "❌ 定时任务缺失 (未配置 Nginx 自动更新)"
fi

echo "------------------------------------------------------------"
echo -e "${GREEN}🎉 全部检测完成，请确认输出结果。${NC}"
EOF

chmod +x /root/system-check.sh
bash /root/system-check.sh