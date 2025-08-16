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
# Nginx 检测
############################
echo -e "${GREEN}🕹️ [2] Nginx 安装与源状态检测${NC}"
echo "------------------------------------------------------------"

codename=$(lsb_release -sc)

# 检查 nginx.org 源
if grep -E "^[^#].*nginx.org.*$codename" /etc/apt/sources.list /etc/apt/sources.list.d/*.list 2>/dev/null | grep -q .; then
    echo -e "${RED}❌ nginx.org 源未禁用${NC}"
else
    echo -e "${GREEN}✅ nginx.org 源已禁用${NC}"
fi

# 检查 ondrej/nginx PPA
if grep -R "ppa.launchpadcontent.net/ondrej/nginx" /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null | grep -q .; then
    echo -e "${GREEN}✅ ondrej/nginx PPA 已添加${NC}"
else
    echo -e "${RED}❌ ondrej/nginx PPA 未添加${NC}"
fi

# Nginx 版本
installed_ver=$(nginx -v 2>&1 | awk -F/ '{print $2}')
echo -e "🔹 当前 nginx 版本: ${GREEN}$installed_ver${NC}"

# 确认安装源
ppa_source=$(apt-cache policy nginx | grep -E "http.*ondrej/nginx" | head -n1)
if [ -n "$ppa_source" ]; then
    echo -e "${GREEN}✅ Nginx 来自 ondrej/nginx PPA: $ppa_source${NC}"
else
    echo -e "${YELLOW}⚠️ Nginx 可能不是 PPA 源安装的${NC}"
fi

echo "------------------------------------------------------------"
echo -e "${GREEN}🎉 全部检测完成，请确认输出结果。${NC}"
EOF

chmod +x /root/system-check.sh
bash /root/system-check.sh