curl -fsSL https://gist.githubusercontent.com/ -o /tmp/net-optimize-check.sh || true
cat >/tmp/net-optimize-check.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
green(){ printf "\033[32m%s\033[0m\n" "$*"; }
yellow(){ printf "\033[33m%s\033[0m\n" "$*"; }
title(){ echo "============================================================"; }
has(){ command -v "$1" >/dev/null 2>&1; }
get(){ sysctl -n "$1" 2>/dev/null || echo "N/A"; }
has_key(){ [[ -e "/proc/sys/${1//./\/}" ]]; }

echo "🔍 开 始 系 统 状 态 检 测 （网 络 优 化 + Nginx）..."
title

echo "🌐 [1] 网 络 优 化 状 态"
echo "------------------------------------------------------------"
echo "✅ 拥塞算法：$(get net.ipv4.tcp_congestion_control)"
echo "✅ 默认队列：$(get net.core.default_qdisc)"
has_key net.ipv4.tcp_mtu_probing && echo "✅ TCP MTU 探测：$(get net.ipv4.tcp_mtu_probing)"
echo "✅ UDP 缓冲："
echo "  🔹 udp_rmem_min = $(get net.ipv4.udp_rmem_min)"
echo "  🔹 udp_wmem_min = $(get net.ipv4.udp_wmem_min)"
echo "  🔹 udp_mem      = $(get net.ipv4.udp_mem)"

if [[ -f /proc/sys/net/netfilter/nf_conntrack_max ]]; then
  echo "✅ nf_conntrack："
  echo "  🔸 nf_conntrack_max                 = $(get net.netfilter.nf_conntrack_max)"
  echo "  🔸 nf_conntrack_udp_timeout         = $(get net.netfilter.nf_conntrack_udp_timeout)"
  echo "  🔸 nf_conntrack_udp_timeout_stream  = $(get net.netfilter.nf_conntrack_udp_timeout_stream)"
else
  echo "ℹ️ nf_conntrack 未启用或不可用"
fi

echo "✅ 当前 ulimit -n：$(ulimit -n)"
echo "✅ MSS Clamping 规则："
( nft list chain inet mangle postrouting 2>/dev/null | grep -E 'maxseg|TCPMSS' ) || \
( iptables -t mangle -L -n -v 2>/dev/null | grep TCPMSS ) || echo "⚠️ 未检测到"

echo "✅ UDP 监听："
( ss -u -l -n -p 2>/dev/null | grep -E 'LISTEN|UNCONN' ) || echo "⚠️ 无 UDP 监听"

if has conntrack; then
  echo "✅ 当前 UDP 活跃连接数：$(conntrack -L -p udp 2>/dev/null | wc -l)"
else
  echo "ℹ️ 未安装 conntrack（apt install conntrack 可安装）"
fi

echo "------------------------------------------------------------"
echo "🗂 sysctl 持久化文件："
if [[ -f /etc/sysctl.d/99-net-optimize.conf ]]; then
  head -n 40 /etc/sysctl.d/99-net-optimize.conf
else
  echo "⚠️ 未发现 /etc/sysctl.d/99-net-optimize.conf"
fi

echo "------------------------------------------------------------"
echo "🛠 开机自恢复服务："
systemctl is-enabled net-optimize-apply.service >/dev/null 2>&1 \
  && echo "✅ 已启用 net-optimize-apply.service" \
  || echo "⚠️ 未启用 net-optimize-apply.service"
systemctl is-active net-optimize-apply.service >/dev/null 2>&1 \
  && echo "✅ 服务已运行（oneshot 已执行）" \
  || echo "ℹ️ 服务非运行态（oneshot 类型正常）"

echo "------------------------------------------------------------"
echo "🔧 Nginx 源与服务："
if has apt-cache; then
  if grep -q "nginx.org/packages" /etc/apt/sources.list.d/nginx.list 2>/dev/null; then
    echo "✅ Nginx 源：nginx.org"
  else
    echo "ℹ️ Nginx 源：默认系统源"
  fi
  if has nginx; then
    ver=$(nginx -v 2>&1 | awk -F/ '{print $2}')
    echo "✅ Nginx 版本：$ver"
    systemctl is-active nginx >/dev/null 2>&1 && echo "✅ Nginx：运行中" || echo "⚠️ Nginx：未运行"
  else
    echo "ℹ️ 未安装 Nginx"
  fi
else
  echo "ℹ️ 非 apt 系统，跳过 Nginx 检测"
fi

apt-cache policy nginx

title
echo "🎉 检 测 完 成"
EOF
chmod +x /tmp/net-optimize-check.sh
bash /tmp/net-optimize-check.sh
