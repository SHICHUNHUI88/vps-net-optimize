cat >/tmp/net-optimize-reset.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

echo "🧹 开始清除所有网络优化配置..."

# 1. 删除 sysctl 持久化配置
if [ -f /etc/sysctl.d/99-net-optimize.conf ]; then
  rm -f /etc/sysctl.d/99-net-optimize.conf
  echo "🗑 删除 /etc/sysctl.d/99-net-optimize.conf"
fi

# 立即重新加载 sysctl（用系统默认）
sysctl --system >/dev/null 2>&1 || true

# 2. 清理 limits.d 中的 ulimit 配置
if [ -f /etc/security/limits.d/99-nofile.conf ]; then
  rm -f /etc/security/limits.d/99-nofile.conf
  echo "🗑 删除 /etc/security/limits.d/99-nofile.conf"
fi

# 恢复 systemd 默认 NOFILE
sed -i "/DefaultLimitNOFILE/d" /etc/systemd/system.conf 2>/dev/null || true
systemctl daemon-reload || true

# 3. 清除 MSS Clamping 规则（nft / iptables）
echo "🗑 清除 MSS Clamping 规则..."
if command -v nft >/dev/null 2>&1; then
  nft delete table inet mangle 2>/dev/null || true
fi

if command -v iptables >/dev/null 2>&1; then
  iptables -t mangle -S 2>/dev/null | grep TCPMSS | sed 's/^-A/iptables -t mangle -D/' | bash 2>/dev/null || true
fi

# 4. 清除 conntrack 配置
rm -f /etc/modules-load.d/nf_conntrack.conf 2>/dev/null || true
sed -i "/nf_conntrack/d" /etc/sysctl.d/99-net-optimize.conf 2>/dev/null || true

# 5. 删除启动恢复服务
systemctl disable net-optimize-apply.service >/dev/null 2>&1 || true
rm -f /etc/systemd/system/net-optimize-apply.service 2>/dev/null || true
rm -f /usr/local/sbin/net-optimize-apply 2>/dev/null || true

echo "🗑 已移除 net-optimize-apply.service（开机恢复服务）"

# 6. 删除主脚本自身副本
rm -f /usr/local/sbin/net-optimize-full.sh 2>/dev/null || true
rm -f /etc/net-optimize/config 2>/dev/null || true
rm -rf /etc/net-optimize 2>/dev/null || true

echo "🗑 已删除 /usr/local/sbin/net-optimize-full.sh /etc/net-optimize/*"

echo "------------------------------------------------------------"
echo "🎉 所有网络优化已恢复为系统默认状态"
echo "🔁 建议重启服务器以完全生效："
echo "    reboot"
EOF

chmod +x /tmp/net-optimize-reset.sh
bash /tmp/net-optimize-reset.sh