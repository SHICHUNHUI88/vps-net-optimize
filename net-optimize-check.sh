#!/usr/bin/env bash
set -euo pipefail

green(){ printf "\033[32m%s\033[0m\n" "$*"; }
yellow(){ printf "\033[33m%s\033[0m\n" "$*"; }
red(){ printf "\033[31m%s\033[0m\n" "$*"; }
title(){ echo "============================================================"; }
sep(){ echo "------------------------------------------------------------"; }

has(){ command -v "$1" >/dev/null 2>&1; }
get(){ sysctl -n "$1" 2>/dev/null || echo "N/A"; }
has_key(){ [[ -e "/proc/sys/${1//./\/}" ]]; }

safe_grep_count() {
  local pattern="$1" file="$2"
  local out
  out="$(grep -cE "$pattern" "$file" 2>/dev/null || true)"
  out="${out%%$'\n'*}"
  echo "${out:-0}"
}

svc_state() {
  local s="$1"
  if systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -qx "$s"; then
    local en act
    en="$(systemctl is-enabled "$s" 2>/dev/null || true)"
    act="$(systemctl is-active "$s" 2>/dev/null || true)"
    echo "  - $s: enabled=$en, active=$act"
  else
    echo "  - $s: (not installed)"
  fi
}

echo "🔍 开 始 系 统 状 态 检 测 （网 络 优 化 + Nginx）..."
title

echo "🌐 [1] 网 络 优 化 关 键 状 态"
sep
green "✅ 拥塞算法：$(get net.ipv4.tcp_congestion_control)"
green "✅ 默认队列：$(get net.core.default_qdisc)"
has_key net.ipv4.tcp_mtu_probing && green "✅ TCP MTU 探测：$(get net.ipv4.tcp_mtu_probing)"

echo "✅ UDP 缓冲："
echo "  🔹 udp_rmem_min = $(get net.ipv4.udp_rmem_min)"
echo "  🔹 udp_wmem_min = $(get net.ipv4.udp_wmem_min)"
echo "  🔹 udp_mem      = $(get net.ipv4.udp_mem)"
echo "✅ TCP 缓冲："
echo "  🔹 tcp_rmem      = $(get net.ipv4.tcp_rmem)"
echo "  🔹 tcp_wmem      = $(get net.ipv4.tcp_wmem)"
echo "✅ Core 缓冲："
echo "  🔹 rmem_default  = $(get net.core.rmem_default)"
echo "  🔹 wmem_default  = $(get net.core.wmem_default)"

sep
echo "🔗 [2] conntrack / netfilter 状态（兼容内建模块）"
sep
if has_key net.netfilter.nf_conntrack_max || [[ -d /proc/sys/net/netfilter ]]; then
  green "✅ nf_conntrack 可用（模块或内建）"
  echo "  🔸 nf_conntrack_max                 = $(get net.netfilter.nf_conntrack_max)"
  echo "  🔸 nf_conntrack_udp_timeout         = $(get net.netfilter.nf_conntrack_udp_timeout)"
  echo "  🔸 nf_conntrack_udp_timeout_stream  = $(get net.netfilter.nf_conntrack_udp_timeout_stream)"
  echo "  🔸 nf_conntrack_tcp_timeout_established = $(get net.netfilter.nf_conntrack_tcp_timeout_established)"
else
  yellow "ℹ️ nf_conntrack 未启用或不可用"
fi

if [[ -f /proc/net/nf_conntrack ]]; then
  udp_c="$(safe_grep_count '^udp' /proc/net/nf_conntrack)"
  tcp_c="$(safe_grep_count '^tcp' /proc/net/nf_conntrack)"
  green "✅ /proc/net/nf_conntrack 可读"
  echo "  🔸 UDP entries = $udp_c"
  echo "  🔸 TCP entries = $tcp_c"
  echo "  🔸 Total       = $((udp_c + tcp_c))"
else
  yellow "ℹ️ /proc/net/nf_conntrack 不存在（可能是 nft / 内核暴露差异）"
fi

if has lsmod; then
  if lsmod | grep -q '^nf_conntrack'; then
    green "✅ lsmod 可见 nf_conntrack（非内建）"
  else
    echo "ℹ️ lsmod 未显示 nf_conntrack（可能是内建，属正常）"
  fi
fi

sep
echo "📂 [3] ulimit / fd"
sep
green "✅ 当前 ulimit -n：$(ulimit -n)"
if [[ -f /etc/security/limits.d/99-net-optimize.conf ]]; then
  echo "✅ limits.d 已写入：/etc/security/limits.d/99-net-optimize.conf"
else
  yellow "⚠️ 未发现 limits.d 配置"
fi
grep -n '^DefaultLimitNOFILE' /etc/systemd/system.conf 2>/dev/null || echo "ℹ️ systemd system.conf 未设置 DefaultLimitNOFILE"

sep
echo "📡 [4] MSS Clamping 规则（iptables/nft 双栈）"
sep
echo "✅ iptables mangle/POSTROUTING (含计数)："
if has iptables; then
  iptables -t mangle -L POSTROUTING -n -v 2>/dev/null | grep -E 'TCPMSS|Chain|pkts|bytes' || echo "  (none)"
else
  echo "  (iptables not installed)"
fi

echo "✅ nft inet mangle postrouting："
if has nft; then
  nft list chain inet mangle postrouting 2>/dev/null | grep -E 'maxseg|TCPMSS|tcp option maxseg' || echo "  (none)"
else
  echo "  (nft not installed)"
fi

if has iptables; then
  dup="$(iptables -t mangle -S POSTROUTING 2>/dev/null | grep -c 'TCPMSS' || true)"
  dup="${dup%%$'\n'*}"; dup="${dup:-0}"
  if [[ "$dup" -gt 1 ]]; then
    yellow "⚠️ 发现多条 TCPMSS 规则：$dup 条（可能重复叠加）"
  else
    green "✅ TCPMSS 规则数量：$dup"
  fi
fi

sep
echo "🧷 [5] UDP 监听 / 活跃连接"
sep
echo "✅ UDP 监听（ss）："
if has ss; then
  ss -u -l -n -p 2>/dev/null | head -n 50 || echo "  (none)"
else
  echo "  (ss not installed)"
fi

if has conntrack; then
  udp_lines="$(conntrack -L -p udp 2>/dev/null | sed '/^$/d' | wc -l | tr -d ' ')"
  tcp_lines="$(conntrack -L -p tcp 2>/dev/null | sed '/^$/d' | wc -l | tr -d ' ')"
  echo "✅ conntrack 工具可用（趋势参考）："
  echo "  🔸 UDP 列表行数：$udp_lines"
  echo "  🔸 TCP 列表行数：$tcp_lines"
else
  yellow "ℹ️ 未安装 conntrack（apt install conntrack 可安装）"
fi

sep
echo "🗂 [6] sysctl 持久化与运行态一致性"
sep
if [[ -f /etc/sysctl.d/99-net-optimize.conf ]]; then
  green "✅ 发现持久化文件：/etc/sysctl.d/99-net-optimize.conf"
  echo "  - 文件前 60 行："
  head -n 60 /etc/sysctl.d/99-net-optimize.conf

  echo ""
  echo "  - 关键项对比（runtime vs file）:"
  check_keys=(
    net.core.default_qdisc
    net.ipv4.tcp_congestion_control
    net.ipv4.tcp_mtu_probing
    net.core.rmem_default
    net.core.wmem_default
    net.netfilter.nf_conntrack_max
    net.netfilter.nf_conntrack_udp_timeout
    net.netfilter.nf_conntrack_udp_timeout_stream
  )
  for k in "${check_keys[@]}"; do
    rt="$(get "$k")"
    fv="$(grep -E "^\s*${k}\s*=" /etc/sysctl.d/99-net-optimize.conf 2>/dev/null | tail -n1 | awk -F= '{gsub(/ /,"",$2); print $2}' || true)"
    fv="${fv:-N/A}"
    if [[ "$fv" != "N/A" && "$rt" != "N/A" && "$rt" != "$fv" ]]; then
      yellow "  ⚠️ $k runtime=$rt  file=$fv  (不一致)"
    else
      echo "  ✅ $k runtime=$rt  file=$fv"
    fi
  done
else
  yellow "⚠️ 未发现 /etc/sysctl.d/99-net-optimize.conf"
fi

sep
echo "🛠 [7] 开机自启服务"
sep
svc_state "net-optimize.service"
svc_state "net-optimize-apply.service"

sep
echo "🔧 [8] Nginx 源与服务"
sep
if has apt-cache; then
  if ls /etc/apt/sources.list.d/*nginx* 1>/dev/null 2>&1; then
    echo "📌 nginx 相关 sources："
    ls -l /etc/apt/sources.list.d/*nginx* 2>/dev/null || true

    if grep -R "nginx.org/packages" /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources 2>/dev/null | grep -q .; then
      green "✅ 检测到 nginx.org 源"
    else
      echo "ℹ️ 未检测到 nginx.org 源"
    fi
  else
    echo "ℹ️ 未发现 nginx 相关 sources.list.d 文件"
  fi

  if has nginx; then
    ver="$(nginx -v 2>&1 | awk -F/ '{print $2}')"
    green "✅ Nginx 版本：$ver"
    systemctl is-active nginx >/dev/null 2>&1 && green "✅ Nginx：运行中" || yellow "⚠️ Nginx：未运行"
  else
    echo "ℹ️ 未安装 Nginx"
  fi

  echo ""
  echo "apt-cache policy nginx："
  apt-cache policy nginx || true
else
  echo "ℹ️ 非 apt 系统，跳过 Nginx 检测"
fi

sep
echo "🔁 [9] Nginx 自动更新（cron）"
sep
cron_file="/etc/cron.d/net-optimize-nginx-update"

if [[ -f "$cron_file" ]]; then
  green "✅ 已发现 Nginx 自动更新 cron：$cron_file"
  echo "  - 内容："
  sed 's/^/    /' "$cron_file"

  perms="$(stat -c '%a' "$cron_file" 2>/dev/null || echo "?")"
  owner="$(stat -c '%U:%G' "$cron_file" 2>/dev/null || echo "?")"
  echo "  - 权限：$perms"
  echo "  - 属主：$owner"

  [[ "$perms" != "644" ]] && yellow "  ⚠️ cron 权限异常（建议 644）"

  if ! grep -qE '(apt-get|apt)\s+.*(install|upgrade).*(nginx)(\s|$)' "$cron_file" 2>/dev/null; then
    yellow "  ⚠️ cron 存在，但未检测到 nginx install/upgrade 命令（可能内容不对）"
  fi
else
  yellow "⚠️ 未发现 Nginx 自动更新 cron"
  echo "  👉 预期路径：/etc/cron.d/net-optimize-nginx-update"
fi

if systemctl list-unit-files 2>/dev/null | grep -q '^cron\.service'; then
  state="$(systemctl is-active cron 2>/dev/null || true)"
  [[ "$state" == "active" ]] && green "✅ cron 服务运行中" || yellow "⚠️ cron 服务状态：$state"
elif systemctl list-unit-files 2>/dev/null | grep -q '^crond\.service'; then
  state="$(systemctl is-active crond 2>/dev/null || true)"
  [[ "$state" == "active" ]] && green "✅ crond 服务运行中" || yellow "⚠️ crond 服务状态：$state"
else
  yellow "ℹ️ 未检测到 cron/crond 服务（可能未安装或使用 systemd timer）"
  echo "  👉 Ubuntu/Debian 可用：apt-get install -y cron && systemctl enable --now cron"
fi

title
green "🎉 检 测 完 成"