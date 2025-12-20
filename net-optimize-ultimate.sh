#!/usr/bin/env bash
# ==============================================================================
# 🚀 Net-Optimize-Ultimate v3.2.2 (修复版)
# 修复点：
#  1) conntrack 检测：不再依赖 lsmod（兼容“内建/不可见模块”场景）
#  2) qdisc 判断：不再依赖 lsmod，改为“能否成功设置”的真实探测
# 保留：v3.2 原有功能/结构/开关
# ==============================================================================

set -euo pipefail

# === 1. 自动更新机制 ===
SCRIPT_PATH="/usr/local/sbin/net-optimize-ultimate.sh"
REMOTE_URL="https://raw.githubusercontent.com/SHICHUNHUI88/vps-net-optimize/main/net-optimize-ultimate.sh"

fetch_raw() {
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$1"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO- "$1"
    else
        return 1
    fi
}

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum | cut -d' ' -f1
    elif command -v openssl >/dev/null 2>&1; then
        openssl dgst -sha256 | awk '{print $2}'
    else
        echo ""
    fi
}

# 检查更新
remote_buf="$(fetch_raw "$REMOTE_URL" || true)"
if [ -n "${remote_buf:-}" ]; then
    remote_hash="$(printf "%s" "$remote_buf" | sha256_of)"
    local_hash="$( [ -f "$SCRIPT_PATH" ] && sha256sum "$SCRIPT_PATH" 2>/dev/null | cut -d' ' -f1 || echo "" )"

    if [ -n "$remote_hash" ] && [ "$remote_hash" != "$local_hash" ]; then
        echo "🌀 检测到新版本，正在更新..."
        printf "%s" "$remote_buf" > "$SCRIPT_PATH"
        chmod +x "$SCRIPT_PATH"
        exec "$SCRIPT_PATH" "$@"
        exit 0
    fi
fi

# 安装到标准位置（注意：当你用 bash <(curl ...) 运行时，$0 可能是 /dev/fd/*，这里允许失败）
install -Dm755 "$0" "$SCRIPT_PATH" 2>/dev/null || true

# 错误追踪
trap 'code=$?; echo "❌ 出错：第 ${BASH_LINENO[0]} 行 -> ${BASH_COMMAND} (退出码 $code)"; exit $code' ERR

echo "🚀 Net-Optimize-Ultimate v3.2.1 开始执行..."
echo "========================================================"

# === 2. 全局配置开关 ===
: "${ENABLE_FQ_PIE:=1}"              # FQ_PIE队列
: "${ENABLE_MTU_PROBE:=1}"           # MTU探测
: "${ENABLE_MSS_CLAMP:=1}"           # MSS Clamping
: "${MSS_VALUE:=1452}"               # MSS值
: "${ENABLE_CONNTRACK_TUNE:=1}"      # 连接跟踪调优
: "${NFCT_MAX:=262144}"              # 最大连接数
: "${ENABLE_NGINX_REPO:=1}"          # Nginx官方源
: "${SKIP_APT:=1}"                   # 跳过APT操作
: "${APPLY_AT_BOOT:=1}"              # 开机自启

# 路径定义
CONFIG_DIR="/etc/net-optimize"
CONFIG_FILE="$CONFIG_DIR/config"
MODULES_FILE="$CONFIG_DIR/modules.list"
APPLY_SCRIPT="/usr/local/sbin/net-optimize-apply"

# === 3. 核心工具函数 ===
require_root() {
    [[ ${EUID:-$(id -u)} -eq 0 ]] || {
        echo "❌ 请使用 root 用户运行"
        exit 1
    }
}

have_cmd() {
    command -v "$1" >/dev/null 2>&1
}

has_sysctl_key() {
    local p="/proc/sys/${1//.//}"
    [[ -e "$p" ]]
}

get_sysctl() {
    sysctl -n "$1" 2>/dev/null || echo "N/A"
}

detect_distro() {
    local id codename
    if [ -r /etc/os-release ]; then
        . /etc/os-release
        id="${ID:-unknown}"
        codename="${VERSION_CODENAME:-${UBUNTU_CODENAME:-unknown}}"
    else
        id="unknown"
        codename="unknown"
    fi
    echo "${id}:${codename}"
}

check_dpkg_clean() {
    if have_cmd dpkg && dpkg --audit 2>/dev/null | grep -q .; then
        echo "⚠️ 检测到 dpkg 状态异常，请先执行修复："
        echo "  dpkg --configure -a"
        echo "  apt-get --fix-broken install -y"
        exit 1
    fi
}

# === v3.2.1 新增：conntrack 可用性检测（不依赖 lsmod）===
conntrack_available() {
    # 1) 关键 sysctl 存在：模块或内建都算可用
    has_sysctl_key net.netfilter.nf_conntrack_max && return 0

    # 2) /proc/sys/net/netfilter 下有 nf_conntrack* 也算可用
    if [ -d /proc/sys/net/netfilter ] && ls /proc/sys/net/netfilter/nf_conntrack* >/dev/null 2>&1; then
        return 0
    fi

    # 3) 部分系统暴露 /proc/net/nf_conntrack
    [ -f /proc/net/nf_conntrack ] && return 0

    return 1
}

# === v3.2.1 新增：qdisc 真实可设置探测（不依赖 lsmod）===
try_set_qdisc() {
    local q="$1"
    has_sysctl_key net.core.default_qdisc || return 1
    sysctl -w net.core.default_qdisc="$q" >/dev/null 2>&1
}

# === 4. 清理旧配置 ===
clean_old_config() {
    echo "🧹 清理旧配置..."

    # 清理旧服务
    systemctl stop net-optimize.service 2>/dev/null || true
    systemctl disable net-optimize.service 2>/dev/null || true
    rm -f /etc/systemd/system/net-optimize.service

    # 清理旧规则
    if have_cmd iptables; then
        iptables -t mangle -S 2>/dev/null | grep TCPMSS | while read -r rule; do
            del_rule="${rule/-A/-D}"
            iptables -t mangle $del_rule 2>/dev/null || true
        done
    fi

    # 清理旧配置目录
    rm -rf "$CONFIG_DIR"
    mkdir -p "$CONFIG_DIR"
}

# === 5. 工具安装（可选）===
maybe_install_tools() {
    if [ "$SKIP_APT" = "1" ]; then
        echo "⏭️ 跳过工具安装（SKIP_APT=1）"
        return 0
    fi

    if ! have_cmd apt-get; then
        echo "ℹ️ 非APT系统，跳过工具安装"
        return 0
    fi

    echo "🧰 安装必要工具..."
    check_dpkg_clean

    DEBIAN_FRONTEND=noninteractive apt-get update -y || echo "⚠️ apt update 失败"

    local packages=""
    packages+=" ca-certificates curl wget gnupg2 lsb-release"
    packages+=" ethtool iproute2 irqbalance chrony"
    packages+=" nftables conntrack iptables"
    packages+=" software-properties-common apt-transport-https"

    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends $packages || \
        echo "⚠️ 部分包安装失败"

    # 启用服务
    systemctl enable --now irqbalance chrony 2>/dev/null || true
}

# === 6. Ulimit 优化 ===
setup_ulimit() {
    echo "📂 优化文件描述符限制..."

    install -d /etc/security/limits.d
    cat > /etc/security/limits.d/99-net-optimize.conf <<'EOF'
# Net-Optimize Ultimate - File Descriptor Limits
*    soft nofile 1048576
*    hard nofile 1048576
root soft nofile 1048576
root hard nofile 1048576
EOF

    if ! grep -q '^DefaultLimitNOFILE=' /etc/systemd/system.conf 2>/dev/null; then
        echo 'DefaultLimitNOFILE=1048576' >> /etc/systemd/system.conf
    else
        sed -i 's/^DefaultLimitNOFILE=.*/DefaultLimitNOFILE=1048576/' /etc/systemd/system.conf
    fi

    for pam_file in /etc/pam.d/common-session /etc/pam.d/common-session-noninteractive; do
        if [ -f "$pam_file" ] && ! grep -q "pam_limits.so" "$pam_file"; then
            echo "session required pam_limits.so" >> "$pam_file"
        fi
    done

    systemctl daemon-reload >/dev/null 2>&1 || true
    echo "✅ ulimit 配置完成"
}

# === 7. 拥塞控制与队列算法（智能验证版）===
setup_tcp_congestion() {
    echo "📶 设置TCP拥塞算法和队列..."

    # --- 1) 队列 qdisc：真实尝试设置，不依赖 lsmod ---
    local target_qdisc=""
    if [ "$ENABLE_FQ_PIE" = "1" ] && try_set_qdisc fq_pie; then
        target_qdisc="fq_pie"
    elif try_set_qdisc fq; then
        target_qdisc="fq"
    elif try_set_qdisc pie; then
        target_qdisc="pie"
    else
        target_qdisc="$(sysctl -n net.core.default_qdisc 2>/dev/null || echo "unknown")"
    fi

    # --- 2) 拥塞算法：BBRplus > BBR > Cubic ---
    local target_cc="cubic"
    local available_cc
    available_cc=$(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null || echo "cubic")

    if echo "$available_cc" | grep -qw bbrplus; then
        target_cc="bbrplus"
    elif echo "$available_cc" | grep -qw bbr; then
        target_cc="bbr"
    fi

    if has_sysctl_key net.ipv4.tcp_congestion_control; then
        sysctl -w net.ipv4.tcp_congestion_control="$target_cc" >/dev/null 2>&1 || true
    fi

    # --- 3) 最终验证 ---
    local current_cc
    local current_qdisc
    current_cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "unknown")
    current_qdisc=$(sysctl -n net.core.default_qdisc 2>/dev/null || echo "unknown")

    echo "✅ 最终生效拥塞算法: $current_cc"
    echo "✅ 最终生效队列算法: $current_qdisc"

    if [[ "$target_cc" == "bbr"* ]] && [[ "$current_cc" != "$target_cc" ]]; then
        echo "⚠️ 提示: 尝试启用 $target_cc 失败，系统自动回退到了 $current_cc"
    fi
}

# === 8. Sysctl深度整合（写入文件）===
write_sysctl_conf() {
    echo "📊 写入内核参数配置文件..."

    local sysctl_file="/etc/sysctl.d/99-net-optimize.conf"
    install -d /etc/sysctl.d

    {
        echo "# ========================================================="
        echo "# 🚀 Net-Optimize Ultimate v3.2.1 - Kernel Parameters"
        echo "# Generated: $(date)"
        echo "# ========================================================="
        echo

        # === 基础网络参数 ===
        echo "# === 基础网络设置 ==="
        echo "net.core.netdev_max_backlog = 250000"
        echo "net.core.somaxconn = 1000000"
        echo "net.ipv4.tcp_max_syn_backlog = 819200"
        echo "net.ipv4.tcp_syncookies = 1"
        echo

        # === 连接生命周期 ===
        echo "# === 连接生命周期 ==="
        echo "net.ipv4.tcp_fin_timeout = 15"
        echo "net.ipv4.tcp_keepalive_time = 600"
        echo "net.ipv4.tcp_keepalive_intvl = 15"
        echo "net.ipv4.tcp_keepalive_probes = 2"
        echo "net.ipv4.tcp_max_tw_buckets = 5000"
        echo "net.ipv4.ip_local_port_range = 1024 65535"
        echo

        # === TCP算法优化 ===
        echo "# === TCP算法优化 ==="
        echo "net.ipv4.tcp_mtu_probing = $ENABLE_MTU_PROBE"
        echo "net.ipv4.tcp_slow_start_after_idle = 0"
        echo "net.ipv4.tcp_no_metrics_save = 0"
        echo "net.ipv4.tcp_ecn = 1"
        echo "net.ipv4.tcp_ecn_fallback = 1"
        echo "net.ipv4.tcp_notsent_lowat = 16384"
        echo "net.ipv4.tcp_fastopen = 3"
        echo "net.ipv4.tcp_timestamps = 1"
        echo "net.ipv4.tcp_autocorking = 0"
        echo "net.ipv4.tcp_low_latency = 1"
        echo "net.ipv4.tcp_orphan_retries = 1"
        echo "net.ipv4.tcp_retries2 = 5"
        echo "net.ipv4.tcp_synack_retries = 1"
        echo "net.ipv4.tcp_rfc1337 = 0"
        echo

        # === 内存缓冲区（64MB方案）===
        echo "# === 内存缓冲区优化 ==="
        echo "net.core.rmem_max = 67108864"
        echo "net.core.wmem_max = 67108864"
        echo "net.core.rmem_default = 67108864"
        echo "net.core.wmem_default = 67108864"
        echo "net.core.optmem_max = 65536"
        echo "net.ipv4.tcp_rmem = 4096 87380 67108864"
        echo "net.ipv4.tcp_wmem = 4096 65536 67108864"
        echo "net.ipv4.udp_rmem_min = 16384"
        echo "net.ipv4.udp_wmem_min = 16384"
        echo "net.ipv4.udp_mem = 65536 131072 262144"
        echo

        # === UDP活跃修复关键 ===
        echo "# === UDP连接优化 ==="
        echo "net.ipv4.ip_forward = 1"
        echo "net.ipv4.conf.all.forwarding = 1"
        echo "net.ipv4.conf.default.forwarding = 1"
        echo "net.ipv4.conf.all.route_localnet = 1"
        echo "net.ipv4.conf.all.rp_filter = 0"
        echo "net.ipv4.conf.default.rp_filter = 0"
        echo

        # === 安全加固 ===
        echo "# === 安全加固 ==="
        echo "net.ipv4.conf.all.accept_redirects = 0"
        echo "net.ipv4.conf.default.accept_redirects = 0"
        echo "net.ipv4.conf.all.secure_redirects = 0"
        echo "net.ipv4.conf.default.secure_redirects = 0"
        echo "net.ipv4.conf.all.send_redirects = 0"
        echo "net.ipv4.conf.default.send_redirects = 0"
        echo "net.ipv4.icmp_echo_ignore_broadcasts = 1"
        echo "net.ipv4.icmp_ignore_bogus_error_responses = 1"
        echo "net.ipv4.icmp_echo_ignore_all = 0"
        echo

        # === IPv6优化 ===
        echo "# === IPv6优化 ==="
        echo "net.ipv6.conf.all.disable_ipv6 = 0"
        echo "net.ipv6.conf.default.disable_ipv6 = 0"
        echo "net.ipv6.conf.all.forwarding = 1"
        echo "net.ipv6.conf.default.forwarding = 1"
        echo "net.ipv6.conf.all.accept_ra = 2"
        echo "net.ipv6.conf.default.accept_ra = 2"
        echo "net.ipv6.conf.all.use_tempaddr = 2"
        echo "net.ipv6.conf.default.use_tempaddr = 2"
        echo "net.ipv6.conf.all.accept_redirects = 0"
        echo "net.ipv6.conf.default.accept_redirects = 0"
        echo

        # === 邻居表调优 ===
        echo "# === 邻居表调优 ==="
        echo "net.ipv4.neigh.default.gc_thresh1 = 2048"
        echo "net.ipv4.neigh.default.gc_thresh2 = 4096"
        echo "net.ipv4.neigh.default.gc_thresh3 = 8192"
        echo "net.ipv6.neigh.default.gc_thresh1 = 2048"
        echo "net.ipv6.neigh.default.gc_thresh2 = 4096"
        echo "net.ipv6.neigh.default.gc_thresh3 = 8192"
        echo "net.ipv4.neigh.default.unres_qlen = 10000"
        echo

        # === 内核安全参数 ===
        echo "# === 内核安全 ==="
        echo "kernel.kptr_restrict = 1"
        echo "kernel.yama.ptrace_scope = 1"
        echo "kernel.sysrq = 176"
        echo "vm.mmap_min_addr = 65536"
        echo "vm.max_map_count = 1048576"
        echo "vm.swappiness = 1"
        echo "vm.overcommit_memory = 1"
        echo "kernel.pid_max = 4194304"
        echo

        # === 文件系统保护 ===
        echo "# === 文件系统保护 ==="
        echo "fs.protected_fifos = 1"
        echo "fs.protected_hardlinks = 1"
        echo "fs.protected_regular = 2"
        echo "fs.protected_symlinks = 1"
        echo

        # === 连接跟踪 ===
        if [ "$ENABLE_CONNTRACK_TUNE" = "1" ]; then
            echo "# === 连接跟踪优化 ==="
            echo "net.netfilter.nf_conntrack_max = $NFCT_MAX"
            echo "net.netfilter.nf_conntrack_udp_timeout = 30"
            echo "net.netfilter.nf_conntrack_udp_timeout_stream = 180"
            echo "net.netfilter.nf_conntrack_tcp_timeout_established = 432000"
            echo "net.netfilter.nf_conntrack_tcp_timeout_time_wait = 120"
            echo "net.netfilter.nf_conntrack_tcp_timeout_close_wait = 60"
            echo "net.netfilter.nf_conntrack_tcp_timeout_fin_wait = 120"
            echo
        fi

    } > "$sysctl_file"

    sysctl -e --system >/dev/null 2>&1 || echo "⚠️ 部分参数不支持，但不影响其他项"
    echo "✅ sysctl 参数已写入并应用"
}

# === 9. 连接跟踪模块加载 ===
setup_conntrack() {
    if [ "$ENABLE_CONNTRACK_TUNE" != "1" ]; then
        echo "⏭️ 跳过连接跟踪调优"
        return 0
    fi

    echo "🔗 加载连接跟踪模块..."

    # 这里依然尝试 modprobe：即使是内建，失败也不致命
    local modules=("nf_conntrack" "nf_conntrack_ipv4" "nf_conntrack_ipv6" "nf_conntrack_ftp")
    local loaded_modules=()

    for mod in "${modules[@]}"; do
        if modprobe "$mod" 2>/dev/null; then
            loaded_modules+=("$mod")
            echo "  ✅ 加载: $mod"
        fi
    done

    if [ ${#loaded_modules[@]} -gt 0 ]; then
        install -d /etc/modules-load.d
        printf "%s\n" "${loaded_modules[@]}" | sort -u > /etc/modules-load.d/net-optimize.conf
    fi

    printf "%s\n" "${loaded_modules[@]}" | sort -u > "$MODULES_FILE"

    echo "✅ 连接跟踪模块配置完成"
}

# === 10. MSS Clamping（三后端一致版：iptables / iptables-nft / iptables-legacy）===
setup_mss_clamping() {
    if [ "${ENABLE_MSS_CLAMP:-0}" != "1" ]; then
        echo "⏭️ 跳过MSS Clamping"
        return 0
    fi

    echo "📡 设置MSS Clamping (MSS=$MSS_VALUE)..."

    # 检测出口接口
    local iface
    iface="$(detect_outbound_iface)"

    if [ -z "${iface:-}" ]; then
        echo "⚠️ 无法确定出口接口，将使用全局规则"
        iface=""
    else
        echo "✅ 检测到出口接口: $iface"
    fi

    # 保存配置（供开机脚本读取）
    mkdir -p "$(dirname "$CONFIG_FILE")"
    cat > "$CONFIG_FILE" <<EOF
ENABLE_MSS_CLAMP=1
CLAMP_IFACE=$iface
MSS_VALUE=$MSS_VALUE
EOF

    # 选择要处理的 iptables 后端
    local ipt_cmds=()
    for c in iptables iptables-nft iptables-legacy; do
        if have_cmd "$c"; then
            ipt_cmds+=("$c")
        fi
    done

    if [ "${#ipt_cmds[@]}" -eq 0 ]; then
        echo "⚠️ iptables 不可用，跳过规则设置"
        return 0
    fi

    # 确保内核模块（尽量加载，失败不致命）
    echo "🛠️ 加载iptables模块..."
    for module in ip_tables iptable_filter iptable_mangle; do
        if ! lsmod 2>/dev/null | grep -q "^${module} "; then
            if modprobe "$module" 2>/dev/null; then
                echo "  ✅ 加载: $module"
            else
                echo "  ⚠️ 无法加载: $module（可能内建或不需要）"
            fi
        fi
    done

    # 删除 TCPMSS 规则（逐条删，避免误伤其他规则）
    _mss_clear_one_backend() {
        local cmd="$1"
        local rules del parts
        local round=0

        echo "🧹 [$cmd] 清理旧MSS规则..."

        while :; do
            rules="$("$cmd" -t mangle -S POSTROUTING 2>/dev/null | grep -E '(^-A POSTROUTING .*TCPMSS| TCPMSS )' || true)"
            [ -z "$rules" ] && break

            # 一次最多清 50 轮，防止异常死循环
            round=$((round + 1))
            if [ "$round" -gt 50 ]; then
                echo "  ⚠️ [$cmd] 清理轮次过多，停止以避免死循环"
                break
            fi

            # 逐行删
            while IFS= read -r rule; do
                [ -z "$rule" ] && continue
                # 把 -A POSTROUTING 替换成 -D POSTROUTING
                del="${rule/-A POSTROUTING/-D POSTROUTING}"
                # 拆成数组，避免 eval
                read -r -a parts <<<"$del"
                "$cmd" -t mangle "${parts[@]}" 2>/dev/null || true
            done <<<"$rules"
        done
    }

    # 添加 TCPMSS 规则（先 -C 检查避免重复）
    _mss_apply_one_backend() {
        local cmd="$1"
        local ok=0

        echo "➕ [$cmd] 添加MSS规则..."

        if [ -n "$iface" ] && [ "$iface" != "unknown" ]; then
            if "$cmd" -t mangle -C POSTROUTING -o "$iface" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "$MSS_VALUE" 2>/dev/null; then
                echo "  ✅ [$cmd] 已存在：iface=$iface MSS=$MSS_VALUE"
                ok=1
            else
                if "$cmd" -t mangle -A POSTROUTING -o "$iface" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "$MSS_VALUE" 2>/dev/null; then
                    echo "  ✅ [$cmd] 已添加：iface=$iface MSS=$MSS_VALUE"
                    ok=1
                else
                    echo "  ⚠️ [$cmd] 添加失败（iface 规则）"
                fi
            fi
        else
            if "$cmd" -t mangle -C POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "$MSS_VALUE" 2>/dev/null; then
                echo "  ✅ [$cmd] 已存在：global MSS=$MSS_VALUE"
                ok=1
            else
                if "$cmd" -t mangle -A POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "$MSS_VALUE" 2>/dev/null; then
                    echo "  ✅ [$cmd] 已添加：global MSS=$MSS_VALUE"
                    ok=1
                else
                    echo "  ⚠️ [$cmd] 添加失败（global 规则）"
                fi
            fi
        fi

        return "$ok"
    }

    # 1) 三后端全清理
    for cmd in "${ipt_cmds[@]}"; do
        _mss_clear_one_backend "$cmd"
    done

    # 2) 三后端都写入（这样未来你切换 alternatives 也不会丢）
    local success=0
    for cmd in "${ipt_cmds[@]}"; do
        if _mss_apply_one_backend "$cmd"; then
            success=1
        fi
    done

    # 3) 验证输出（逐后端）
    echo "🔍 验证MSS规则（逐后端）..."
    for cmd in "${ipt_cmds[@]}"; do
        echo "---- [$cmd] ----"
        "$cmd" -t mangle -L POSTROUTING -n -v 2>/dev/null | grep -E 'Chain|pkts|bytes|TCPMSS' || echo "  (none)"
        echo "count: $(("$cmd" -t mangle -S POSTROUTING 2>/dev/null | grep -c TCPMSS || true))"
    done

    if [ "$success" -eq 1 ]; then
        echo "✅ MSS Clamping 设置完成"
        return 0
    else
        echo "❌ MSS Clamping 设置失败（所有后端都未成功写入）"
        return 1
    fi
}

# === 11. Nginx官方源（完整实现）===
fix_nginx_repo() {
    if [ "$ENABLE_NGINX_REPO" != "1" ]; then
        echo "⏭️ 跳过Nginx源配置"
        return 0
    fi

    if [ "$SKIP_APT" = "1" ]; then
        echo "⏭️ SKIP_APT=1，跳过Nginx源配置（不触碰APT）"
        return 0
    fi

    if ! have_cmd apt-get; then
        echo "⚠️ 非APT系统，跳过Nginx配置"
        return 0
    fi

    echo "🔧 配置nginx.org官方源..."
    check_dpkg_clean

    local distro_info
    distro_info=$(detect_distro)
    local distro="${distro_info%:*}"
    local codename="${distro_info#*:}"

    local nginx_url=""
    case "$distro" in
        ubuntu) nginx_url="http://nginx.org/packages/ubuntu/" ;;
        debian) nginx_url="http://nginx.org/packages/debian/" ;;
        *)      nginx_url="http://nginx.org/packages/debian/" ;;
    esac

    if [ -z "$codename" ] || [ "$codename" = "unknown" ]; then
        codename="stable"
    fi

    echo "📌 发行版: $distro"
    echo "📌 Codename: $codename"
    echo "📌 Nginx源: ${nginx_url}${codename}"

    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        gnupg2 curl ca-certificates lsb-release software-properties-common || \
        echo "⚠️ 依赖安装失败，继续尝试"

    rm -f /etc/apt/sources.list.d/nginx*.list

    if ! curl -fsSL https://nginx.org/keys/nginx_signing.key | \
        gpg --dearmor --yes -o /usr/share/keyrings/nginx-archive-keyring.gpg 2>/dev/null; then
        echo "⚠️ GPG密钥下载失败，尝试其他方法..."
        apt-key adv --keyserver keyserver.ubuntu.com --recv-keys ABF5BD827BD9BF62 2>/dev/null || true
    fi

    cat > /etc/apt/sources.list.d/nginx-official.list <<EOF
deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] ${nginx_url} ${codename} nginx
deb-src [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] ${nginx_url} ${codename} nginx
EOF

    cat > /etc/apt/preferences.d/99-nginx-official <<'EOF'
Package: nginx*
Pin: origin nginx.org
Pin-Priority: 1001
EOF

    apt-get update -y || echo "⚠️ apt update 失败"
    apt-get remove -y nginx-common nginx-core nginx-full nginx-light 2>/dev/null || true

    echo "📦 安装nginx.org最新版..."
    if DEBIAN_FRONTEND=noninteractive apt-get install -y nginx; then
        systemctl restart nginx 2>/dev/null || true
        systemctl enable nginx 2>/dev/null || true

        local cron_file="/etc/cron.d/net-optimize-nginx-update"
        cat > "$cron_file" <<'CRON_JOB'
# 每月1号凌晨3点自动更新nginx
0 3 1 * * root DEBIAN_FRONTEND=noninteractive apt-get update && apt-get install --only-upgrade -y nginx > /dev/null 2>&1
CRON_JOB
        chmod 644 "$cron_file"

        echo "✅ Nginx官方源配置完成，已添加自动更新任务"
    else
        echo "⚠️ Nginx安装失败，请检查网络连接"
    fi
}

# === 12. 开机自启服务 ===
install_boot_service() {
    if [ "$APPLY_AT_BOOT" != "1" ]; then
        echo "⏭️ 跳过开机自启配置"
        return 0
    fi

    echo "🛠️ 配置开机自启动服务..."

    cat > "$APPLY_SCRIPT" <<'EOF'
#!/bin/bash
set -euo pipefail

MODULES_FILE="/etc/net-optimize/modules.list"
if [ -f "$MODULES_FILE" ]; then
    while IFS= read -r module; do
        [ -n "$module" ] && modprobe "$module" 2>/dev/null || true
    done < "$MODULES_FILE"
fi

sysctl -e --system >/dev/null 2>&1 || true

CONFIG_FILE="/etc/net-optimize/config"
if [ -f "$CONFIG_FILE" ]; then
    . "$CONFIG_FILE"

    if [ "${ENABLE_MSS_CLAMP:-0}" = "1" ] && command -v iptables >/dev/null; then
        MSS="${MSS_VALUE:-1452}"
        IFACE="${CLAMP_IFACE:-}"

        modprobe ip_tables 2>/dev/null || true
        modprobe iptable_mangle 2>/dev/null || true

        iptables -t mangle -S POSTROUTING 2>/dev/null | grep "TCPMSS" | while read -r rule; do
            del_rule="${rule/-A/-D}"
            iptables -t mangle $del_rule 2>/dev/null || true
        done

        if [ -n "$IFACE" ] && [ "$IFACE" != "unknown" ]; then
            iptables -t mangle -A POSTROUTING -o "$IFACE" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "$MSS"
        else
            iptables -t mangle -A POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "$MSS"
        fi
    fi
fi

echo "[$(date)] Net-Optimize 开机优化完成"
EOF

    chmod +x "$APPLY_SCRIPT"

    cat > /etc/systemd/system/net-optimize.service <<'EOF'
[Unit]
Description=Net-Optimize Ultimate Boot Optimization
After=network-online.target
Wants=network-online.target
Before=nginx.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/net-optimize-apply
RemainAfterExit=yes
StandardOutput=journal
TimeoutSec=30

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable net-optimize.service >/dev/null 2>&1

    echo "✅ 开机自启服务配置完成"
}

# === 13. 状态检查（完整）===
print_status() {
    echo ""
    echo "==================== 优化状态报告 ===================="

    echo "📊 基础状态:"
    echo "  TCP拥塞算法: $(get_sysctl net.ipv4.tcp_congestion_control)"
    echo "  默认队列: $(get_sysctl net.core.default_qdisc)"
    echo "  文件句柄限制: $(ulimit -n)"
    echo "  内存缓冲区: $(get_sysctl net.core.rmem_default) bytes"
    echo ""

    echo "🌐 网络状态:"
    echo "  IP转发: $(get_sysctl net.ipv4.ip_forward)"
    echo "  路由过滤: $(get_sysctl net.ipv4.conf.all.rp_filter)"
    echo "  IPv6状态: $(get_sysctl net.ipv6.conf.all.disable_ipv6)"
    echo "  TCP ECN: $(get_sysctl net.ipv4.tcp_ecn)"
    echo "  TCP FastOpen: $(get_sysctl net.ipv4.tcp_fastopen)"
    echo ""

    echo "🔗 连接跟踪:"
    if conntrack_available; then
        echo "  ✅ conntrack 可用（模块或内建）"
        echo "  最大连接数: $(get_sysctl net.netfilter.nf_conntrack_max)"

        if [ -f /proc/net/nf_conntrack ]; then
            # 注意：grep -c 在 0 匹配时也会输出 0，但 exit code=1
            # 这里用 || true + 兜底，避免出现 0\n0
            udp_count="$(grep -c '^udp' /proc/net/nf_conntrack 2>/dev/null || true)"
            tcp_count="$(grep -c '^tcp' /proc/net/nf_conntrack 2>/dev/null || true)"

            # 防御性处理：只取第一行，空值视为 0
            udp_count="${udp_count%%$'\n'*}"
            tcp_count="${tcp_count%%$'\n'*}"
            udp_count="${udp_count:-0}"
            tcp_count="${tcp_count:-0}"

            echo "  UDP连接: $udp_count"
            echo "  TCP连接: $tcp_count"
            echo "  总连接数: $((udp_count + tcp_count))"
        else
            echo "  ℹ️ /proc/net/nf_conntrack 不存在（可能是 nftables / 内核暴露差异）"
        fi
    else
        echo "  ⚠️ conntrack 不可用（内核未启用 netfilter conntrack）"
    fi
    echo ""

    echo "📡 MSS Clamping规则:"
    if have_cmd iptables && iptables -t mangle -L POSTROUTING -n 2>/dev/null | grep -q TCPMSS; then
        iptables -t mangle -L POSTROUTING -n 2>/dev/null | grep TCPMSS
    else
        echo "  ⚠️ 未找到MSS规则"
    fi
    echo ""

    echo "💻 系统信息:"
    echo "  内核版本: $(uname -r)"
    echo "  发行版: $(detect_distro)"
    echo "  内存: $(free -h | awk '/^Mem:/ {print $2}')"
    echo "  可用内存: $(free -h | awk '/^Mem:/ {print $7}')"

    echo "======================================================"
    echo ""
}

# === 14. 主流程 ===
main() {
    require_root

    echo "🚀 Net-Optimize-Ultimate v3.2.1 启动..."
    echo "========================================================"

    clean_old_config
    maybe_install_tools
    setup_ulimit
    setup_tcp_congestion
    write_sysctl_conf
    setup_conntrack
    setup_mss_clamping
    fix_nginx_repo
    install_boot_service

    print_status

    echo "✅ 所有优化配置完成！"
    echo ""
    echo "📌 重要提示："
    echo "  1. 64MB缓冲区需要重启后完全生效"
    echo "  2. 检查状态: systemctl status net-optimize"
    echo "  3. 查看连接: cat /proc/net/nf_conntrack | head -20"
    echo "  4. 验证MSS: iptables -t mangle -L -n -v"
    echo ""

    if [ -t 0 ]; then
        read -r -p "🔄 是否立即重启以生效所有优化？(y/N): " answer
        if [[ "$answer" =~ ^[Yy]$ ]]; then
            echo "🌀 系统将在3秒后重启..."
            sleep 3
            reboot
        else
            echo "📌 请稍后手动重启以应用所有优化"
        fi
    else
        echo "📌 非交互模式，请手动重启以应用优化"
    fi
}

# === 15. 执行 ===
main