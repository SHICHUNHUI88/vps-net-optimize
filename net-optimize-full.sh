#!/bin/bash
set -e

echo "🚀 开始执行全局网络优化（TCP+UDP+IPv6+WiFi+ulimit+Nginx）..."
echo "------------------------------------------------------------"

# 是否交互模式
interactive=0
[ -t 0 ] && interactive=1

# === 函数定义 ===

clean_old_config() {
    echo "🧹 清理旧配置..."
    rm -f /etc/rc.local 2>/dev/null
    sed -i '/^\* soft nofile/d;/^\* hard nofile/d' /etc/security/limits.conf
    sed -i '/^DefaultLimitNOFILE=/d' /etc/systemd/system.conf /etc/systemd/user.conf
    rm -f /etc/systemd/system.conf.d/99-nofile.conf /etc/systemd/system/ssh.service.d/override.conf 2>/dev/null
    sed -i '/^net.core.default_qdisc/d;/^net.ipv4.tcp_congestion_control/d;/^net.ipv4.tcp_mtu_probing/d;/^net.ipv4.ip_forward/d;/^net.ipv6.conf.all.forwarding/d;/^net.ipv6.conf.default.forwarding/d;/^net.ipv6.conf.all.accept_ra/d;/^net.ipv6.conf.default.accept_ra/d;/^net.ipv4.conf.all.rp_filter/d;/^net.ipv4.conf.default.rp_filter/d;/^net.ipv4.icmp_echo_ignore_broadcasts/d;/^net.ipv4.icmp_ignore_bogus_error_responses/d' /etc/sysctl.conf
}

setup_tcp_congestion() {
    echo "📶 设置 TCP 拥塞算法和队列..."
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
}

setup_ulimit() {
    echo "📂 设置 ulimit ..."
    sed -i '/\* soft nofile/d;/\* hard nofile/d' /etc/security/limits.conf
    echo "* soft nofile 1048576" >> /etc/security/limits.conf
    echo "* hard nofile 1048576" >> /etc/security/limits.conf
    sed -i '/^DefaultLimitNOFILE=/d' /etc/systemd/system.conf
    sed -i '/^DefaultLimitNOFILE=/d' /etc/systemd/user.conf
    echo "DefaultLimitNOFILE=1048576" >> /etc/systemd/system.conf
    echo "DefaultLimitNOFILE=1048576" >> /etc/systemd/user.conf
    mkdir -p /etc/systemd/system/sshd.service.d
    cat > /etc/systemd/system/sshd.service.d/override.conf <<EOF
[Service]
LimitNOFILE=1048576
EOF
    grep -q pam_limits.so /etc/pam.d/common-session || echo "session required pam_limits.so" >> /etc/pam.d/common-session
    grep -q 'ulimit -n 1048576' ~/.bashrc || echo 'ulimit -n 1048576' >> ~/.bashrc
}

enable_mtu_probe() {
    echo "🌐 启用 TCP MTU 探测..."
    sed -i '/^net.ipv4.tcp_mtu_probing/d' /etc/sysctl.conf
    echo "net.ipv4.tcp_mtu_probing = 2" >> /etc/sysctl.conf
    sysctl -w net.ipv4.tcp_mtu_probing=2
}

setup_mss_clamping() {
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
        iptables -t mangle -D $chain -p tcp --tcp-flags SYN,RST SYN -j TCPMSS 2>/dev/null || true
        iptables -t mangle -A $chain -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss $mss
    done
    DEBIAN_FRONTEND=noninteractive apt-get update -y >/dev/null
    DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent netfilter-persistent >/dev/null
    netfilter-persistent save || echo "⚠️ 保存 iptables 失败"
    systemctl enable netfilter-persistent || true
}

udp_optimize() {
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
}

nf_conntrack_optimize() {
    echo "🧩 启用 nf_conntrack ..."
    modprobe nf_conntrack 2>/dev/null || modprobe nf_conntrack_ipv4 2>/dev/null || true
    echo nf_conntrack > /etc/modules-load.d/nf_conntrack.conf
    sysctl -w net.netfilter.nf_conntrack_max=262144
    sysctl -w net.netfilter.nf_conntrack_udp_timeout=30
    sysctl -w net.netfilter.nf_conntrack_udp_timeout_stream=180
}

write_sysctl_conf() {
    echo "📊 写入 sysctl 参数..."
    cat >> /etc/sysctl.conf <<EOF
net.core.default_qdisc = fq_pie
net.ipv4.tcp_congestion_control = $(sysctl -n net.ipv4.tcp_congestion_control)
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
# 安全优化
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
EOF
    sysctl -p
}

fix_nginx_repo() {
    echo "🔧 修复 nginx.org 官方源并安装最新版本..."
    
    # 获取系统代号
    codename=$(lsb_release -sc)

    # 安装必要工具
    apt-get install -y software-properties-common apt-transport-https gnupg2 ca-certificates lsb-release curl

    # 配置 nginx 官方源
    rm -f /etc/apt/sources.list.d/nginx.list
    cat > /etc/apt/sources.list.d/nginx.list <<EOF
deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] http://nginx.org/packages/ubuntu/ $codename nginx
deb-src [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] http://nginx.org/packages/ubuntu/ $codename nginx
EOF

    # 导入公钥
    curl -fsSL https://nginx.org/keys/nginx_signing.key | gpg --dearmor --yes -o /usr/share/keyrings/nginx-archive-keyring.gpg

    # 配置优先级
    cat > /etc/apt/preferences.d/99nginx <<EOF
Package: nginx*
Pin: origin nginx.org
Pin-Priority: 1001
EOF

    # 更新和安装 nginx
    apt-get update -y
    apt-get remove -y nginx-core nginx-common || true
    DEBIAN_FRONTEND=noninteractive apt-get install -y nginx

    # 重启 nginx 并显示版本
    systemctl restart nginx
    nginx -v
    systemctl status nginx | grep Active

    # 设置 root 用户的定时任务
    cron_job="0 3 1 * * /bin/bash -c 'DEBIAN_FRONTEND=noninteractive apt-get update -y && apt-get install -y nginx'"

    # 使用临时文件安全写入 root crontab
    tmpfile=$(mktemp)
    sudo crontab -l -u root 2>/dev/null > "$tmpfile"
    grep -Fq "$cron_job" "$tmpfile" || echo "$cron_job" >> "$tmpfile"
    sudo crontab -u root "$tmpfile"
    rm -f "$tmpfile"

    echo "✅ 已启用 nginx.org 官方源并优先使用"
    echo "🗓️ 已设置定时任务：每月 1 号凌晨 3 点自动更新 Nginx (root 用户)"
}

install_conntrack() {
    echo "🔧 安装 conntrack 工具..."
    apt-get install -y conntrack >/dev/null 2>&1
}

setup_boot_restore() {
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
    iptables -t mangle -D \$chain -p tcp --tcp-flags SYN,RST SYN -j TCPMSS 2>/dev/null || true
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

[Install]
WantedBy=multi-user.target
EOL
    systemctl daemon-reload
    systemctl enable net-optimize.service
}

print_status() {
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
}

ask_reboot() {
    if [ "$interactive" = "1" ]; then
        read -p "🔁 是否立即重启以使优化生效？(y/N): " answer
        if [[ "$answer" =~ ^[Yy]$ ]]; then
            echo "🌀 正在重启..."
            (sleep 1; reboot) &
        else
            echo "📌 请稍后手动重启以生效所有配置"
        fi
    else
        echo "📌 非交互模式执行，未触发重启，建议手动重启"
    fi
}

main() {
    clean_old_config
    setup_tcp_congestion
    setup_ulimit
    enable_mtu_probe
    setup_mss_clamping
    udp_optimize
    nf_conntrack_optimize
    write_sysctl_conf
    fix_nginx_repo
    install_conntrack
    setup_boot_restore
    print_status
    ask_reboot
    echo "🎉 网络优化完成，重启后将自动恢复设置！"
}

# === 执行 ===
main
