# VPS 工具安装脚本

这是一个用于 **VPS/Linux 服务器初始化** 的工具安装脚本，支持一键安装常用的软件和系统工具，智能跳过已安装的包。

## 功能
- 🔹 自动更新系统
- 🔹 安装常用编辑器和基础工具（nano、vim、git、wget、curl 等）
- 🔹 安装网络调试和监控工具（htop、iftop、mtr、tcpdump、netcat-openbsd 等）
- 🔹 安装并启用 `cron`
- 🔹 安装 Python3 环境
- 🔹 安装性能调优工具（ethtool、sysstat、lsof 等）
- 🔹 配置 `unattended-upgrades` 自动安全更新
- 🔹 自动清理无用包和缓存

## 一键执行
在 VPS 上执行以下命令即可一键运行（自动下载并执行最新脚本）：

```bash
bash <(wget -qO- https://raw.githubusercontent.com/SHICHUNHUI88/vps-net-optimize/main/setup-tools.sh)
```

---

## 🌏 vps-net-optimize

一键优化脚本，适用于 TCP / UDP / IPv6 / ulimit / MSS 等场景的 VPS 网络性能优化。

---

## 🚀 一键执行网络优化配置
（网络优化之前请先装VPS适用工具，否则网络优化可能安装不成功）

复制以下命令，在 VPS 上粘贴执行：

```bash
bash <(curl -Ls https://raw.githubusercontent.com/SHICHUNHUI88/vps-net-optimize/main/net-optimize-full.sh)
```

---

## 🔍 一键检测当前网络优化状态

复制以下命令，在 VPS 上粘贴执行：

```bash
wget -qO- https://raw.githubusercontent.com/SHICHUNHUI88/vps-net-optimize/main/net-optimize-check.sh | bash
```
---

## ❌ 一键还原并删除所有网络优化配置

复制以下命令，在 VPS 上粘贴执行：
```bash
bash <(curl -fsSL https://raw.githubusercontent.com/SHICHUNHUI88/vps-net-optimize/main/net-optimize-reset.sh)
```
---