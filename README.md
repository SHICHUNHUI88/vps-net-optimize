# VPS 适用工具安装脚本

这是一个用于 **VPS/Linux 服务器初始化** 的工具安装脚本，支持一键安装常用的软件和系统工具，智能跳过已安装的包。

## 功能
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

## 🧬 BBRPlus 内核一键安装（慎用❗）

**📢适用于 RAM 足够的 KVM VPS**

**🚫⚠ AMD 核心 VPS 请勿安装，否则可能会死机！**

```bash
wget -O bbrplus.sh https://raw.githubusercontent.com/ylx2016/Linux-NetSpeed/master/tcp.sh && chmod +x bbrplus.sh && ./bbrplus.sh
```

---

## 🌏 vps-net-optimize

一键优化脚本，适用于 TCP / UDP / IPv6 / ulimit / MSS 等场景的 VPS 网络性能优化。

---

## 🚀 一键执行网络优化配置
❗**网络优化之前请先装VPS适用工具，否则网络优化可能安装不成功**

复制以下命令，在 VPS 上粘贴执行：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/SHICHUNHUI88/vps-net-optimize/main/net-optimize-ultimate.sh)
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

# 🛰 VPS 11种协议一键安装脚本

由 mack-a 开发的 V2ray / Xray / Trojan / Reality 综合安装程序。

⚠️安装前请准备好**域名**托管到CF指向VPS的IP不要开小黄云才能执行代码

**步骤：
1️⃣ 选 1 安装 ， 2️⃣ 选 2 安装 Sing-box  ，3️⃣ 输入你自己的域名......，不懂就问AI**

```bash
wget -P /root -N --no-check-certificate "https://raw.githubusercontent.com/mack-a/v2ray-agent/master/install.sh" && chmod 700 /root/install.sh && /root/install.sh
```
代码跑完之后建议把所有的连接信息复制下来保存到**谷歌文档**，方便以后提取

---

# 📱 ClashMeta/Clash Mi可直接提取的 10 协议模板，只支持mihomo核心（移动端可用）

适用于 Android 手機 ClashMeta /Clash Mi（ Mihomo
）支持与 VPS 11协议配合使用：

👉 一键查看模板：

https://cdn.gh-proxy.org/https://gist.github.com/SHICHUNHUI88/099059cfce913ef7b80496fbf4241324/raw/us_la.yaml

可以将此模板全部复制给gpt让他记住，然后把VPS的11个协议全部复制出来给gpt让他按照这个模板来提取连接配置更换就可以了

---

# 📱 Singbox 可直接提取的 10 协议模板（移动端可用）

**✅ 适配Android sing-box 内核 1.12.12以上**

👉 一键查看模板：

https://cdn.gh-proxy.org/https://gist.github.com/SHICHUNHUI88/ea81e07938efe1b2e892db7a9bee872e/raw/singbox-v1.12-config.json

---

# ClashMi Geo RuleSet（自建镜像）

本仓库将上游 Geo 规则库同步到我的仓库中，主要用于 **ClashMi / mihomo** 的 **Geo RuleSet（MRS 拆分规则集）** 拉取。

这样做的目的：
- 使用自己的链接，避免上游访问不稳定导致拉取失败
- 每天定时同步上游更新（包含 **增删同步**），本仓库始终保持最新

---

## 上游来源（Loyalsoldier）

本仓库同步并转换的 `.srs` 规则集来自 Loyalsoldier：

geox-url: 
  - geoip:   "https://cdn.jsdelivr.net/gh/Loyalsoldier/geoip@release/geoip.dat" 
  - geosite:"https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geosite.dat"


---

## 使用方法（ClashMi）

在 ClashMi → **Geo RuleSet** 中填写以下两个目录链接（推荐使用 CDN）：

### GeoSite mrs（域名-mrs 规则集目录）
```
https://cdn.jsdelivr.net/gh/SHICHUNHUI88/vps-net-optimize@main/geo/geosite
```
https://github.com/SHICHUNHUI88/vps-net-optimize/tree/main/geo/geosite

### GeoIP（IP-mrs 规则集目录）
```
https://cdn.jsdelivr.net/gh/SHICHUNHUI88/vps-net-optimize@main/geo/geoip
```
https://github.com/SHICHUNHUI88/vps-net-optimize/tree/main/geo/geoip

> 说明：这是“目录链接”，ClashMi 会按需下载其中的 `.mrs` 小文件（例如 
- `geosite/google.mrs`
- `geoip/google.mrs`

---

## 同步机制

- 上游来源：Loyalsoldier / MetaCubeX 相关 Geo 规则体系（拆分 `.mrs`）
- 同步频率：每日自动同步（北京时间凌晨更新）
- 同步策略：**增删同步**（上游新增/删除/更新都会同步到本仓库）

---

## 目录结构（Loyalsoldier）

singbox/
  Loy-geosite/   # 域名类规则集（.srs）
  Loy-geoip/     # IP 类规则集（.srs）

---

## CDN 目录链接（推荐）

### Loy-GeoSite（SRS 目录）
```
https://cdn.jsdelivr.net/gh/SHICHUNHUI88/vps-net-optimize@main/singbox/Loy-geosite
```
https://github.com/SHICHUNHUI88/vps-net-optimize/tree/main/singbox/Loy-geosite

### Loy-GeoIP（SRS 目录）
```
https://cdn.jsdelivr.net/gh/SHICHUNHUI88/vps-net-optimize@main/singbox/Loy-geoip
```
https://github.com/SHICHUNHUI88/vps-net-optimize/tree/main/singbox/Loy-geoip

> 说明：这是“目录链接”，singbox 会按需下载其中的 `.srs` 小文件（例如
- `Loy-geosite/geosite-google.srs`
- `Loy-geoip/geoip-google.srs`

---
# sing-box RuleSet Mirror（Split SRS）

本仓库提供 **sing-box 拆分规则集（`.srs`）** 的自建镜像，主要用于在 sing-box 配置中通过 `rule_set: remote` 方式按需拉取规则。

特点：
- **拆分小件**：按分类提供大量 `.srs` 文件（例如 `geosite-openai.srs`、`geoip-cn.srs`）
- **自建镜像**：将上游规则集同步到我的仓库，便于国内/跨网环境稳定拉取
- **增删同步**：上游新增/删除/更新都会同步到本仓库
- **定时更新**：每日自动同步（北京时间凌晨）

---

## 上游来源

本仓库同步的拆分 `.srs` 规则集来自 sing-box 官方生态（SagerNet）：

- `SagerNet/sing-geosite`（geosite 拆分规则集）
- `SagerNet/sing-geoip`（geoip 拆分规则集）

---

## 目录结构
singbox/ geosite/   # 域名类规则集（.srs） geoip/     # IP 类规则集（.srs）
---

## CDN 目录链接（推荐）

### GeoSite（SRS 目录）
```
https://cdn.jsdelivr.net/gh/SHICHUNHUI88/vps-net-optimize@main/singbox/geosite
```
https://github.com/SHICHUNHUI88/vps-net-optimize/tree/main/singbox/geosite

### GeoIP（SRS 目录）
```
https://cdn.jsdelivr.net/gh/SHICHUNHUI88/vps-net-optimize@main/singbox/geoip
```
https://github.com/SHICHUNHUI88/vps-net-optimize/tree/main/singbox/geoip

> 说明：这是“目录链接”，singbox 会按需下载其中的 `.srs` 小文件（例如
- `geosite/geosite-google.srs`
- `geoip/geoip-google.srs`

