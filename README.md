# ASNIPtest

从 **ASN 编号** 出发，自动完成 IP 段拉取 → 端口扫描 → Cloudflare 反代节点检测，输出可用 CF 节点 CSV。

---

## 目录

- [快速开始](#快速开始)
- [安装](#安装)
  - [Linux / macOS](#linux--macos)
  - [Windows（WSL2）](#windowswsl2)
- [使用](#使用)
  - [命令行模式](#命令行模式)
  - [交互模式](#交互模式)
- [工作流程](#工作流程)
- [输出格式](#输出格式)
- [硬件自适应](#硬件自适应)
- [依赖](#依赖)
- [卸载](#卸载)

---

## 快速开始

**Linux / macOS**
```bash
curl -fsSL https://github.250887.xyz/https://raw.githubusercontent.com/cpddli/ASNIPtest/main/install.sh | bash
```

## 卸载

```bash
curl -fsSL https://github.250887.xyz/https://raw.githubusercontent.com/cpddli/ASNIPtest/main/uninstall.sh | bash
```

这会删除 `cmtjd` 命令和 `~/ASNIPtest` 目录。

### 命令行模式

直接指定 ASN 编号启动扫描：

```bash
cmtjd AS209242            # 单个 ASN
cmtjd AS209242,AS3214     # 多个 ASN（逗号分隔）
cmtjd AS209242 AS3214     # 多个 ASN（空格分隔）
```

### 后台运行（SSH 断线不杀）

长扫描（5-30分钟），担心 SSH 断线可以用 `screen`：

```bash
# 安装 screen（仅首次）
apt install -y screen

# 启动 screen 会话
screen -S scan

# 在里面正常跑 cmtjd AS209242
# 按 Ctrl+A 再按 D 断开（进程继续跑）
```

下次 SSH 连回来，`screen -r scan` 即可恢复查看。

> 如果记不清会话名，`screen -ls` 列出所有会话。

### 交互模式

不带参数运行，进入交互提示：

```bash
cmtjd
```
  硬件: 4核 2048MB → masscan 4000pps ...

  本机公网 IP: 1.2.3.4
  地区: Tokyo, JP  运营商: xxx

  输入 ASN 编号 (多个用逗号分隔): _
```

输入 ASN 后自动开始扫描。完成后自动提供 CSV 下载链接。

> 扫描完成后提供手动测速选项（TCP 延迟 + CF 下载带宽），用户可选择是否测速。

---

## 工作流程

```
用户输入 ASN
    │
    ▼
┌──────────────────────┐
│ 1. ASN → CIDR        │  RIPEStat API 查询该 ASN 广播的所有 IPv4 前缀
├──────────────────────┤
│ 2. masscan 端口扫描   │  高速 SYN 扫描（CIDR 直接传入，跳过 prips 展开）
├──────────────────────┤
│ 3. cf-scanner 粗筛   │  TLS 握手检测，命中 Cloudflare 反代节点
├──────────────────────┤
│ 4. API 精筛          │  api.090227.xyz/check 二次验证（TLS + 数据中心 + 地区）
├──────────────────────┤
│ 5. 手动测速（可选）    │  TCP 延迟 + CF 文件下载速度
├──────────────────────┤
│ 输出 CSV + 下载链接   │  临时 HTTP 服务提供文件下载
└──────────────────────┘
```

---

## 输出格式

运行完成后生成 CSV 文件并启动临时下载服务：

```
📥 下载链接 (临时, 按回车关闭):
http://1.2.3.4:8899/output_AS209242_20260617_120000.csv

结果: 42 条 → output_AS209242_20260617_120000.csv
```

**CSV 列说明：**

| 列 | 说明 | 示例 |
|---|---|---|
| IP地址 | Cloudflare 节点 IP | `162.159.192.1` |
| 端口 | TLS 端口 | `443` |
| TLS | TLS 版本 | `TRUE` |
| 数据中心 | CF 数据中心代号 | `HKG` |
| 地区 | 国家/地区代码 | `HK` |
| 城市 | 城市名 | `Hong Kong` |
| 网络延迟 | TCP 延迟 (ms) | `42` |
| 下载速度 | CF 下载带宽 (Mbps) | `5.12` |
| ASN | 源 ASN 编号 | `AS209242` |

> 下载链接自动检测本机 IP，同时显示局域网和公网地址（公网不同时）。按 **回车** 关闭下载服务。

---

## 硬件自适应

启动时自动探测网卡实际发包能力（取最优速率的 80%），同时根据 CPU 核数和内存调整并发

## 依赖

| 工具 | 用途 | 安装方式 |
|---|---|---|
| [masscan](https://github.com/robertdavidgraham/masscan) | 高速端口扫描 | `apt install masscan` 或源码编译 |
| cf-scanner | CF 反代节点检测 | 内置，自动编译 |
| [RIPEStat API](https://stat.ripe.net/) | ASN → CIDR | 免费公开，无需注册 |

> `install.sh` 自动处理所有依赖。

### 不支持的环境

masscan 依赖 **raw socket**（CAP_NET_RAW），以下环境有限制：

- ❌ NAT 容器（独角鲸/小鲸等，缺少 CAP_NET_RAW）
- ❌ OpenVZ / LXC 未开启特权模式
- ⚠️ WSL2 需切换为 NAT 网络模式（默认桥接不支持 raw socket）

> 换到 KVM VPS 或物理机即可正常使用。

---


## 鸣谢

- [**cmliu**](https://github.com/cmliu) — 提供 [CF-Workers-CheckProxyIP](https://github.com/cmliu/CF-Workers-CheckProxyIP) 公共 API 接口 (`api.090227.xyz/check`)，用于节点二次验证。
