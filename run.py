#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cf-ip-scanner — ASN IP 提取、Masscan 扫描与 Cloudflare 节点精筛 (N100 优化版)
用法: python3 run.py AS209242 [AS3214 ...] [-p 80,443] [-s]
"""

import argparse
import json
import os
import re
import socket
import subprocess
import sys
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

BASE = Path(__file__).parent.resolve()
CF_SCANNER = BASE / "cf-scanner"
VERIFY_PY = BASE / "verify.py"
API_URL = "https://cfapi.250887.xyz/check"
HEADERS = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; cf-ip-scanner/3.0)"}

# ── 家用光猫与 N100 优化参数配置 ──
MASSCAN_RATE = 3000      # 限制在 3000 pps，保护家用光猫 NAT 连接表不崩溃/不丢包
CF_SCANNER_CONC = 120    # N100 多核处理能力
API_CONCURRENT = 32      # API 并发精筛
API_CHUNK = 5000         # 16GB 大内存 Chunk 优化
SPEEDTEST_THREADS = 16   # 多线程并发测速


def get_public_ip():
    apis = [
        "https://api.ipify.org",
        "https://api-ipv4.ip.sb/ip",
        "https://ifconfig.me/ip",
    ]
    for url in apis:
        try:
            req = urllib.request.Request(url, headers=HEADERS)
            with urllib.request.urlopen(req, timeout=5) as resp:
                ip = resp.read().decode("utf-8").strip()
                if ip and "." in ip:
                    return ip
        except Exception:
            continue
    return "127.0.0.1"


def get_lan_ip():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(2)
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"


def detect_isp():
    ip = get_public_ip()
    print(f"\n  本机公网 IP: {ip}")
    if ip == "127.0.0.1":
        print("  (无法获取公网 IP，跳过运营商检测)")
        return ip, "", ""
    try:
        url = f"https://ipinfo.io/{ip}/json"
        req = urllib.request.Request(url, headers=HEADERS)
        with urllib.request.urlopen(req, timeout=8) as resp:
            data = json.loads(resp.read())
            country = data.get("country", "")
            org = data.get("org", "")
            city = data.get("city", "")
            isp = org.split(" ", 1)[-1] if (country == "CN" and org) else org
            print(f"  地区: {city}, {country} | 运营商/机构: {isp}")
            return ip, country, isp
    except Exception as e:
        print(f"  (运营商检测跳过: {e})")
    return ip, "", ""


# ── Step 1: 多源抓取 ASN 前缀 (防漏扫) ──
def fetch_prefixes(asns):
    cidrs = set()
    for asn in asns:
        count = 0
        # 源 1: RIPE STAT API
        url_ripe = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}"
        try:
            req = urllib.request.Request(url_ripe, headers=HEADERS)
            with urllib.request.urlopen(req, timeout=12) as resp:
                data = json.loads(resp.read())
                for p in data.get("data", {}).get("prefixes", []):
                    prefix = p.get("prefix", "")
                    if prefix and ":" not in prefix:
                        cidrs.add(prefix)
                        count += 1
        except Exception as e:
            print(f"  ⚠️ AS{asn} RIPE 源获取异常: {e}")

        # 源 2: BGPView 备用源（补充防漏）
        if count == 0:
            url_bgp = f"https://api.bgpview.io/asn/{asn}/prefixes"
            try:
                req = urllib.request.Request(url_bgp, headers=HEADERS)
                with urllib.request.urlopen(req, timeout=12) as resp:
                    data = json.loads(resp.read())
                    for p in data.get("data", {}).get("ipv4_prefixes", []):
                        prefix = p.get("prefix", "")
                        if prefix:
                            cidrs.add(prefix)
                            count += 1
            except Exception:
                pass

        print(f"  AS{asn} → 获取到 {count} 个 IPv4 CIDR")

    cidr_list = sorted(list(cidrs))
    cidr_file = BASE / "cidrs.txt"
    cidr_file.write_text("\n".join(cidr_list))
    print(f"  汇总去重后共 {len(cidr_list)} 个 CIDR")
    return cidr_list


# ── 端口解析 ──
def get_default_ports():
    ports_file = BASE / "ports.txt"
    if not ports_file.exists():
        return "443"
    with open(ports_file) as f:
        ports = [l.strip() for l in f if l.strip() and not l.startswith("#")]
    return ",".join(ports) if ports else "443"


def parse_ports(port_str):
    if not port_str:
        return get_default_ports()
    ports = set()
    for part in port_str.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            if "-" in part:
                a, b = part.split("-", 1)
                pa, pb = int(a), int(b)
                if 1 <= pa <= pb <= 65535:
                    ports.update(str(p) for p in range(pa, pb + 1))
            elif part.isdigit() and 1 <= int(part) <= 65535:
                ports.add(part)
        except ValueError:
            continue
    return ",".join(sorted(ports, key=int)) if ports else get_default_ports()


# ── Step 2: Masscan 扫描 (加安全重试，防丢包) ──
def run_masscan(ports_str):
    result_file = BASE / "masscan_result.txt"
    ip_file = BASE / "cidrs.txt"

    if result_file.exists():
        if os.geteuid() == 0:
            result_file.unlink(missing_ok=True)
        else:
            subprocess.run(["sudo", "rm", "-f", str(result_file)], check=False)

    sudo = [] if os.geteuid() == 0 else ["sudo"]
    cmd = sudo + [
        "masscan",
        "-iL", str(ip_file),
        "-p", ports_str,
        "--rate", str(MASSCAN_RATE),
        "-oL", str(result_file),
        "--retries", "2",      # 增加两次重试，提高准确率
        "--wait", "7"          # 增加等待发包响应时间
    ]

    proc = subprocess.Popen(
        cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True, bufsize=1
    )
    bar_width = 30
    last_pct = -1

    for line in proc.stderr:
        m = re.search(r"(\d+\.?\d*)%\s*done", line)
        if m:
            pct = min(float(m.group(1)), 100)
            if abs(pct - last_pct) >= 0.5:
                filled = int(bar_width * pct / 100)
                bar = "█" * filled + "░" * (bar_width - filled)
                sys.stderr.write(f"\r  [{bar}] {pct:.1f}%")
                sys.stderr.flush()
                last_pct = pct

    proc.wait()
    sys.stderr.write(f"\r  [{'█' * bar_width}] 100.0%\n")
    sys.stderr.flush()

    if os.geteuid() != 0 and result_file.exists():
        subprocess.run(
            ["sudo", "chown", f"{os.getuid()}:{os.getgid()}", str(result_file)], check=False
        )

    total = 0
    tmp_file = result_file.with_suffix(".tmp")
    if result_file.exists():
        with open(result_file) as src, open(tmp_file, "w") as dst:
            for line in src:
                if line.startswith("#") or not line.strip():
                    continue
                parts = line.strip().split()
                if len(parts) >= 4 and parts[0] == "open":
                    dst.write(f"{parts[3]}:{parts[2]}\n")
                    total += 1
        tmp_file.replace(result_file)

    print(f"  开放端口目标总数: {total}")
    return total


# ── Step 3: cf-scanner 识别 ──
def cf_scan():
    new_file = BASE / "masscan_result.txt"
    hits_file = BASE / "cf_hits.txt"

    if not new_file.exists() or new_file.stat().st_size == 0:
        print("  无开放端口，跳过 CF 扫描")
        return 0

    if CF_SCANNER.is_file() and not os.access(CF_SCANNER, os.X_OK):
        CF_SCANNER.chmod(0o755)

    proc = subprocess.Popen(
        [str(CF_SCANNER), "-i", str(new_file), "-o", str(hits_file), "-c", str(CF_SCANNER_CONC)],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1
    )
    bar_width = 30
    last_pct = -1

    for line in proc.stdout:
        m = re.search(r"Scanned\s+\d+/(\d+)\s+\((\d+\.?\d*)%\)", line)
        if m:
            pct = min(float(m.group(2)), 100)
            if abs(pct - last_pct) >= 0.5:
                filled = int(bar_width * pct / 100)
                bar = "█" * filled + "░" * (bar_width - filled)
                sys.stderr.write(f"\r  [{bar}] {pct:.1f}%")
                sys.stderr.flush()
                last_pct = pct

    proc.wait()
    sys.stderr.write(f"\r  [{'█' * bar_width}] 100.0%\n")
    sys.stderr.flush()

    hits = 0
    if hits_file.exists():
        with open(hits_file) as f:
            hits = sum(1 for _ in f)
    print(f"  粗筛发现 CF 节点: {hits}")
    return hits


# ── Step 4: API 精筛 ──
def api_verify():
    hits_file = BASE / "cf_hits.txt"
    verified_file = BASE / "verified.txt"

    if not hits_file.exists() or hits_file.stat().st_size == 0:
        print("  无待精筛节点，跳过")
        return 0

    print(f"  正在请求 API 精筛 (并发数: {API_CONCURRENT})...")
    proc = subprocess.Popen(
        [
            sys.executable, "-u", str(VERIFY_PY),
            "--input", str(hits_file),
            "--output", str(verified_file),
            "--api", API_URL,
            "--chunk", str(API_CHUNK),
            "--concurrent", str(API_CONCURRENT)
        ],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1
    )

    for line in proc.stdout:
        sys.stdout.write("  " + line)
        sys.stdout.flush()

    proc.wait()
    passed = 0
    if verified_file.exists():
        with open(verified_file) as f:
            passed = sum(1 for line in f if line.strip() and not line.startswith("#"))
    print(f"  精筛完成，可用节点: {passed}")
    return passed


# ── 单节点测速任务（多线程） ──
def _test_node(entry):
    parts = entry.split(",")
    if len(parts) < 8:
        return entry, 0, 0.0

    ip, port = parts[0], parts[1]
    latency = 0
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(3)
            t0 = time.time()
            s.connect((ip, int(port)))
            latency = round((time.time() - t0) * 1000)
    except Exception:
        return entry, 0, 0.0

    speed_mbps = 0.0
    if latency > 0:
        try:
            cmd = [
                "curl", "--connect-to", f"speed.cloudflare.com:443:{ip}:{port}",
                "-o", "/dev/null", "-s", "-w", "%{speed_download}",
                "--connect-timeout", "3", "--max-time", "8",
                "https://speed.cloudflare.com/__down?bytes=5242880"
            ]
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            speed_bps = float(r.stdout.strip() or 0)
            speed_mbps = round(speed_bps * 8 / 1_000_000, 2)
        except Exception:
            speed_mbps = 0.0

    parts[6] = str(latency)
    parts[7] = str(speed_mbps)
    return ",".join(parts), latency, speed_mbps


# ── Step 5: N100 多线程并发测速 ──
def speed_test():
    verified_file = BASE / "verified.txt"
    if not verified_file.exists() or verified_file.stat().st_size == 0:
        print("  无节点可供测速")
        return

    lines = []
    with open(verified_file) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                lines.append(line)

    if len(lines) <= 1:
        print("  无有效数据行")
        return

    header = lines[0]
    entries = lines[1:]
    total = len(entries)
    print(f"  节点数: {total} (启动 {SPEEDTEST_THREADS} 线程并发测速)")

    results = []
    completed = 0
    bar_width = 30

    with ThreadPoolExecutor(max_workers=SPEEDTEST_THREADS) as executor:
        future_map = {executor.submit(_test_node, entry): entry for entry in entries}
        for future in as_completed(future_map):
            completed += 1
            try:
                updated_entry, lat, spd = future.result()
                results.append(updated_entry)
            except Exception:
                results.append(future_map[future])
                lat, spd = 0, 0.0

            pct = completed / total * 100
            filled = int(bar_width * pct / 100)
            bar = "█" * filled + "░" * (bar_width - filled)
            sys.stderr.write(f"\r  [{bar}] {pct:.1f}% | 延迟 {lat}ms  {spd}Mbps{' ':12}")
            sys.stderr.flush()

    sys.stderr.write(f"\r  [{'█' * 30}] 100.0% | 测速完成: {total} 个节点{' ':15}\n")

    with open(verified_file, "w") as f:
        f.write(header + "\n")
        for res in results:
            f.write(res + "\n")


# ── Step 6: 导出 CSV 与 HTTP 下载 ──
def output_csv(asns):
    verified_file = BASE / "verified.txt"
    if not verified_file.exists() or verified_file.stat().st_size == 0:
        print("  无有效结果导出")
        return

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    asn_tag = "_".join(asns)
    output = BASE / f"output_{asn_tag}_{ts}.csv"

    valid_lines = []
    with open(verified_file) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and not line.startswith("IP地址") and line.count(",") >= 7:
                valid_lines.append(line)

    with open(output, "w") as f:
        f.write("IP地址,端口,TLS,数据中心,地区,城市,网络延迟,下载速度,ASN\n")
        for line in valid_lines:
            f.write(line + "\n")

    print(f"\n  扫描完成！写入结果: {len(valid_lines)} 条 → {output.name}")

    lan_ip = get_lan_ip()
    port = 8899

    def _port_free(p):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            return sock.connect_ex(("127.0.0.1", p)) != 0

    while not _port_free(port) and port < 9000:
        port += 1

    if port >= 9000:
        print(f"  📄 结果已保存至文件: {output}")
        return

    http_server = None
    try:
        print(f"\n  📥 下载链接 (按回车关闭):")
        print(f"  http://{lan_ip}:{port}/{output.name}  (局域网)")
        pub_ip = get_public_ip()
        if pub_ip not in ("127.0.0.1", lan_ip):
            print(f"  http://{pub_ip}:{port}/{output.name}  (公网)")
        print()

        http_server = subprocess.Popen(
            [sys.executable, "-m", "http.server", str(port), "--directory", str(BASE)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        input()
    except (EOFError, KeyboardInterrupt):
        pass
    finally:
        if http_server and http_server.poll() is None:
            http_server.terminate()
            http_server.wait()


# ── Main ──
def main():
    parser = argparse.ArgumentParser(description="Cloudflare IP Scanner - N100 优化版")
    parser.add_argument("asns", nargs="*", help="ASN 编号，如 AS209242")
    parser.add_argument("-p", "--ports", type=str, default="", help="端口 (例: 443 或 80,443)")
    parser.add_argument("-s", "--speedtest", action="store_true", help="自动启动测速")

    args = parser.parse_args()

    raw_asns = args.asns
    if not raw_asns:
        try:
            user_input = input("  输入 ASN 编号 (多个用逗号分隔): ").strip()
            raw_asns = [a.strip() for a in user_input.replace("，", ",").split(",") if a.strip()]
        except (EOFError, KeyboardInterrupt):
            sys.exit(0)

    asns = [a.upper().replace("AS", "") for a in raw_asns if a.upper().replace("AS", "").isdigit()]

    if not asns:
        print("  ❌ 未传入有效的 ASN 编号！")
        sys.exit(1)

    print(f"\n  目标 ASN: {', '.join(f'AS{a}' for a in asns)}")
    detect_isp()

    scan_ports = parse_ports(args.ports)
    print(f"  扫描端口: {scan_ports}")
    print(f"  运行参数: Masscan速率={MASSCAN_RATE}pps (已限速保护光猫) | API精筛并发={API_CONCURRENT} | 测速线程={SPEEDTEST_THREADS}")

    do_speedtest = args.speedtest
    if not do_speedtest and not sys.argv[1:]:
        try:
            choice = input("\n  是否启动并发测速？(y/N): ").strip().lower()
            do_speedtest = choice == "y"
        except (EOFError, KeyboardInterrupt):
            do_speedtest = False

    try:
        print("\n  [1/5 提取 ASN CIDR 前缀]")
        fetch_prefixes(asns)

        print("\n  [2/5 Masscan 端口扫描]")
        run_masscan(scan_ports)

        print("\n  [3/5 cf-scanner 节点识别]")
        cf_scan()

        print("\n  [4/5 API 精筛节点]")
        api_verify()

        if do_speedtest:
            print("\n  [5/5 并行测速]")
            speed_test()
        else:
            print("\n  [跳过测速]")

        output_csv(asns)
    except Exception as e:
        print(f"\n  ❌ 执行失败: {e}")
        sys.exit(1)

    print("\n✓ 运行完成\n")


if __name__ == "__main__":
    main()
