#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
API 精筛 — 调用 API 验证 CF 节点可用性 (纯原生标准库长连接优化版)
无需安装任何 pip 第三方库，使用 http.client + threading.local 实现 TCP/TLS 连接复用
"""
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import http.client
import json
import ssl
import sys
import threading
import time
import urllib.parse

# 线程局部变量，用于存储每个线程独立的 HTTPS/HTTP 长连接对象
thread_local = threading.local()

def get_connection(host, is_https, timeout=8):
    """获取或初始化当前线程持有的 persistent 连接对象"""
    conn = getattr(thread_local, "conn", None)
    if conn is None:
        if is_https:
            ctx = ssl.create_default_context()
            conn = http.client.HTTPSConnection(host, timeout=timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(host, timeout=timeout)
        thread_local.conn = conn
    return conn

def close_connection():
    """关闭当前线程的连接并置空"""
    conn = getattr(thread_local, "conn", None)
    if conn:
        try:
            conn.close()
        except Exception:
            pass
        thread_local.conn = None

def check_single(line, parsed_api):
    """通过复用 TCP/TLS 连接请求 API 检查单条 IP:PORT"""
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    parts = line.split()
    ip_port = parts[0] if parts else line

    if ":" not in ip_port:
        return None

    host = parsed_api.netloc
    is_https = (parsed_api.scheme == "https")
    path_prefix = parsed_api.path if parsed_api.path else "/check"
    full_path = f"{path_prefix}?proxyip={ip_port}"

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "Accept": "application/json",
        "Origin": "https://090227.xyz",
        "Connection": "keep-alive"  # 显式声明保持长连接
    }

    for attempt in range(2):
        try:
            conn = get_connection(host, is_https)
            conn.request("GET", full_path, headers=headers)
            resp = conn.getresponse()

            # 非 200 状态码，清空缓冲区并重置连接
            if resp.status != 200:
                resp.read()
                close_connection()
                continue

            raw_data = resp.read().decode("utf-8", errors="ignore")
            data = json.loads(raw_data)

            if not data.get("success"):
                return None

            # 解析 exit 节点信息
            pr = data.get("probe_results", {})
            exit_info = (
                pr.get("ipv4", {}).get("exit")
                or pr.get("ipv6", {}).get("exit")
                or {}
            )

            colo = exit_info.get("colo", data.get("colo", ""))
            country = exit_info.get("country", "")
            region = exit_info.get("region", "")
            asn = exit_info.get("asn", data.get("asn", ""))

            ip, port = ip_port.rsplit(":", 1)
            return f"{ip},{port},TRUE,{colo},{country},{region},,,AS{asn}"

        except Exception:
            # 发生网络异常或超时时，彻底关闭旧连接，下次循环重新建连
            close_connection()
            if attempt == 0:
                time.sleep(0.5)
            continue

    return None

def main():
    parser = argparse.ArgumentParser(description="Cloudflare API Verify Tool (Standard Lib Optimized)")
    parser.add_argument("--input", required=True, help="输入 IP 列表文件")
    parser.add_argument("--output", required=True, help="输出结果 CSV 文件")
    parser.add_argument(
        "--api", default="https://cfapi.250887.xyz/check", help="API 接口地址"
    )
    parser.add_argument("--chunk", type=int, default=5000, help="兼容性分块大小")
    parser.add_argument(
        "--concurrent", type=int, default=32, help="线程并发数"
    )
    args = parser.parse_args()

    parsed_api = urllib.parse.urlparse(args.api)

    try:
        with open(args.input, "r", encoding="utf-8", errors="ignore") as f:
            all_lines = [l.strip() for l in f if l.strip() and not l.startswith("#")]
    except Exception as e:
        sys.stderr.write(f"  ❌ 读取输入文件失败: {e}\n")
        sys.exit(1)

    total = len(all_lines)
    if total == 0:
        sys.stderr.write("  ⚠️ 输入列表为空，跳过验证。\n")
        sys.exit(0)

    passed = 0
    done = 0
    start_time = time.time()
    bar_width = 30

    with open(args.output, "w", encoding="utf-8") as out:
        out.write("IP地址,端口,TLS,数据中心,地区,城市,网络延迟,下载速度,ASN\n")

        with ThreadPoolExecutor(max_workers=args.concurrent) as executor:
            future_to_line = {
                executor.submit(check_single, line, parsed_api): line
                for line in all_lines
            }

            for future in as_completed(future_to_line):
                done += 1
                result = future.result()

                if result:
                    out.write(result + "\n")
                    out.flush()
                    passed += 1

                elapsed = time.time() - start_time
                rate = done / elapsed if elapsed > 0 else 0
                eta = (total - done) / rate if rate > 0 else 0
                pct = (done / total) * 100

                filled = int(bar_width * pct / 100)
                bar = "█" * filled + "░" * (bar_width - filled)

                sys.stderr.write(
                    f"\r  [{bar}] {pct:.1f}% ({done}/{total}) | 通过 {passed} | {rate:.1f}/s | ETA {eta/60:.1f}m    "
                )
                sys.stderr.flush()

    total_elapsed = int(time.time() - start_time)
    sys.stderr.write(
        f"\r  [{'█' * bar_width}] 100.0% ({total}/{total}) | 通过 {passed}/{total} | 耗时 {total_elapsed // 60}m{total_elapsed % 60}s{' ' * 20}\n"
    )

if __name__ == "__main__":
    main()
