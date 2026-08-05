#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
API 精筛 — 调用 API 验证 CF 节点可用性
流式并发，支持实时进度条显示
"""
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import sys
import time
import urllib.request


def check_single(line, api_url):
    """通过 API 检查单条 IP:PORT，返回符合 cfnb 格式的字符串或 None"""
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    parts = line.split()
    ip_port = parts[0] if parts else line

    # 简单的格式校验
    if ":" not in ip_port:
        return None

    url = f"{api_url}?proxyip={ip_port}"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "Accept": "application/json",
        "Origin": "https://090227.xyz",
    }

    # 增加 1 次网络抖动重试
    for attempt in range(2):
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=8) as resp:
                data = json.loads(resp.read().decode("utf-8", errors="ignore"))
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
                # cfnb 格式: IP地址,端口,TLS,数据中心,地区,城市,网络延迟,下载速度,ASN
                return f"{ip},{port},TRUE,{colo},{country},{region},,,AS{asn}"
        except Exception:
            if attempt == 0:
                time.sleep(0.5)  # 首次失败稍作等待再重试
            continue

    return None


def main():
    parser = argparse.ArgumentParser(description="Cloudflare API Verify Tool")
    parser.add_argument("--input", required=True, help="输入 IP 列表文件")
    parser.add_argument("--output", required=True, help="输出结果 CSV 文件")
    parser.add_argument(
        "--api", default="https://api.090227.xyz/check", help="API 接口地址"
    )
    parser.add_argument(
        "--concurrent", type=int, default=32, help="线程并发数"
    )
    args = parser.parse_args()

    # 读取并去重/过滤空行
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
            # 提交所有任务
            future_to_line = {
                executor.submit(check_single, line, args.api): line
                for line in all_lines
            }

            # 逐个接收完成结果，实现真正的实时进度打印
            for future in as_completed(future_to_line):
                done += 1
                result = future.result()

                if result:
                    out.write(result + "\n")
                    out.flush()  # 实时刷盘，防止中途断电/中断丢失数据
                    passed += 1

                # 计算并刷新实时进度条
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
