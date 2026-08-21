#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cf-ip-scanner — 从 ASN 拉取 IP，masscan 扫描，检测 Cloudflare 反代节点
用法: python3 run.py AS209242 [AS3214 ...]
"""
import sys, os, subprocess, json, urllib.request, multiprocessing, socket, time, re, threading, ipaddress, random
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# ── 获取公网 IP (仅在最后提供下载链接时使用，避免启动卡顿) ──
def get_public_ip():
    apis = [
        ("https://api.ipify.org", 5),
        ("https://api-ipv4.ip.sb/ip", 5),
        ("https://ifconfig.me/ip", 5),
        ("https://icanhazip.com", 5),
    ]
    for url, timeout in apis:
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            return urllib.request.urlopen(req, timeout=timeout).read().decode("utf-8").strip()
        except Exception:
            continue

    dns_queries = [
        (["dig", "+short", "myip.opendns.com", "@resolver1.opendns.com"], 5),
        (["dig", "TXT", "+short", "o-o.myaddr.l.google.com", "@ns1.google.com"], 5),
        (["dig", "+short", "whoami.akamai.net", "@ns1-1.akamaitech.net"], 5),
    ]
    for cmd, timeout in dns_queries:
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            out = r.stdout.strip().strip('"')
            if out and "." in out and out.count(".") == 3:
                parts = out.split(".")
                if all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
                    return out
        except Exception:
            continue
    return "127.0.0.1"

# ── 获取局域网 IP ──
def get_lan_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        pass
    return "127.0.0.1"

# ── 🌟 家用光猫安全核心配置 🌟 ──

MASSCAN_RATE = 1000
CF_SCANNER_CONC = 40
API_CONCURRENT = 15
API_CHUNK = 300

BASE       = Path(__file__).parent.resolve()
CF_SCANNER = BASE / "cf-scanner"
VERIFY_PY  = BASE / "verify.py"
API_URL    = "https://api.250887.xyz/check"
TG_CONFIG_FILE = BASE / "tg_config.json"
TG_API_BASE    = "https://tg.250887.xyz"

if CF_SCANNER.is_file():
    CF_SCANNER.chmod(0o755)

# ── 安全输入辅助函数 ──
def safe_input(prompt_text):
    try:
        return input(prompt_text).strip()
    except (EOFError, KeyboardInterrupt):
        try:
            with open("/dev/tty") as tty:
                os.dup2(tty.fileno(), 0)
            return input(prompt_text).strip()
        except Exception:
            return ""

# ── Telegram Bot 配置与发送模块 ──
def load_tg_config():
    if TG_CONFIG_FILE.exists():
        try:
            with open(TG_CONFIG_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {"enabled": False, "token": "", "chat_id": ""}

def check_or_init_tg_config():
    """首次运行时提示绑定 TG Bot，按回车可跳过"""
    if not TG_CONFIG_FILE.exists():
        print("  [Telegram Bot 设置]")
        choice = safe_input("  首次运行，是否绑定 Telegram Bot？(y/N，按回车跳过不绑定): ").lower()
        if choice == "y":
            token = safe_input("  请输入 TG Bot Token: ")
            chat_id = safe_input("  请输入 TG Chat ID: ")
            if token and chat_id:
                cfg = {"enabled": True, "token": token, "chat_id": chat_id}
                try:
                    with open(TG_CONFIG_FILE, "w", encoding="utf-8") as f:
                        json.dump(cfg, f, ensure_ascii=False, indent=2)
                    print("  ✅ Telegram Bot 绑定成功！\n")
                    return cfg
                except Exception as e:
                    print(f"  ❌ 保存 TG 配置失败: {e}\n")
            else:
                print("  ⚠️ 输入不完整，已跳过绑定。\n")
        
        cfg = {"enabled": False, "token": "", "chat_id": ""}
        try:
            with open(TG_CONFIG_FILE, "w", encoding="utf-8") as f:
                json.dump(cfg, f, ensure_ascii=False, indent=2)
        except Exception:
            pass
        return cfg
    else:
        return load_tg_config()

def send_tg_document(file_path, caption=""):
    """利用 TG Bot 发送文件到指定会话 ID"""
    cfg = load_tg_config()
    token = cfg.get("token")
    chat_id = cfg.get("chat_id")

    if not token or not chat_id:
        print("  尚未绑定 TG Bot，请输入配置:")
        token = safe_input("  请输入 TG Bot Token: ")
        chat_id = safe_input("  请输入 TG Chat ID: ")
        if token and chat_id:
            cfg = {"enabled": True, "token": token, "chat_id": chat_id}
            try:
                with open(TG_CONFIG_FILE, "w", encoding="utf-8") as f:
                    json.dump(cfg, f, ensure_ascii=False, indent=2)
            except Exception:
                pass
        else:
            print("  ❌ 未提供完整的 TG 配置，取消发送。")
            return False

    url = f"{TG_API_BASE}/bot{token}/sendDocument"
    file_path = Path(file_path)
    if not file_path.exists():
        print(f"  ❌ 文件不存在，无法发送: {file_path}")
        return False

    print(f"  正在发送 [{file_path.name}] 至 Telegram...")

    # 优先方法 1: 使用系统 curl 命令行发送
    try:
        cmd = [
            "curl", "-s", "-X", "POST", url,
            "-F", f"chat_id={chat_id}",
            "-F", f"document=@{file_path}"
        ]
        if caption:
            cmd.extend(["-F", f"caption={caption}"])
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if r.returncode == 0 and ("\"ok\":true" in r.stdout.lower() or "\"ok\": true" in r.stdout.lower()):
            print("  ✅ 成功发送文件至 Telegram！")
            return True
    except Exception:
        pass

    # 备用方法 2: urllib multipart 原生实现
    try:
        boundary = "----WebKitFormBoundary" + "".join(random.choices("0123456789abcdef", k=16))
        body = []

        body.append(f"--{boundary}\r\nContent-Disposition: form-data; name=\"chat_id\"\r\n\r\n{chat_id}\r\n".encode("utf-8"))

        if caption:
            body.append(f"--{boundary}\r\nContent-Disposition: form-data; name=\"caption\"\r\n\r\n{caption}\r\n".encode("utf-8"))

        filename = file_path.name
        with open(file_path, "rb") as f:
            file_bytes = f.read()

        header = (f"--{boundary}\r\n"
                  f"Content-Disposition: form-data; name=\"document\"; filename=\"{filename}\"\r\n"
                  f"Content-Type: application/octet-stream\r\n\r\n").encode("utf-8")

        body.append(header + file_bytes + b"\r\n")
        body.append(f"--{boundary}--\r\n".encode("utf-8"))

        payload = b"".join(body)
        req = urllib.request.Request(
            url,
            data=payload,
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}"}
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            res_text = resp.read().decode("utf-8")
            if "\"ok\":true" in res_text.lower() or "\"ok\": true" in res_text.lower():
                print("  ✅ 成功发送文件至 Telegram！")
                return True
            else:
                print(f"  ❌ 发送失败，Telegram 返回: {res_text}")
                return False
    except Exception as e:
        print(f"  ❌ 发送至 Telegram 异常: {e}")
        return False

# ── Step 1: ASN → CIDR ──
def fetch_prefixes(asns):
    raw_cidrs = []
    API_DOMAIN = "https://as.250887.xyz"

    for asn in asns:
        url = f"{API_DOMAIN}/AS{asn}"
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        success = False
        
        for attempt in range(3):
            try:
                with urllib.request.urlopen(req, timeout=10) as resp:
                    text = resp.read().decode('utf-8').strip()
                    lines = [line.strip() for line in text.splitlines() if line.strip() and ":" not in line]
                    raw_cidrs.extend(lines)
                    print(f"  AS{asn} → 获取到 {len(lines)} 个 IPv4 CIDR")
                    success = True
                    break
            except Exception as e:
                print(f"  AS{asn} → 尝试 {attempt+1}/3 失败: {e}")
                time.sleep(2)
        
        if not success:
            print(f"  ❌ AS{asn} → 获取失败，跳过该 ASN。")

    if not raw_cidrs:
        raise ValueError("拉取到的 CIDR 数量为 0，可能是网络无法连接 API 或输入了无效的 ASN 编号。程序已安全停止。")

    net_objs = []
    for c in raw_cidrs:
        try:
            net_objs.append(ipaddress.IPv4Network(c, strict=False))
        except ValueError:
            pass
    
    merged_nets = list(ipaddress.collapse_addresses(net_objs))
    cidrs = [str(net) for net in merged_nets]

    cidr_file = BASE / "cidrs.txt"
    cidr_file.write_text("\n".join(cidrs))
    print(f"  共获取 {len(raw_cidrs)} 个 CIDR，合并去重后实际扫描 {len(cidrs)} 个网段")
    return cidrs

# ── 端口解析 ──
with open(BASE / "ports.txt") as f:
    _default_ports = [l.strip() for l in f if l.strip() and not l.startswith("#")]
DEFAULT_PORTS = ",".join(_default_ports)

def parse_ports(port_str):
    ports = set()
    for part in port_str.split(','):
        part = part.strip()
        if not part:
            continue
        try:
            if '-' in part:
                a, b = part.split('-', 1)
                pa, pb = int(a), int(b)
                if pa < 1 or pb > 65535 or pa > pb:
                    continue
                ports.update(str(p) for p in range(pa, pb + 1))
            elif part.isdigit():
                p = int(part)
                if 1 <= p <= 65535:
                    ports.add(part)
        except ValueError:
            continue
    return ",".join(sorted(ports, key=int)) if ports else ""

def run_masscan(ports_str=None):
    ports = ports_str if ports_str else DEFAULT_PORTS
    if not ports or ports == ",":
        ports = DEFAULT_PORTS
    result_file = BASE / "masscan_result.txt"
    ip_file = BASE / "cidrs.txt"

    if not ip_file.exists() or ip_file.stat().st_size == 0:
         raise ValueError("cidrs.txt 文件为空，无法启动 masscan 扫描。")

    if result_file.exists():
        if os.geteuid() == 0:
            result_file.unlink()
        else:
            subprocess.run(["sudo", "rm", "-f", str(result_file)], check=False)

    sudo = [] if os.geteuid() == 0 else ["sudo"]
    cmd = sudo + [
        "masscan", "-iL", str(ip_file),
        "-p", ports,
        "--rate", str(MASSCAN_RATE),
        "-oL", str(result_file),
        "--wait", "5"
    ]
    
    print(f"  [运行 masscan] 速率: {MASSCAN_RATE} pps, 端口: {ports}")
    
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                            text=True, bufsize=1)
    bar_width = 30
    last_pct = -1
    stderr_lines = []
    for line in proc.stderr:
        stderr_lines.append(line)
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
    if proc.returncode == 0:
        sys.stderr.write(f"\r  [{'█' * bar_width}] 100.0%\n")
        sys.stderr.flush()
    else:
        sys.stderr.write("\n")
        sys.stderr.flush()
        stderr_text = "".join(stderr_lines)
        if "permission denied" in stderr_text.lower() or "init: failed" in stderr_text.lower():
            print("  ❌ masscan 需要 raw socket 权限，NAT 容器/部分 VPS 不支持")
            print("  → 请换到 KVM VPS 或物理机运行")
        raise subprocess.CalledProcessError(proc.returncode, cmd)

    if os.geteuid() != 0:
        uid = os.getuid()
        gid = os.getgid()
        subprocess.run(["sudo", "chown", f"{uid}:{gid}", str(result_file)], check=False)

    total = 0
    parsed_lines = []
    tmp_file = result_file.with_suffix(".tmp")
    
    with open(result_file) as src:
        for line in src:
            if line.startswith("#") or not line.strip():
                continue
            parts = line.strip().split()
            if len(parts) >= 4 and parts[0] == "open":
                parsed_lines.append(f"{parts[3]}:{parts[2]}\n")
    
    random.shuffle(parsed_lines)

    with open(tmp_file, "w") as dst:
        dst.writelines(parsed_lines)
        
    total = len(parsed_lines)
    tmp_file.replace(result_file)
    print(f"  开放端口: {total} (已完成乱序打乱)")
    return total

# ── Step 4: cf-scanner 粗筛 ──
def cf_scan():
    new_file = BASE / "masscan_result.txt"
    hits_file = BASE / "cf_hits.txt"

    # 【修复BUG】：清理上一次历史残留文件，防止追加写入
    if hits_file.exists():
        try:
            hits_file.unlink()
        except:
            pass

    if not new_file.exists() or new_file.stat().st_size == 0:
        print("  无开放端口，跳过")
        return 0

    if not os.access(CF_SCANNER, os.X_OK):
        os.chmod(CF_SCANNER, 0o755)

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
    if proc.returncode == 0:
        sys.stderr.write(f"\r  [{'█' * bar_width}] 100.0%\n")
        sys.stderr.flush()
    else:
        sys.stderr.write("\n")
        sys.stderr.flush()
        raise subprocess.CalledProcessError(proc.returncode, proc.args)

    hits = sum(1 for _ in open(hits_file)) if hits_file.exists() else 0
    print(f"  CF 节点: {hits}")
    return hits

# ── Step 5: API 精筛 ──
def api_verify():
    hits_file = BASE / "cf_hits.txt"
    verified_file = BASE / "verified.txt"

    # 【修复BUG】：清理上一次历史残留文件，防止追加写入
    if verified_file.exists():
        try:
            verified_file.unlink()
        except:
            pass

    if not hits_file.exists() or hits_file.stat().st_size == 0:
        print("  无 CF 节点，跳过")
        return 0

    print(f"  正在请求 API 精筛 (并发: {API_CONCURRENT}, 块大小: {API_CHUNK})...")
    
    proc = subprocess.Popen([
        "python3", "-u", str(VERIFY_PY),
        "--input", str(hits_file),
        "--output", str(verified_file),
        "--api", API_URL,
        "--chunk", str(API_CHUNK),
        "--concurrent", str(API_CONCURRENT)
    ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)

    bar_width = 30
    passed_count = 0

    for line in proc.stdout:
        line = line.strip()
        if not line:
            continue
        
        m_pct = re.search(r"(\d+\.?\d*)%", line)
        m_pass = re.search(r"(?:通过|passed)\s*(\d+)", line, re.IGNORECASE)
        m_count = re.search(r"\((\d+)/(\d+)\)", line)

        if m_pct:
            pct = min(float(m_pct.group(1)), 100.0)
            filled = int(bar_width * pct / 100)
            bar = "█" * filled + "░" * (bar_width - filled)

            if m_pass:
                passed_count = int(m_pass.group(1))

            if m_count:
                done, total = m_count.group(1), m_count.group(2)
                sys.stderr.write(f"\r  [{bar}] {pct:.1f}% ({done}/{total}) | 通过: {passed_count}{'':15}")
            else:
                sys.stderr.write(f"\r  [{bar}] {pct:.1f}% | 通过: {passed_count}{'':15}")
            sys.stderr.flush()

    proc.wait()
    sys.stderr.write(f"\r  [{'█' * bar_width}] 100.0% | 精筛完成{'':20}\n")
    sys.stderr.flush()

    passed = sum(1 for _ in open(verified_file)) if verified_file.exists() else 0
    print(f"  精筛完成，通过节点: {passed}")
    return passed

# ── Step 6: 多线程测速 ──
def speed_test():
    verified_file = BASE / "verified.txt"
    if not verified_file.exists() or verified_file.stat().st_size == 0:
        print("  无节点，跳过")
        return

    lines = []
    with open(verified_file) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("IP地址"):
                continue
            lines.append(line)

    total = len(lines)
    if total == 0:
        print("  无节点，跳过")
        return

    SPEED_TEST_CONC = 8
    print(f"  节点数: {total} (启动多线程并发测速中, 并发:{SPEED_TEST_CONC})")

    results = []
    tested = 0
    lock = threading.Lock()

    def _test_single(entry):
        parts = entry.split(",")
        if len(parts) < 7:
            return None
        ip, port = parts[0], parts[1]

        latency = 0
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            t0 = time.time()
            s.connect((ip, int(port)))
            latency = round((time.time() - t0) * 1000)
            s.close()
        except:
            pass

        speed_mbps = 0
        if latency > 0:
            try:
                r = subprocess.run([
                    "curl", "--connect-to", f"speed.cloudflare.com:443:{ip}:{port}",
                    "-o", "/dev/null", "-s", "-w", "%{speed_download}",
                    "--connect-timeout", "5", "--max-time", "20",
                    "https://speed.cloudflare.com/__down?bytes=10485760"
                ], capture_output=True, text=True, timeout=25)
                speed_bps = float(r.stdout.strip() or 0)
                speed_mbps = round(speed_bps * 8 / 1000000, 2)
            except:
                pass

        if len(parts) == 7:
            return f"{parts[0]},{parts[1]},{parts[2]},{parts[3]},{parts[4]},{parts[5]},{latency},{speed_mbps},{parts[6]}"
        elif len(parts) >= 9:
            parts[6] = str(latency)
            parts[7] = str(speed_mbps)
            return ",".join(parts)
        return None

    with ThreadPoolExecutor(max_workers=SPEED_TEST_CONC) as executor:
        futures = {executor.submit(_test_single, line): line for line in lines}
        for future in as_completed(futures):
            res = future.result()
            if res:
                results.append(res)
            
            with lock:
                tested += 1
                pct = tested / total * 100
                bar_width = 30
                filled = int(bar_width * pct / 100)
                bar = "█" * filled + "░" * (bar_width - filled)
                sys.stderr.write(f"\r  [{bar}] {pct:.1f}% | 进度: {tested}/{total} {'':15}")
                sys.stderr.flush()

    sys.stderr.write(f"\r  [{'█' * 30}] 100.0% | 测速完成: {total} 个节点{'':15}\n")
    
    with open(verified_file, "w") as f:
        f.write("IP地址,端口,TLS,数据中心,地区,城市,网络延迟,下载速度,ASN\n")
        f.write("\n".join(results) + "\n")

# ── 输出 + 下载链接 ──
def output_csv(asns):
    verified_file = BASE / "verified.txt"
    if not verified_file.exists() or verified_file.stat().st_size == 0:
        print("  无结果")
        return None

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    asn_tag = "_".join(asns)
    output = BASE / f"output_{asn_tag}_{ts}.csv"

    lines = []
    with open(verified_file) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("IP地址"):
                continue
            
            parts = line.split(",")
            if len(parts) == 7:
                line = f"{parts[0]},{parts[1]},{parts[2]},{parts[3]},{parts[4]},{parts[5]},0,0,{parts[6]}"
            
            if line.count(",") >= 8:
                lines.append(line)

    with open(output, "w") as f:
        f.write("IP地址,端口,TLS,数据中心,地区,城市,网络延迟,下载速度,ASN\n")
        for line in lines:
            f.write(line + "\n")

    print(f"\n  结果: {len(lines)} 条 → {output.name}")

    lan_ip = get_lan_ip()
    port = 8899

    def _port_free(p):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.settimeout(1)
            return sock.connect_ex(('127.0.0.1', p)) != 0
        finally:
            sock.close()

    def _kill_port(p):
        import signal
        try:
            out = subprocess.run(["ss", "-tlnp", f"sport = :{p}"],
                                 capture_output=True, text=True, timeout=5)
            for line in out.stdout.split("\n"):
                if f":{p}" in line and "users:" in line:
                    m = re.search(r"pid=(\d+)", line)
                    if m:
                        os.kill(int(m.group(1)), signal.SIGTERM)
                        time.sleep(0.5)
                        return True
        except:
            pass
        return False

    if not _port_free(port):
        print(f"  端口 {port} 被占用，尝试释放...")
        if _kill_port(port) and _port_free(port):
            print(f"  已释放端口 {port}")
        else:
            while not _port_free(port) and port < 9900:
                port += 1
            if port >= 9900:
                print(f"\n  ⚠️  找不到可用端口，跳过下载服务")
                print(f"  📄 结果文件: {output}")
                return output

    _http_server = None
    try:
        print(f"\n  📥 下载链接 (按回车关闭):")
        print(f"  http://{lan_ip}:{port}/{output.name}  (本机)")
        public_ip = get_public_ip()
        if public_ip != "127.0.0.1" and public_ip != lan_ip:
            print(f"  http://{public_ip}:{port}/{output.name}  (公网)")
        print()
        _http_server = subprocess.Popen(
            ["python3", "-m", "http.server", str(port), "--directory", str(BASE)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        input()
    except (EOFError, KeyboardInterrupt):
        pass
    finally:
        if _http_server and _http_server.poll() is None:
            _http_server.terminate()
            _http_server.wait()

    return output

# ── Main ──
if __name__ == "__main__":
    # 首次运行时提示绑定 TG Bot
    check_or_init_tg_config()

    if len(sys.argv) < 2:
        raw = safe_input("  输入 ASN 编号 (多个用逗号分隔): ")
        if not raw:
            print("用法: python3 run.py AS209242")
            print("  ssh 断线不杀: screen -S scan → python3 run.py AS209242 → Ctrl+A D")
            sys.exit(1)
        asns = [a.strip().replace("AS", "").replace("as", "") for a in raw.replace("，", ",").split(",") if a.strip()]
    else:
        args = sys.argv[1:]
        i = 0
        asn_args = []
        while i < len(args):
            if args[i] == "-p":
                i += 2
            else:
                asn_args.append(args[i])
                i += 1
        raw = ",".join(asn_args)
        asns = [a.strip().replace("AS", "").replace("as", "") for a in raw.replace("，", ",").split(",") if a.strip()]
        if not asns:
            print("用法: python3 run.py AS209242 或 python3 run.py AS209242 -p 8443")
            print("  ssh 断线不杀: screen -S scan → python3 run.py AS209242 → Ctrl+A D")
            sys.exit(1)
    
    pps_input = safe_input("  设置 masscan 扫描速率 PPS (回车默认 1000): ")
    if pps_input:
        if pps_input.isdigit() and int(pps_input) > 0:
            MASSCAN_RATE = int(pps_input)
        else:
            print("  ⚠️ 输入无效，使用默认速率 1000 pps")

    print(f"\n  配置: masscan={MASSCAN_RATE}pps, cf-scanner={CF_SCANNER_CONC}c, API={API_CONCURRENT}c(块{API_CHUNK})")
    print(f"  ASN: {', '.join(f'AS{a}' for a in asns)}\n")

    scan_ports = DEFAULT_PORTS
    if len(sys.argv) < 2:
        print(f"  默认端口: {DEFAULT_PORTS}")
        port_input = safe_input("  回车使用默认，或输入自定义端口 (如 80 或 1-1000 或 80,443,8000-9000): ")
        if port_input:
            parsed = parse_ports(port_input)
            if parsed:
                scan_ports = parsed
                print(f"  扫描端口: {scan_ports}")
    else:
        for i, arg in enumerate(sys.argv[1:], 1):
            if arg == "-p" and i < len(sys.argv) - 1:
                scan_ports = parse_ports(sys.argv[i+1])
                print(f"  自定义端口: {scan_ports}")
                break

    steps = [
        ("1/6 ASN→CIDR", lambda: fetch_prefixes(asns)),
        ("2/6 masscan",   lambda: run_masscan(scan_ports)),
        ("3/6 cf-scanner", cf_scan),
        ("4/6 API精筛",   api_verify),
    ]

    choice = safe_input("\n  是否测速？(y/n，默认跳过): ").lower()
    if choice == "y":
        steps.append(("6/6 测速", speed_test))
    else:
        print("  跳过测速\n")

    for label, fn in steps:
        print(f"\n  [{label}]")
        try:
            fn()
        except Exception as e:
            print(f"  ❌ 任务提前终止: {e}")
            sys.exit(1)

    # 导出结果文件
    result_csv_path = output_csv(asns)

    # 运行结束后提示是否发送至 Telegram (默认不发送，输入 y 发送)
    if result_csv_path and Path(result_csv_path).exists():
        tg_send_choice = safe_input("\n  是否发送结果至 Telegram？(y/N，默认不发送): ").lower()
        if tg_send_choice == "y":
            send_tg_document(result_csv_path, caption=f"Cloudflare 节点扫描结果: {Path(result_csv_path).name}")

    print()
    print("  ───")
    print("  SSH 断线不杀: screen -S scan → python3 run.py AS209242 → Ctrl+A D")
    print("  恢复: screen -r scan")
    print("\n✓ 完成\n")
