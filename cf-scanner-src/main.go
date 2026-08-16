package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

var (
	inputFile   = flag.String("i", "", "IP list file (required)")
	outputFile  = flag.String("o", "", "Output file for CF proxy hits (default: cf_hits_<timestamp>.txt)")
	stateFile   = flag.String("state", "scanner.state", "Checkpoint file for resume")
	concurrency = flag.Int("c", 500, "Concurrent connections")
	connectTO   = flag.Duration("connect-timeout", 1500*time.Millisecond, "TCP+TLS connect timeout")
	port        = flag.String("p", "443", "Target port")
	sni         = flag.String("sni", "cloudflare.com", "TLS SNI to send")
)

func isCloudflareProxy(ip string, dialer *net.Dialer, tlsConfig *tls.Config) (bool, string) {
	targetHost, targetPort := ip, *port
	if h, p, err := net.SplitHostPort(ip); err == nil {
		targetHost, targetPort = h, p
	}
	target := net.JoinHostPort(targetHost, targetPort)

	conn, err := tls.DialWithDialer(dialer, "tcp", target, tlsConfig)
	if err != nil {
		return false, target
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	for _, cert := range certs {
		if strings.Contains(cert.Subject.CommonName, "cloudflare.com") {
			return true, target
		}
		for _, name := range cert.DNSNames {
			if strings.Contains(name, "cloudflare.com") {
				return true, target
			}
		}
	}
	return false, target
}

func countLines(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	count := 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			count++
		}
	}
	return count, scanner.Err()
}

func streamLines(ctx context.Context, path string, skip int, out chan<- string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lineNum++
		if lineNum <= skip {
			continue
		}
		out <- line
	}
	return scanner.Err()
}

func main() {
	flag.Parse()
	if *inputFile == "" {
		fmt.Fprintln(os.Stderr, "Usage: cf-scanner -i ips.txt [-o hits.txt] [-c 500]")
		os.Exit(1)
	}

	if *outputFile == "" {
		*outputFile = fmt.Sprintf("cf_hits_%s.txt", time.Now().Format("20060102_150405"))
	}
	fmt.Printf("Output: %s\n", *outputFile)

	fmt.Print("Counting IPs... ")
	total, err := countLines(*inputFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "\nFailed to read %s: %v\n", *inputFile, err)
		os.Exit(1)
	}
	fmt.Printf("%d\n", total)

	// Checkpoint resume
	skip := 0
	if data, err := os.ReadFile(*stateFile); err == nil {
		parts := strings.SplitN(strings.TrimSpace(string(data)), "\t", 2)
		if len(parts) == 2 && parts[0] == *inputFile {
			fmt.Sscanf(parts[1], "%d", &skip)
			if skip > 0 && skip < total {
				fmt.Printf("Resuming from line %d (%.1f%% done)\n", skip, float64(skip)/float64(total)*100)
			} else {
				skip = 0
			}
		} else {
			fmt.Printf("State file is for %q, not %q — starting fresh\n", parts[0], *inputFile)
		}
	}

	// 修复：以 APPEND 追加模式打开，防止续扫时清空历史结果
	out, err := os.OpenFile(*outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open %s: %v\n", *outputFile, err)
		os.Exit(1)
	}
	defer out.Close()

	// 上下文管理与信号捕获 (支持 Ctrl+C 安全退出并保存进度)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	jobs := make(chan string, *concurrency*2)
	results := make(chan string, *concurrency)

	var (
		scanned  atomic.Int64
		hitCount atomic.Int64
		wg       sync.WaitGroup
	)

	// 全局复用 TLS 与 Dialer 结构，显著提升网络效率并降低 GC 压力
	sharedTLSConfig := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         *sni,
	}
	dialer := &net.Dialer{
		Timeout:   *connectTO,
		KeepAlive: -1, // 探测任务，关闭 TCP Keep-Alive
	}

	// 1. 结果异步写入协程 (Single-Writer Pattern)
	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		bufWriter := bufio.NewWriter(out)
		defer bufWriter.Flush()

		for target := range results {
			bufWriter.WriteString(target + "\n")
		}
	}()

	// 2. 扫描 Worker 线程池
	for i := 0; i < *concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
				}

				ok, target := isCloudflareProxy(ip, dialer, sharedTLSConfig)
				scanned.Add(1)
				if ok {
					hitCount.Add(1)
					results <- target
				}
			}
		}()
	}

	// 3. 状态自动持久化与进度显示协程
	startTime := time.Now()
	startSkip := int64(skip)
	done := make(chan struct{})

	saveState := func(currentScanned int64) {
		os.WriteFile(*stateFile, []byte(fmt.Sprintf("%s\t%d", *inputFile, startSkip+currentScanned)), 0644)
	}

	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				n := scanned.Load()
				elapsed := time.Since(startTime)
				rate := float64(n) / elapsed.Seconds()
				remain := int64(total) - startSkip - n
				var eta time.Duration
				if rate > 0 {
					eta = time.Duration(float64(remain)/rate) * time.Second
				}
				pct := float64(startSkip+n) / float64(total) * 100
				fmt.Printf("\r\033[KScanned %d/%d (%.1f%%) | %.0f/s | hits=%d | ETA %s",
					startSkip+n, total, pct, rate, hitCount.Load(), eta.Round(time.Second))

				// 定时更新断点状态
				saveState(n)
			}
		}
	}()

	// 4. 定时 GC 释放大吞吐下的堆内存
	gcDone := make(chan struct{})
	go func() {
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-gcDone:
				return
			case <-ticker.C:
				runtime.GC()
			}
		}
	}()

	// 5. 启动 IP 投递流
	go func() {
		if err := streamLines(ctx, *inputFile, skip, jobs); err != nil && ctx.Err() == nil {
			fmt.Fprintf(os.Stderr, "\nError reading input: %v\n", err)
		}
		close(jobs)
	}()

	// 等待 Workers 完成
	wg.Wait()
	close(results) // 通知写协程刷新磁盘
	<-writerDone

	close(done)
	close(gcDone)

	// 判断是否正常完成还是中途手动中断 (Ctrl+C)
	if ctx.Err() != nil {
		saveState(scanned.Load())
		fmt.Printf("\n\nProcess interrupted! Progress saved to %s (Line %d)\n", *stateFile, startSkip+scanned.Load())
		os.Exit(0)
	}

	// 正常结束，清空断点文件
	elapsed := time.Since(startTime)
	fmt.Printf("\r\033[KDone! %d/%d (100%%) | %s | hits=%d\n",
		total, total, elapsed.Round(time.Second), hitCount.Load())
	fmt.Printf("Results: %s (%d hits)\n", *outputFile, hitCount.Load())
	os.Remove(*stateFile)
}
