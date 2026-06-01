// perftest - fscan 可扩展性测试工具
// 测量不同线程数下的扫描性能，生成 CSV 数据用于绘图
package main

import (
	"encoding/csv"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type Result struct {
	Threads   int
	Duration  float64 // 秒
	PortsRate float64 // ports/sec
	FailRate  float64 // 失败率%
}

func main() {
	target := flag.String("target", "", "scan target, e.g. 192.168.1.0/24")
	ports := flag.String("ports", "22,80,443,3389,8080", "port list")
	threads := flag.String("threads", "100,200,400,600,800,1000", "comma-separated thread counts")
	repeat := flag.Int("repeat", 3, "repeat count for each thread count")
	output := flag.String("o", "perf_results.csv", "output CSV file")
	flag.Parse()

	if *target == "" {
		fmt.Println("Usage: perftest -target 192.168.1.0/24 [-ports 22,80,443] [-threads 100,200,400]")
		os.Exit(1)
	}

	threadList := parseIntList(*threads)
	results := []Result{}

	fmt.Printf("=== fscan scalability test ===\n")
	fmt.Printf("Target: %s\n", *target)
	fmt.Printf("Ports: %s\n", *ports)
	fmt.Printf("Threads: %v\n", threadList)
	fmt.Printf("Repeats: %d\n\n", *repeat)

	for _, t := range threadList {
		var totalDuration float64
		var totalRate float64

		fmt.Printf("[threads=%d] ", t)
		for i := 0; i < *repeat; i++ {
			fmt.Printf(".")
			duration, rate := runFscan(*target, *ports, t)
			totalDuration += duration
			totalRate += rate
		}

		avgDuration := totalDuration / float64(*repeat)
		avgRate := totalRate / float64(*repeat)

		results = append(results, Result{
			Threads:   t,
			Duration:  avgDuration,
			PortsRate: avgRate,
		})
		fmt.Printf(" average: %.2fs, %.1f ports/sec\n", avgDuration, avgRate)
	}

	writeCSV(*output, results)
	fmt.Printf("\nResults saved to: %s\n", *output)
	printPlotCommand(*output)
}

func runFscan(target, ports string, threads int) (duration float64, rate float64) {
	args := []string{
		"-h", target,
		"-p", ports,
		"-t", strconv.Itoa(threads),
		"-np", "-nopoc", // 禁用ping和poc，只测端口扫描
		"-o", "/dev/null",
	}

	start := time.Now()
	cmd := exec.Command("./fscan", args...)
	output, _ := cmd.CombinedOutput()
	duration = time.Since(start).Seconds()

	// 从输出解析扫描的端口数
	portCount := extractPortCount(string(output), target, ports)
	if duration > 0 {
		rate = float64(portCount) / duration
	}
	return
}

func extractPortCount(output, target, ports string) int {
	// Try to parse either Chinese or English fscan completion output.
	re := regexp.MustCompile(`(?:\x{626b}\x{63cf}\x{5b8c}\x{6210}|Scan Completed).*?(\d+).*?(?:\x{7aef}\x{53e3}|ports?)`)
	if matches := re.FindStringSubmatch(output); len(matches) > 1 {
		count, _ := strconv.Atoi(matches[1])
		return count
	}

	// 估算: IP数 × 端口数
	ipCount := estimateIPCount(target)
	portCount := len(strings.Split(ports, ","))
	return ipCount * portCount
}

func estimateIPCount(target string) int {
	if strings.Contains(target, "/24") {
		return 254
	}
	if strings.Contains(target, "/16") {
		return 65534
	}
	return 1
}

func parseIntList(s string) []int {
	parts := strings.Split(s, ",")
	result := make([]int, 0, len(parts))
	for _, p := range parts {
		if n, err := strconv.Atoi(strings.TrimSpace(p)); err == nil {
			result = append(result, n)
		}
	}
	return result
}

func writeCSV(filename string, results []Result) {
	f, err := os.Create(filename)
	if err != nil {
		fmt.Printf("Failed to create file: %v\n", err)
		return
	}
	defer func() { _ = f.Close() }()

	w := csv.NewWriter(f)
	_ = w.Write([]string{"threads", "duration_sec", "ports_per_sec"})
	for _, r := range results {
		_ = w.Write([]string{
			strconv.Itoa(r.Threads),
			fmt.Sprintf("%.3f", r.Duration),
			fmt.Sprintf("%.1f", r.PortsRate),
		})
	}
	w.Flush()
}

func printPlotCommand(csvFile string) {
	fmt.Println("\n=== Plot commands ===")
	fmt.Println("\n# gnuplot:")
	fmt.Printf(`gnuplot -e "
set terminal png size 800,600;
set output 'scalability.png';
set title 'fscan Scalability';
set xlabel 'Threads';
set ylabel 'Ports/sec';
set grid;
plot '%s' using 1:3 with linespoints title 'Throughput'
"
`, csvFile)

	fmt.Println("\n# Python matplotlib:")
	fmt.Println(`python -c "
import pandas as pd
import matplotlib.pyplot as plt
df = pd.read_csv('` + csvFile + `')
plt.figure(figsize=(10,6))
plt.plot(df['threads'], df['ports_per_sec'], 'o-', linewidth=2, markersize=8)
plt.xlabel('Threads')
plt.ylabel('Ports/sec')
plt.title('fscan Scalability Chart')
plt.grid(True)
plt.savefig('scalability.png', dpi=150)
print('已保存: scalability.png')
"`)
}
