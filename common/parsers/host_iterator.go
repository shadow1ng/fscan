package parsers

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/shadow1ng/fscan/common/i18n"
)

const DefaultHostBatchSize = 4096

type HostIterator struct {
	sources []hostSource
	current hostSource
	exclude *hostMatcher
}

func NewHostIterator(host string, filename string, nohosts ...string) (*HostIterator, error) {
	var sources []hostSource

	if filename != "" {
		fileSrc, err := newFileHostSource(filename)
		if err != nil {
			return nil, err
		}
		sources = append(sources, fileSrc)
	}

	hostSources, err := newHostSources(host)
	if err != nil {
		closeHostSources(sources)
		return nil, err
	}
	sources = append(sources, hostSources...)

	matcher := newHostMatcher()
	for _, exclude := range nohosts {
		if strings.TrimSpace(exclude) == "" {
			continue
		}
		if err := matcher.add(exclude); err != nil {
			closeHostSources(sources)
			return nil, err
		}
	}

	return &HostIterator{
		sources: sources,
		exclude: matcher,
	}, nil
}

func (it *HostIterator) Close() error {
	if it == nil {
		return nil
	}
	var firstErr error
	if it.current != nil {
		firstErr = it.current.Close()
		it.current = nil
	}
	for _, src := range it.sources {
		if err := src.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	it.sources = nil
	return firstErr
}

func (it *HostIterator) Next() (string, bool, error) {
	for {
		if it.current == nil {
			if len(it.sources) == 0 {
				return "", false, nil
			}
			it.current = it.sources[0]
			it.sources = it.sources[1:]
		}

		host, ok, err := it.current.Next()
		if err != nil {
			return "", false, err
		}
		if !ok {
			if err := it.current.Close(); err != nil {
				return "", false, err
			}
			it.current = nil
			continue
		}
		if it.exclude != nil && it.exclude.match(host) {
			continue
		}
		return host, true, nil
	}
}

func (it *HostIterator) NextBatch(ctx context.Context, size int) ([]string, error) {
	if size <= 0 {
		size = DefaultHostBatchSize
	}

	batch := make([]string, 0, size)
	seen := make(map[string]struct{}, size)
	for len(batch) < size {
		select {
		case <-ctx.Done():
			return batch, ctx.Err()
		default:
		}

		host, ok, err := it.Next()
		if err != nil {
			return batch, err
		}
		if !ok {
			return batch, nil
		}
		if _, exists := seen[host]; exists {
			continue
		}
		seen[host] = struct{}{}
		batch = append(batch, host)
	}
	return batch, nil
}

type hostSource interface {
	Next() (string, bool, error)
	Close() error
}

type singleHostSource struct {
	host string
	done bool
}

func (s *singleHostSource) Next() (string, bool, error) {
	if s.done {
		return "", false, nil
	}
	s.done = true
	return s.host, true, nil
}

func (s *singleHostSource) Close() error { return nil }

type cidrHostSource struct {
	current uint32
	end     uint32
	done    bool
}

func (s *cidrHostSource) Next() (string, bool, error) {
	if s.done || s.current > s.end {
		return "", false, nil
	}
	host := uint32ToIP(s.current)
	if s.current == s.end {
		s.done = true
	} else {
		s.current++
	}
	return host, true, nil
}

func (s *cidrHostSource) Close() error { return nil }

type fileHostSource struct {
	file    *os.File
	scanner *bufio.Scanner
	current hostSource
}

func newFileHostSource(filename string) (*fileHostSource, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	src := &fileHostSource{
		file:    file,
		scanner: bufio.NewScanner(file),
	}
	src.scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	return src, nil
}

func (s *fileHostSource) Next() (string, bool, error) {
	for {
		if s.current != nil {
			host, ok, err := s.current.Next()
			if err != nil {
				return "", false, err
			}
			if ok {
				return host, true, nil
			}
			_ = s.current.Close()
			s.current = nil
		}

		if !s.scanner.Scan() {
			if err := s.scanner.Err(); err != nil {
				return "", false, err
			}
			return "", false, nil
		}
		line := strings.TrimSpace(s.scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		sources, err := newHostSources(line)
		if err != nil || len(sources) == 0 {
			continue
		}
		if len(sources) == 1 {
			s.current = sources[0]
			continue
		}
		s.current = &multiHostSource{sources: sources}
	}
}

func (s *fileHostSource) Close() error {
	if s.current != nil {
		_ = s.current.Close()
		s.current = nil
	}
	if s.file == nil {
		return nil
	}
	err := s.file.Close()
	s.file = nil
	return err
}

type multiHostSource struct {
	sources []hostSource
	current hostSource
}

func (s *multiHostSource) Next() (string, bool, error) {
	for {
		if s.current == nil {
			if len(s.sources) == 0 {
				return "", false, nil
			}
			s.current = s.sources[0]
			s.sources = s.sources[1:]
		}
		host, ok, err := s.current.Next()
		if err != nil {
			return "", false, err
		}
		if ok {
			return host, true, nil
		}
		_ = s.current.Close()
		s.current = nil
	}
}

func (s *multiHostSource) Close() error {
	if s.current != nil {
		_ = s.current.Close()
		s.current = nil
	}
	closeHostSources(s.sources)
	s.sources = nil
	return nil
}

func newHostSources(host string) ([]hostSource, error) {
	var sources []hostSource
	for _, h := range strings.Split(host, ",") {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		src, err := newHostSource(h)
		if err != nil {
			closeHostSources(sources)
			return nil, err
		}
		sources = append(sources, src)
	}
	return sources, nil
}

func newHostSource(host string) (hostSource, error) {
	switch {
	case host == "192":
		return newCIDRHostSource("192.168.0.0/16")
	case host == "172":
		return newCIDRHostSource("172.16.0.0/12")
	case host == "10":
		return newCIDRHostSource("10.0.0.0/8")
	case strings.Contains(host, "/"):
		src, err := newCIDRHostSource(host)
		if err != nil {
			return nil, fmt.Errorf(i18n.Tr("parser_cidr_failed", host)+": %w", err)
		}
		return src, nil
	case strings.Contains(host, "-") && !strings.Contains(host, ":") && looksLikeIPRange(host):
		src, err := newRangeHostSource(host)
		if err != nil {
			return nil, fmt.Errorf(i18n.Tr("parser_ip_range_failed", host)+": %w", err)
		}
		return src, nil
	default:
		return &singleHostSource{host: host}, nil
	}
}

func newCIDRHostSource(cidr string) (hostSource, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	start, ok := ipToUint32(ipNet.IP)
	if !ok {
		return nil, fmt.Errorf("%s", i18n.GetText("parser_ipv4_only"))
	}
	ones, bits := ipNet.Mask.Size()
	if bits != 32 {
		return nil, fmt.Errorf("%s", i18n.GetText("parser_ipv4_only"))
	}
	size := uint64(1) << uint(32-ones)
	end := start + uint32(size-1)
	if size > 2 {
		start++
		end--
	}
	return &cidrHostSource{current: start, end: end}, nil
}

func newRangeHostSource(rangeStr string) (hostSource, error) {
	parts := strings.Split(rangeStr, "-")
	if len(parts) != 2 {
		return nil, fmt.Errorf("%s", i18n.Tr("parser_invalid_ip_range_fmt", rangeStr))
	}

	startIPStr := strings.TrimSpace(parts[0])
	endIPStr := strings.TrimSpace(parts[1])
	startIP := net.ParseIP(startIPStr)
	if startIP == nil {
		return nil, fmt.Errorf("%s", i18n.Tr("parser_invalid_start_ip", startIPStr))
	}

	if len(endIPStr) < 4 || !strings.Contains(endIPStr, ".") {
		endNum, err := strconv.Atoi(endIPStr)
		if err != nil || endNum > 255 {
			return nil, fmt.Errorf("%s", i18n.Tr("parser_invalid_ip_end_val", endIPStr))
		}
		parts := strings.Split(startIPStr, ".")
		if len(parts) != 4 {
			return nil, fmt.Errorf("%s", i18n.Tr("parser_invalid_ip_fmt", startIPStr))
		}
		parts[3] = strconv.Itoa(endNum)
		endIPStr = strings.Join(parts, ".")
	}

	start, ok := ipToUint32(startIP)
	if !ok {
		return nil, fmt.Errorf("%s", i18n.GetText("parser_ipv4_only"))
	}
	end, ok := ipToUint32(net.ParseIP(endIPStr))
	if !ok {
		return nil, fmt.Errorf("%s", i18n.Tr("parser_invalid_end_ip", endIPStr))
	}
	if start > end {
		return nil, fmt.Errorf("%s", i18n.GetText("parser_start_gt_end"))
	}
	return &cidrHostSource{current: start, end: end}, nil
}

func closeHostSources(sources []hostSource) {
	for _, src := range sources {
		_ = src.Close()
	}
}

type hostMatcher struct {
	exact  map[string]struct{}
	ranges []ipRange
}

type ipRange struct {
	start uint32
	end   uint32
}

func newHostMatcher() *hostMatcher {
	return &hostMatcher{exact: make(map[string]struct{})}
}

func (m *hostMatcher) add(input string) error {
	for _, h := range strings.Split(input, ",") {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		switch {
		case h == "192":
			if err := m.addCIDR("192.168.0.0/16"); err != nil {
				return err
			}
		case h == "172":
			if err := m.addCIDR("172.16.0.0/12"); err != nil {
				return err
			}
		case h == "10":
			if err := m.addCIDR("10.0.0.0/8"); err != nil {
				return err
			}
		case strings.Contains(h, "/"):
			if err := m.addCIDR(h); err != nil {
				return err
			}
		case strings.Contains(h, "-") && !strings.Contains(h, ":") && looksLikeIPRange(h):
			if err := m.addRange(h); err != nil {
				return err
			}
		default:
			m.exact[h] = struct{}{}
		}
	}
	return nil
}

func (m *hostMatcher) addCIDR(cidr string) error {
	src, err := newCIDRHostSource(cidr)
	if err != nil {
		return err
	}
	rangeSrc, ok := src.(*cidrHostSource)
	if !ok {
		return fmt.Errorf("%s", i18n.GetText("parser_ipv4_only"))
	}
	m.ranges = append(m.ranges, ipRange{start: rangeSrc.current, end: rangeSrc.end})
	return nil
}

func (m *hostMatcher) addRange(rangeStr string) error {
	src, err := newRangeHostSource(rangeStr)
	if err != nil {
		return err
	}
	rangeSrc, ok := src.(*cidrHostSource)
	if !ok {
		return fmt.Errorf("%s", i18n.GetText("parser_ipv4_only"))
	}
	m.ranges = append(m.ranges, ipRange{start: rangeSrc.current, end: rangeSrc.end})
	return nil
}

func (m *hostMatcher) match(host string) bool {
	if _, ok := m.exact[host]; ok {
		return true
	}
	ip, ok := ipToUint32(net.ParseIP(host))
	if !ok {
		return false
	}
	for _, r := range m.ranges {
		if ip >= r.start && ip <= r.end {
			return true
		}
	}
	return false
}

func ipToUint32(ip net.IP) (uint32, bool) {
	ip4 := ip.To4()
	if ip4 == nil {
		return 0, false
	}
	return uint32(ip4[0])<<24 | uint32(ip4[1])<<16 | uint32(ip4[2])<<8 | uint32(ip4[3]), true
}

func uint32ToIP(v uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

// EstimateHostCount 快速估算主机总数（不消费 iterator）
func EstimateHostCount(host string, filename string) int64 {
	var total int64

	if filename != "" {
		if f, err := os.Open(filename); err == nil {
			scanner := bufio.NewScanner(f)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				total += estimateHostEntry(line)
			}
			_ = f.Close()
		}
	}

	for _, h := range strings.Split(host, ",") {
		h = strings.TrimSpace(h)
		if h != "" {
			total += estimateHostEntry(h)
		}
	}

	return total
}

func estimateHostEntry(entry string) int64 {
	switch {
	case entry == "192":
		return 65536 // /16
	case entry == "172":
		return 1 << 20 // /12
	case entry == "10":
		return 1 << 24 // /8
	case strings.Contains(entry, "/"):
		_, ipNet, err := net.ParseCIDR(entry)
		if err != nil {
			return 1
		}
		ones, bits := ipNet.Mask.Size()
		if bits != 32 {
			return 1
		}
		size := int64(1) << uint(32-ones)
		if size > 2 {
			size -= 2
		}
		return size
	case strings.Contains(entry, "-") && !strings.Contains(entry, ":") && looksLikeIPRange(entry):
		parts := strings.SplitN(entry, "-", 2)
		startIP := net.ParseIP(strings.TrimSpace(parts[0]))
		if startIP == nil {
			return 1
		}
		startU, ok := ipToUint32(startIP)
		if !ok {
			return 1
		}
		endStr := strings.TrimSpace(parts[1])
		var endU uint32
		if len(endStr) < 4 || !strings.Contains(endStr, ".") {
			n, err := strconv.Atoi(endStr)
			if err != nil || n > 255 {
				return 1
			}
			endU = (startU & 0xFFFFFF00) | uint32(n)
		} else {
			endIP := net.ParseIP(endStr)
			if endIP == nil {
				return 1
			}
			endU, ok = ipToUint32(endIP)
			if !ok {
				return 1
			}
		}
		if endU < startU {
			return 1
		}
		return int64(endU-startU) + 1
	default:
		return 1
	}
}
