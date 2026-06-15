package parsers

import (
	"bufio"
	"context"
	"errors"
	"net"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestHostIteratorCIDRBatch(t *testing.T) {
	iter, err := NewHostIterator("192.168.1.0/30", "", "")
	if err != nil {
		t.Fatalf("NewHostIterator error = %v", err)
	}
	defer iter.Close()

	batch, err := iter.NextBatch(context.Background(), 10)
	if err != nil {
		t.Fatalf("NextBatch error = %v", err)
	}

	want := []string{"192.168.1.1", "192.168.1.2"}
	if !reflect.DeepEqual(batch, want) {
		t.Fatalf("batch = %#v, want %#v", batch, want)
	}
}

func TestHostIteratorDoesNotExpandWholeRangeAtOnce(t *testing.T) {
	iter, err := NewHostIterator("10", "", "")
	if err != nil {
		t.Fatalf("NewHostIterator error = %v", err)
	}
	defer iter.Close()

	batch, err := iter.NextBatch(context.Background(), 3)
	if err != nil {
		t.Fatalf("NextBatch error = %v", err)
	}

	want := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}
	if !reflect.DeepEqual(batch, want) {
		t.Fatalf("batch = %#v, want %#v", batch, want)
	}
}

func TestHostIteratorExcludeCIDR(t *testing.T) {
	iter, err := NewHostIterator("192.168.1.0/29", "", "192.168.1.2-192.168.1.4")
	if err != nil {
		t.Fatalf("NewHostIterator error = %v", err)
	}
	defer iter.Close()

	batch, err := iter.NextBatch(context.Background(), 10)
	if err != nil {
		t.Fatalf("NextBatch error = %v", err)
	}

	want := []string{"192.168.1.1", "192.168.1.5", "192.168.1.6"}
	if !reflect.DeepEqual(batch, want) {
		t.Fatalf("batch = %#v, want %#v", batch, want)
	}
}

func TestHostIteratorAcceptsMultipleExcludeSources(t *testing.T) {
	iter, err := NewHostIterator("192.168.1.0/29", "", "192.168.1.2", "192.168.1.5")
	if err != nil {
		t.Fatalf("NewHostIterator error = %v", err)
	}
	defer iter.Close()

	batch, err := iter.NextBatch(context.Background(), 10)
	if err != nil {
		t.Fatalf("NextBatch error = %v", err)
	}

	want := []string{"192.168.1.1", "192.168.1.3", "192.168.1.4", "192.168.1.6"}
	if !reflect.DeepEqual(batch, want) {
		t.Fatalf("batch = %#v, want %#v", batch, want)
	}
}

func TestHostIteratorReadsLongHostFileLine(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/hosts.txt"
	longPrefix := strings.Repeat("a", 70*1024)
	host := longPrefix + ".example.com"
	if err := os.WriteFile(path, []byte(host+"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile error = %v", err)
	}

	iter, err := NewHostIterator("", path)
	if err != nil {
		t.Fatalf("NewHostIterator error = %v", err)
	}
	defer iter.Close()

	batch, err := iter.NextBatch(context.Background(), 1)
	if err != nil {
		t.Fatalf("NextBatch error = %v", err)
	}
	if !reflect.DeepEqual(batch, []string{host}) {
		t.Fatalf("batch = %#v, want long host", batch)
	}
}

func TestMultiHostSourceAndMatcherCIDR(t *testing.T) {
	src := &multiHostSource{sources: []hostSource{
		&singleHostSource{host: "192.168.1.1"},
		&singleHostSource{host: "192.168.1.2"},
	}}

	host, ok, err := src.Next()
	if err != nil || !ok || host != "192.168.1.1" {
		t.Fatalf("first Next = %q/%v/%v", host, ok, err)
	}
	host, ok, err = src.Next()
	if err != nil || !ok || host != "192.168.1.2" {
		t.Fatalf("second Next = %q/%v/%v", host, ok, err)
	}
	host, ok, err = src.Next()
	if err != nil || ok || host != "" {
		t.Fatalf("exhausted Next = %q/%v/%v", host, ok, err)
	}
	if err := src.Close(); err != nil {
		t.Fatalf("Close error = %v", err)
	}

	matcher := newHostMatcher()
	if err := matcher.add("192.168.1.0/30,example.com"); err != nil {
		t.Fatalf("matcher add error = %v", err)
	}
	if !matcher.match("192.168.1.1") || !matcher.match("192.168.1.2") || !matcher.match("example.com") {
		t.Fatal("matcher should match CIDR hosts and exact host")
	}
	if matcher.match("192.168.1.3") || matcher.match("nope.example") {
		t.Fatal("matcher matched hosts outside its rules")
	}
	if err := matcher.add("2001:db8::/126"); err == nil {
		t.Fatal("IPv6 CIDR should be rejected by IPv4-only matcher")
	}
}

func TestCloseHostSourcesIgnoresCloseErrors(t *testing.T) {
	first := &closeTrackingSource{err: errors.New("close failed")}
	second := &closeTrackingSource{}

	closeHostSources([]hostSource{first, second})

	if !first.closed || !second.closed {
		t.Fatalf("sources closed = %v/%v, want both true", first.closed, second.closed)
	}
}

type closeTrackingSource struct {
	closed bool
	err    error
}

func (s *closeTrackingSource) Next() (string, bool, error) {
	return "", false, nil
}

func (s *closeTrackingSource) Close() error {
	s.closed = true
	return s.err
}

// =============================================================================
// newHostSource 分支覆盖
// =============================================================================

// TestNewHostSource_Shortcuts 验证 192/172/10 快捷方式展开为正确 CIDR
func TestNewHostSource_Shortcuts(t *testing.T) {
	cases := []struct {
		input     string
		wantFirst string
	}{
		{"192", "192.168.0.1"},
		{"172", "172.16.0.1"},
		{"10", "10.0.0.1"},
	}
	for _, c := range cases {
		t.Run(c.input, func(t *testing.T) {
			src, err := newHostSource(c.input)
			if err != nil {
				t.Fatalf("newHostSource(%q) error = %v", c.input, err)
			}
			defer src.Close()
			host, ok, err := src.Next()
			if err != nil || !ok {
				t.Fatalf("Next() = %q/%v/%v", host, ok, err)
			}
			if host != c.wantFirst {
				t.Errorf("first host = %q, 期望 %q", host, c.wantFirst)
			}
		})
	}
}

// TestNewHostSource_CIDRBranch 验证含 "/" 走 CIDR 分支
func TestNewHostSource_CIDRBranch(t *testing.T) {
	src, err := newHostSource("10.0.0.0/30")
	if err != nil {
		t.Fatalf("newHostSource CIDR error = %v", err)
	}
	defer src.Close()
	host, ok, _ := src.Next()
	if !ok || host != "10.0.0.1" {
		t.Errorf("CIDR first host = %q, 期望 10.0.0.1", host)
	}
}

// TestNewHostSource_InvalidCIDR 无效 CIDR 返回错误
func TestNewHostSource_InvalidCIDR(t *testing.T) {
	_, err := newHostSource("999.0.0.0/24")
	if err == nil {
		t.Error("无效 CIDR 应返回 error")
	}
}

// TestNewHostSource_RangeBranch 验证 a-b 格式走 range 分支
func TestNewHostSource_RangeBranch(t *testing.T) {
	src, err := newHostSource("192.168.1.5-192.168.1.7")
	if err != nil {
		t.Fatalf("newHostSource range error = %v", err)
	}
	defer src.Close()

	var got []string
	for {
		h, ok, err := src.Next()
		if err != nil {
			t.Fatalf("Next() error = %v", err)
		}
		if !ok {
			break
		}
		got = append(got, h)
	}
	want := []string{"192.168.1.5", "192.168.1.6", "192.168.1.7"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("range hosts = %v, 期望 %v", got, want)
	}
}

// TestNewHostSource_RangeShortTail 验证短尾写法 x.x.x.a-b
func TestNewHostSource_RangeShortTail(t *testing.T) {
	src, err := newHostSource("10.0.0.3-5")
	if err != nil {
		t.Fatalf("newHostSource short-tail range error = %v", err)
	}
	defer src.Close()

	var got []string
	for {
		h, ok, err := src.Next()
		if err != nil {
			t.Fatalf("Next() error = %v", err)
		}
		if !ok {
			break
		}
		got = append(got, h)
	}
	want := []string{"10.0.0.3", "10.0.0.4", "10.0.0.5"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("short-tail range = %v, 期望 %v", got, want)
	}
}

// TestNewHostSource_SingleHost 验证普通主机名走 singleHostSource 分支
func TestNewHostSource_SingleHost(t *testing.T) {
	src, err := newHostSource("example.com")
	if err != nil {
		t.Fatalf("newHostSource single error = %v", err)
	}
	defer src.Close()

	host, ok, err := src.Next()
	if err != nil || !ok || host != "example.com" {
		t.Errorf("single host = %q/%v/%v, 期望 example.com/true/nil", host, ok, err)
	}
	// 第二次应该耗尽
	_, ok, _ = src.Next()
	if ok {
		t.Error("singleHostSource 第二次 Next 应返回 ok=false")
	}
}

// =============================================================================
// hostMatcher.add 分支覆盖
// =============================================================================

// TestHostMatcherAdd_192Shortcut 验证 add("192") 展开为 192.168.0.0/16
func TestHostMatcherAdd_192Shortcut(t *testing.T) {
	m := newHostMatcher()
	if err := m.add("192"); err != nil {
		t.Fatalf("add(192) error = %v", err)
	}
	if !m.match("192.168.1.100") {
		t.Error("192.168.1.100 应命中 192.168.0.0/16")
	}
	if m.match("10.0.0.1") {
		t.Error("10.0.0.1 不应命中")
	}
}

// TestHostMatcherAdd_172Shortcut 验证 add("172")
func TestHostMatcherAdd_172Shortcut(t *testing.T) {
	m := newHostMatcher()
	if err := m.add("172"); err != nil {
		t.Fatalf("add(172) error = %v", err)
	}
	if !m.match("172.16.0.1") {
		t.Error("172.16.0.1 应命中 172.16.0.0/12")
	}
}

// TestHostMatcherAdd_10Shortcut 验证 add("10")
func TestHostMatcherAdd_10Shortcut(t *testing.T) {
	m := newHostMatcher()
	if err := m.add("10"); err != nil {
		t.Fatalf("add(10) error = %v", err)
	}
	if !m.match("10.1.2.3") {
		t.Error("10.1.2.3 应命中 10.0.0.0/8")
	}
}

// TestHostMatcherAdd_CIDR 验证 add 处理 CIDR 字符串
func TestHostMatcherAdd_CIDR(t *testing.T) {
	m := newHostMatcher()
	if err := m.add("192.168.5.0/24"); err != nil {
		t.Fatalf("add CIDR error = %v", err)
	}
	if !m.match("192.168.5.10") {
		t.Error("192.168.5.10 应命中 /24")
	}
	if m.match("192.168.6.10") {
		t.Error("192.168.6.10 不应命中")
	}
}

// TestHostMatcherAdd_Range 验证 add 处理 a-b 范围
func TestHostMatcherAdd_Range(t *testing.T) {
	m := newHostMatcher()
	if err := m.add("10.0.0.10-10.0.0.20"); err != nil {
		t.Fatalf("add range error = %v", err)
	}
	if !m.match("10.0.0.15") {
		t.Error("10.0.0.15 应命中范围")
	}
	if m.match("10.0.0.9") || m.match("10.0.0.21") {
		t.Error("边界外不应命中")
	}
}

// TestHostMatcherAdd_ExactHost 验证 add 处理普通主机名（exact 分支）
func TestHostMatcherAdd_ExactHost(t *testing.T) {
	m := newHostMatcher()
	if err := m.add("myhost.local"); err != nil {
		t.Fatalf("add exact error = %v", err)
	}
	if !m.match("myhost.local") {
		t.Error("exact 主机名应命中")
	}
	if m.match("other.local") {
		t.Error("其他主机名不应命中")
	}
}

// TestHostMatcherAdd_MultipleComma 验证逗号分隔多个值
func TestHostMatcherAdd_MultipleComma(t *testing.T) {
	m := newHostMatcher()
	if err := m.add("host1.com, host2.com, 192.168.1.0/30"); err != nil {
		t.Fatalf("add comma-separated error = %v", err)
	}
	if !m.match("host1.com") || !m.match("host2.com") || !m.match("192.168.1.1") {
		t.Error("逗号分隔的值应全部命中")
	}
}

// TestHostMatcherAdd_EmptyEntry 逗号中间空串不报错
func TestHostMatcherAdd_EmptyEntry(t *testing.T) {
	m := newHostMatcher()
	if err := m.add(",,,"); err != nil {
		t.Fatalf("全空逗号不应报错: %v", err)
	}
}

// TestHostMatcherAdd_InvalidCIDR 无效 CIDR 返回 error
func TestHostMatcherAdd_InvalidCIDR(t *testing.T) {
	m := newHostMatcher()
	if err := m.add("999.0.0.0/8"); err == nil {
		t.Error("无效 CIDR 应返回 error")
	}
}

// =============================================================================
// fileHostSource.Next 分支覆盖
// =============================================================================

// TestFileHostSourceNext_SkipsEmptyAndComments 验证空行和注释行被跳过
func TestFileHostSourceNext_SkipsEmptyAndComments(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/hosts.txt"
	content := "\n# this is a comment\n\n  \n10.0.0.1\n# another comment\n10.0.0.2\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile error = %v", err)
	}

	iter, err := NewHostIterator("", path)
	if err != nil {
		t.Fatalf("NewHostIterator error = %v", err)
	}
	defer iter.Close()

	batch, err := iter.NextBatch(context.Background(), 10)
	if err != nil {
		t.Fatalf("NextBatch error = %v", err)
	}
	want := []string{"10.0.0.1", "10.0.0.2"}
	if !reflect.DeepEqual(batch, want) {
		t.Errorf("batch = %v, 期望 %v", batch, want)
	}
}

// TestFileHostSourceNext_MultipleSources 验证文件中每行多个 host（逗号分隔）走 multiHostSource 分支
func TestFileHostSourceNext_MultipleSources(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/hosts.txt"
	// 一行两个 host，触发 multiHostSource 分支
	content := "10.0.0.1,10.0.0.2\n10.0.0.3\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile error = %v", err)
	}

	iter, err := NewHostIterator("", path)
	if err != nil {
		t.Fatalf("NewHostIterator error = %v", err)
	}
	defer iter.Close()

	batch, err := iter.NextBatch(context.Background(), 10)
	if err != nil {
		t.Fatalf("NextBatch error = %v", err)
	}
	want := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}
	if !reflect.DeepEqual(batch, want) {
		t.Errorf("batch = %v, 期望 %v", batch, want)
	}
}

// TestFileHostSourceNext_InvalidLineSkipped 无效行（解析失败）被跳过不报错
func TestFileHostSourceNext_InvalidLineSkipped(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/hosts.txt"
	// 包含无效 CIDR，应被跳过
	content := "999.0.0.0/8\n10.0.0.1\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile error = %v", err)
	}

	iter, err := NewHostIterator("", path)
	if err != nil {
		t.Fatalf("NewHostIterator error = %v", err)
	}
	defer iter.Close()

	batch, err := iter.NextBatch(context.Background(), 10)
	if err != nil {
		t.Fatalf("NextBatch error = %v", err)
	}
	// 无效行被跳过，只返回有效行
	if len(batch) != 1 || batch[0] != "10.0.0.1" {
		t.Errorf("batch = %v, 期望 [10.0.0.1]", batch)
	}
}

// =============================================================================
// NewHostIterator 错误路径
// =============================================================================

// TestNewHostIterator_InvalidFilename 不存在的文件应返回 error
func TestNewHostIterator_InvalidFilename(t *testing.T) {
	_, err := NewHostIterator("", "/nonexistent/path/hosts.txt")
	if err == nil {
		t.Error("不存在的文件应返回 error")
	}
}

// TestNewHostIterator_InvalidHost host 解析失败时应返回 error（并关闭已打开的文件 source）
func TestNewHostIterator_InvalidHost_WithFile(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/hosts.txt"
	if err := os.WriteFile(path, []byte("10.0.0.1\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	// 无效 CIDR 会让 newHostSources 失败
	_, err := NewHostIterator("999.0.0.0/8", path)
	if err == nil {
		t.Error("无效 host 应返回 error")
	}
}

// TestNewHostIterator_InvalidExclude exclude 参数无效时应返回 error
func TestNewHostIterator_InvalidExclude(t *testing.T) {
	_, err := NewHostIterator("10.0.0.1", "", "999.0.0.0/8")
	if err == nil {
		t.Error("无效 exclude 应返回 error")
	}
}

// TestNewHostIterator_EmptyExcludeSkipped 空白 exclude 条目应被跳过，不报错
func TestNewHostIterator_EmptyExcludeSkipped(t *testing.T) {
	iter, err := NewHostIterator("10.0.0.1", "", "   ", "")
	if err != nil {
		t.Fatalf("空白 exclude 不应报错: %v", err)
	}
	defer iter.Close()
	host, ok, err := iter.Next()
	if err != nil || !ok || host != "10.0.0.1" {
		t.Errorf("Next() = %q/%v/%v", host, ok, err)
	}
}

// =============================================================================
// Close 路径
// =============================================================================

// TestClose_Nil nil HostIterator Close 不 panic
func TestClose_Nil(t *testing.T) {
	var it *HostIterator
	if err := it.Close(); err != nil {
		t.Errorf("nil Close 应返回 nil, 得到 %v", err)
	}
}

// TestClose_WithCurrent 有 current source 时 Close 应关闭它
func TestClose_WithCurrent(t *testing.T) {
	src := &closeTrackingSource{}
	it := &HostIterator{current: src}
	if err := it.Close(); err != nil {
		t.Errorf("Close error = %v", err)
	}
	if !src.closed {
		t.Error("current source 应被关闭")
	}
	if it.current != nil {
		t.Error("Close 后 current 应为 nil")
	}
}

// TestClose_SourcesError Close 中 source 返回 error 应被记录
func TestClose_SourcesError(t *testing.T) {
	errSrc := &closeTrackingSource{err: errors.New("close error")}
	it := &HostIterator{sources: []hostSource{errSrc}}
	err := it.Close()
	if err == nil {
		t.Error("source Close 失败时应返回 error")
	}
	if !errSrc.closed {
		t.Error("出错的 source 也应被调用 Close")
	}
}

// TestClose_CurrentErrorThenSources current Close 报错，后续 source Close 成功，返回 current 的 error
func TestClose_CurrentErrorThenSources(t *testing.T) {
	currentSrc := &closeTrackingSource{err: errors.New("current close error")}
	otherSrc := &closeTrackingSource{}
	it := &HostIterator{
		current: currentSrc,
		sources: []hostSource{otherSrc},
	}
	err := it.Close()
	if err == nil {
		t.Error("应返回 current 的 error")
	}
	if !currentSrc.closed || !otherSrc.closed {
		t.Error("两个 source 都应被关闭")
	}
}

// =============================================================================
// Next 错误路径
// =============================================================================

// errorSource 让 Next() 返回 error
type errorSource struct {
	err error
}

func (s *errorSource) Next() (string, bool, error) { return "", false, s.err }
func (s *errorSource) Close() error                { return nil }

// errorOnCloseSource Next 返回 ok=false，Close 返回 error
type errorOnCloseSource struct {
	err error
}

func (s *errorOnCloseSource) Next() (string, bool, error) { return "", false, nil }
func (s *errorOnCloseSource) Close() error                { return s.err }

// TestNext_SourceNextError source.Next() 返回 error 时 iter.Next 应透传
func TestNext_SourceNextError(t *testing.T) {
	it := &HostIterator{
		sources: []hostSource{&errorSource{err: errors.New("next error")}},
	}
	_, _, err := it.Next()
	if err == nil {
		t.Error("source Next error 应透传")
	}
}

// TestNext_SourceCloseError 源耗尽时 Close 报错应透传
func TestNext_SourceCloseError(t *testing.T) {
	it := &HostIterator{
		sources: []hostSource{&errorOnCloseSource{err: errors.New("close error")}},
	}
	_, _, err := it.Next()
	if err == nil {
		t.Error("source 耗尽时 Close error 应透传")
	}
}

// =============================================================================
// NextBatch 边界条件
// =============================================================================

// TestNextBatch_ZeroSize size=0 应使用 DefaultHostBatchSize（实际受源数量限制）
func TestNextBatch_ZeroSize(t *testing.T) {
	iter, err := NewHostIterator("10.0.0.1", "")
	if err != nil {
		t.Fatalf("NewHostIterator: %v", err)
	}
	defer iter.Close()

	// size=0 触发默认 DefaultHostBatchSize 分支，源只有一个 host
	batch, err := iter.NextBatch(context.Background(), 0)
	if err != nil {
		t.Fatalf("NextBatch(0) error = %v", err)
	}
	if len(batch) != 1 || batch[0] != "10.0.0.1" {
		t.Errorf("batch = %v, 期望 [10.0.0.1]", batch)
	}
}

// TestNextBatch_NegativeSize size<0 也应使用默认值
func TestNextBatch_NegativeSize(t *testing.T) {
	iter, err := NewHostIterator("10.0.0.2", "")
	if err != nil {
		t.Fatalf("NewHostIterator: %v", err)
	}
	defer iter.Close()

	batch, err := iter.NextBatch(context.Background(), -1)
	if err != nil {
		t.Fatalf("NextBatch(-1) error = %v", err)
	}
	if len(batch) != 1 || batch[0] != "10.0.0.2" {
		t.Errorf("batch = %v, 期望 [10.0.0.2]", batch)
	}
}

// TestNextBatch_ContextCancelled context 取消应立即返回
func TestNextBatch_ContextCancelled(t *testing.T) {
	iter, err := NewHostIterator("10.0.0.0/8", "")
	if err != nil {
		t.Fatalf("NewHostIterator: %v", err)
	}
	defer iter.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // 立即取消

	_, err = iter.NextBatch(ctx, 100)
	if err == nil {
		t.Error("已取消的 context 应返回 error")
	}
}

// TestNextBatch_DeduplicatesHosts 重复 host 只保留一个
func TestNextBatch_DeduplicatesHosts(t *testing.T) {
	// 两个相同的单 host source
	it := &HostIterator{
		sources: []hostSource{
			&singleHostSource{host: "10.0.0.1"},
			&singleHostSource{host: "10.0.0.1"},
		},
	}
	batch, err := it.NextBatch(context.Background(), 10)
	if err != nil {
		t.Fatalf("NextBatch error = %v", err)
	}
	if len(batch) != 1 || batch[0] != "10.0.0.1" {
		t.Errorf("batch = %v, 期望去重为 [10.0.0.1]", batch)
	}
}

// TestNextBatch_NextError Next 报错时应透传
func TestNextBatch_NextError(t *testing.T) {
	it := &HostIterator{
		sources: []hostSource{&errorSource{err: errors.New("iter error")}},
	}
	_, err := it.NextBatch(context.Background(), 10)
	if err == nil {
		t.Error("Next error 应透传到 NextBatch")
	}
}

// =============================================================================
// newRangeHostSource 错误路径
// =============================================================================

// TestNewRangeHostSource_TooManyDashes 超过一个 "-" 应报错（实际按首个切分：a-b-c 被 Split 成 3 段）
func TestNewRangeHostSource_TooManyDashes(t *testing.T) {
	// "a-b-c" Split by "-" 得到 3 段，len != 2，应报错
	_, err := newRangeHostSource("10.0.0.1-10.0.0.5-extra")
	if err == nil {
		t.Error("三段格式应报错")
	}
}

// TestNewRangeHostSource_InvalidStartIP 起始 IP 无效
func TestNewRangeHostSource_InvalidStartIP(t *testing.T) {
	_, err := newRangeHostSource("notanip-10.0.0.5")
	if err == nil {
		t.Error("无效起始 IP 应报错")
	}
}

// TestNewRangeHostSource_InvalidShortTailNonNumeric 短尾不是数字应报错
func TestNewRangeHostSource_InvalidShortTailNonNumeric(t *testing.T) {
	// 尾部 "xyz" 不是数字
	_, err := newRangeHostSource("10.0.0.1-xyz")
	if err == nil {
		t.Error("非数字短尾应报错")
	}
}

// TestNewRangeHostSource_InvalidShortTailOver255 短尾超过 255 应报错
func TestNewRangeHostSource_InvalidShortTailOver255(t *testing.T) {
	_, err := newRangeHostSource("10.0.0.1-300")
	if err == nil {
		t.Error("短尾 >255 应报错")
	}
}

// TestNewRangeHostSource_StartGTEnd 起始 > 结束应报错
func TestNewRangeHostSource_StartGTEnd(t *testing.T) {
	_, err := newRangeHostSource("10.0.0.200-10.0.0.100")
	if err == nil {
		t.Error("start > end 应报错")
	}
}

// TestNewRangeHostSource_InvalidFullEndIP 完整结束 IP 无效（如 "10.0.0.999"）
func TestNewRangeHostSource_InvalidFullEndIP(t *testing.T) {
	// end IP 包含 "." 但无效
	_, err := newRangeHostSource("10.0.0.1-10.0.0.999")
	if err == nil {
		t.Error("无效结束 IP 应报错")
	}
}

// TestNewRangeHostSource_ShortTailStartGTEnd 短尾导致 start > end 应报错
func TestNewRangeHostSource_ShortTailStartGTEnd(t *testing.T) {
	_, err := newRangeHostSource("10.0.0.200-100")
	if err == nil {
		t.Error("短尾结果 start > end 应报错")
	}
}

// =============================================================================
// hostMatcher.addRange 错误路径
// =============================================================================

// TestAddRange_InvalidRange addRange 传入无效范围应报错
func TestAddRange_InvalidRange(t *testing.T) {
	m := newHostMatcher()
	if err := m.addRange("notvalid-range"); err == nil {
		t.Error("无效 range 应返回 error")
	}
}

// TestAddRange_ValidRange addRange 正常路径
func TestAddRange_ValidRange(t *testing.T) {
	m := newHostMatcher()
	if err := m.addRange("10.0.0.10-10.0.0.20"); err != nil {
		t.Fatalf("addRange error = %v", err)
	}
	if !m.match("10.0.0.10") || !m.match("10.0.0.20") {
		t.Error("addRange 边界值应命中")
	}
}

// =============================================================================
// hostMatcher.add 错误路径（shortcut 分支中 addCIDR 失败）
// =============================================================================

// TestHostMatcherAdd_InvalidRange add 的 range 格式无效
func TestHostMatcherAdd_InvalidRange(t *testing.T) {
	m := newHostMatcher()
	// 构造一个 looksLikeIPRange 通过但 newRangeHostSource 失败的字符串
	// "10.0.0.200-10.0.0.100" start>end 会报错
	if err := m.add("10.0.0.200-10.0.0.100"); err == nil {
		t.Error("无效 range (start>end) 应返回 error")
	}
}

// =============================================================================
// newCIDRHostSource IPv6 路径
// =============================================================================

// TestNewCIDRHostSource_IPv6Rejected IPv6 CIDR 应报错
func TestNewCIDRHostSource_IPv6Rejected(t *testing.T) {
	_, err := newCIDRHostSource("2001:db8::/32")
	if err == nil {
		t.Error("IPv6 CIDR 应被拒绝")
	}
}

// =============================================================================
// fileHostSource.Close 路径
// =============================================================================

// TestFileHostSource_CloseWithCurrent fileHostSource.Close 时 current != nil 分支
func TestFileHostSource_CloseWithCurrent(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/hosts.txt"
	// 写入一个 CIDR，这样 fileHostSource 会持有 current source
	if err := os.WriteFile(path, []byte("10.0.0.0/30\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	src, err := newFileHostSource(path)
	if err != nil {
		t.Fatalf("newFileHostSource: %v", err)
	}
	// 触发 current 被设置
	_, _, _ = src.Next()
	// 此时 current 应非 nil，Close 应正常关闭它
	if err := src.Close(); err != nil {
		t.Errorf("Close with current error = %v", err)
	}
}

// TestFileHostSource_CloseNilFile file 已经为 nil 时 Close 直接返回 nil
func TestFileHostSource_CloseNilFile(t *testing.T) {
	src := &fileHostSource{file: nil}
	if err := src.Close(); err != nil {
		t.Errorf("nil file Close error = %v", err)
	}
}

// =============================================================================
// multiHostSource.Close 路径
// =============================================================================

// TestMultiHostSource_CloseWithCurrent Close 时 current != nil 分支
func TestMultiHostSource_CloseWithCurrent(t *testing.T) {
	inner := &closeTrackingSource{}
	ms := &multiHostSource{current: inner}
	if err := ms.Close(); err != nil {
		t.Errorf("Close error = %v", err)
	}
	if !inner.closed {
		t.Error("current 应被关闭")
	}
	if ms.current != nil {
		t.Error("Close 后 current 应为 nil")
	}
}

// =============================================================================
// ipToUint32 IPv6 路径
// =============================================================================

// TestIpToUint32_IPv6ReturnsFalse IPv6 地址应返回 false
func TestIpToUint32_IPv6ReturnsFalse(t *testing.T) {
	ip := net.ParseIP("2001:db8::1")
	_, ok := ipToUint32(ip)
	if ok {
		t.Error("IPv6 地址应返回 ok=false")
	}
}

// TestIpToUint32_NilReturnsFalse nil IP 应返回 false
func TestIpToUint32_NilReturnsFalse(t *testing.T) {
	_, ok := ipToUint32(nil)
	if ok {
		t.Error("nil IP 应返回 ok=false")
	}
}

// =============================================================================
// 剩余未覆盖路径
// =============================================================================

// TestFileHostSource_CurrentNextError fileHostSource.Next 中 current.Next() 报错应透传
func TestFileHostSource_CurrentNextError(t *testing.T) {
	src := &fileHostSource{
		current: &errorSource{err: errors.New("inner error")},
		// scanner 为 nil——不会走到 scanner 分支
		scanner: bufio.NewScanner(strings.NewReader("")),
	}
	_, _, err := src.Next()
	if err == nil {
		t.Error("current.Next() 报错应透传")
	}
}

// TestMultiHostSource_InnerNextError multiHostSource.Next 中内部 source.Next() 报错应透传
func TestMultiHostSource_InnerNextError(t *testing.T) {
	ms := &multiHostSource{
		sources: []hostSource{&errorSource{err: errors.New("inner error")}},
	}
	_, _, err := ms.Next()
	if err == nil {
		t.Error("内部 source.Next() 报错应透传到 multiHostSource.Next")
	}
}

// TestNewHostSource_RangeError newHostSource range 分支中 newRangeHostSource 失败
func TestNewHostSource_RangeError(t *testing.T) {
	// start > end，looksLikeIPRange 通过（前半部分是有效 IP），但 newRangeHostSource 返回错误
	_, err := newHostSource("10.0.0.200-10.0.0.100")
	if err == nil {
		t.Error("start>end range 应返回 error")
	}
}

// TestNewCIDRHostSource_IPv6DirectCall 直接调用 newCIDRHostSource 传入 IPv6 CIDR
func TestNewCIDRHostSource_IPv6DirectCall(t *testing.T) {
	// IPv6 CIDR —— bits=128 != 32，触发 line 332-334
	_, err := newCIDRHostSource("::1/128")
	if err == nil {
		t.Error("IPv6 CIDR 应被 newCIDRHostSource 拒绝 (bits!=32)")
	}
}
