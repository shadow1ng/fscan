package lib

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"math/rand" //nolint:gosec // G404: math/rand用于生成测试数据，非加密用途
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker/decls"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/interpreter/functions"
	"github.com/shadow1ng/fscan/common"
	"github.com/shadow1ng/fscan/common/i18n"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
)

// 基础CEL环境缓存（避免重复创建，减少内存分配）
var (
	baseEnvOnce    sync.Once
	baseEnv        *cel.Env
	baseProgramOpt []cel.ProgramOption
)

// 包级POC配置（atomic 保证并发安全）
var pocDNSLog atomic.Bool

// InitPOCConfig 初始化POC配置（在扫描开始前调用）
// 这样CEL回调函数可以使用包级变量而非GetGlobalConfig
func InitPOCConfig(dnsLog bool) {
	pocDNSLog.Store(dnsLog)
}

// NewEnv 创建一个新的 CEL 环境（使用缓存避免重复注册函数）
func NewEnv(c *CustomLib) (*cel.Env, error) {
	cachedCELEnvOnce.Do(func() {
		cachedCELEnv, cachedCELEnvErr = cel.NewEnv(cel.Lib(c))
	})
	return cachedCELEnv, cachedCELEnvErr
}

// initBaseEnv 初始化基础CEL环境（只执行一次）
func initBaseEnv() {
	baseEnvOnce.Do(func() {
		// 收集所有函数声明
		var allDeclarations []*exprpb.Decl
		allDeclarations = append(allDeclarations, registerStringDeclarations()...)
		allDeclarations = append(allDeclarations, registerEncodingDeclarations()...)
		allDeclarations = append(allDeclarations, registerCryptoDeclarations()...)
		allDeclarations = append(allDeclarations, registerRandomDeclarations()...)
		allDeclarations = append(allDeclarations, registerMiscDeclarations()...)

		// 收集所有函数实现
		var allImplementations []*functions.Overload
		allImplementations = append(allImplementations, registerStringImplementations()...)
		allImplementations = append(allImplementations, registerEncodingImplementations()...)
		allImplementations = append(allImplementations, registerCryptoImplementations()...)
		allImplementations = append(allImplementations, registerRandomImplementations()...)
		allImplementations = append(allImplementations, registerMiscImplementations()...)

		// 保存程序选项供后续使用
		//nolint:staticcheck // SA1019: cel.Functions已废弃但CEL库尚未提供替代方案
		baseProgramOpt = []cel.ProgramOption{cel.Functions(allImplementations...)}

		// 创建基础环境
		var err error
		baseEnv, err = cel.NewEnv(
			cel.Container("lib"),
			cel.Types(&UrlType{}, &Request{}, &Response{}, &Reverse{}),
			//nolint:staticcheck // SA1019: cel.Declarations已废弃但CEL库尚未提供替代方案
			cel.Declarations(
				decls.NewIdent("request", decls.NewObjectType("lib.Request"), nil),
				decls.NewIdent("response", decls.NewObjectType("lib.Response"), nil),
				decls.NewIdent("reverse", decls.NewObjectType("lib.Reverse"), nil),
			),
			//nolint:staticcheck // SA1019: cel.Declarations已废弃但CEL库尚未提供替代方案
			cel.Declarations(allDeclarations...),
		)
		if err != nil {
			common.LogError(i18n.Tr("webscan_cel_init_failed", err))
		}
	})
}

// GetBaseEnv 获取基础CEL环境
func GetBaseEnv() *cel.Env {
	initBaseEnv()
	return baseEnv
}

// GetBaseProgramOptions 获取基础程序选项
func GetBaseProgramOptions() []cel.ProgramOption {
	initBaseEnv()
	return baseProgramOpt
}

// ExtendEnvWithVars 扩展基础环境，添加POC特定的变量声明
func ExtendEnvWithVars(varDecls []*exprpb.Decl) (*cel.Env, error) {
	base := GetBaseEnv()
	if base == nil {
		return nil, fmt.Errorf("基础CEL环境未初始化")
	}
	if len(varDecls) == 0 {
		return base, nil
	}
	//nolint:staticcheck // SA1019: cel.Declarations已废弃但CEL库尚未提供替代方案
	return base.Extend(cel.Declarations(varDecls...))
}

// MakeVarDecl 根据变量名和表达式创建变量声明
func MakeVarDecl(key, value string) *exprpb.Decl {
	switch {
	case strings.HasPrefix(value, "randomInt"):
		//nolint:staticcheck // SA1019: decls.NewIdent已废弃但CEL库尚未提供替代方案
		return decls.NewIdent(key, decls.Int, nil)
	case strings.HasPrefix(value, "newReverse"):
		//nolint:staticcheck // SA1019: decls.NewIdent已废弃但CEL库尚未提供替代方案
		return decls.NewIdent(key, decls.NewObjectType("lib.Reverse"), nil)
	default:
		//nolint:staticcheck // SA1019: decls.NewIdent已废弃但CEL库尚未提供替代方案
		return decls.NewIdent(key, decls.String, nil)
	}
}

// Evaluate 评估 CEL 表达式
func Evaluate(env *cel.Env, expression string, params map[string]interface{}) (ref.Val, error) {
	// 空表达式默认返回 true
	if expression == "" {
		return types.Bool(true), nil
	}

	// 编译表达式
	ast, issues := env.Compile(expression)
	if issues.Err() != nil {
		return nil, fmt.Errorf("表达式编译错误: %w", issues.Err())
	}

	// 创建程序（使用缓存的程序选项）
	program, err := env.Program(ast, GetBaseProgramOptions()...)
	if err != nil {
		return nil, fmt.Errorf("程序创建错误: %w", err)
	}

	// 执行评估
	result, _, err := program.Eval(params)
	if err != nil {
		return nil, fmt.Errorf("表达式评估错误: %w", err)
	}

	return result, nil
}

// URLTypeToString 将 TargetURL 结构体转换为字符串
func URLTypeToString(u *UrlType) string {
	var builder strings.Builder

	// 处理 scheme 部分
	if u.Scheme != "" {
		builder.WriteString(u.Scheme)
		builder.WriteByte(':')
	}

	// 处理 host 部分
	if u.Scheme != "" || u.Host != "" {
		if u.Host != "" || u.Path != "" {
			builder.WriteString("//")
		}
		if host := u.Host; host != "" {
			builder.WriteString(host)
		}
	}

	// 处理 path 部分
	path := u.Path
	if path != "" && path[0] != '/' && u.Host != "" {
		builder.WriteByte('/')
	}

	// 处理相对路径
	if builder.Len() == 0 {
		if i := strings.IndexByte(path, ':'); i > -1 && strings.IndexByte(path[:i], '/') == -1 {
			builder.WriteString("./")
		}
	}
	builder.WriteString(path)

	// 处理查询参数
	if u.Query != "" {
		builder.WriteByte('?')
		builder.WriteString(u.Query)
	}

	// 处理片段标识符
	if u.Fragment != "" {
		builder.WriteByte('#')
		builder.WriteString(u.Fragment)
	}

	return builder.String()
}

// CustomLib 自定义CEL库配置
type CustomLib struct {
	envOptions     []cel.EnvOption
	programOptions []cel.ProgramOption
}

// 缓存CustomLib实例和CEL环境，避免重复注册CEL函数导致冲突
var (
	cachedCustomLib     CustomLib
	cachedCustomLibOnce sync.Once
	cachedCELEnv        *cel.Env
	cachedCELEnvOnce    sync.Once
	cachedCELEnvErr     error
)

// NewEnvOption 创建新的CEL环境配置（使用缓存避免重复注册）
func NewEnvOption() CustomLib {
	cachedCustomLibOnce.Do(func() {
		cachedCustomLib = createCustomLib()
	})
	return cachedCustomLib
}

// createCustomLib 实际创建CustomLib（只执行一次）
func createCustomLib() CustomLib {
	c := CustomLib{}

	// 收集所有函数声明
	var allDeclarations []*exprpb.Decl
	allDeclarations = append(allDeclarations, registerStringDeclarations()...)
	allDeclarations = append(allDeclarations, registerEncodingDeclarations()...)
	allDeclarations = append(allDeclarations, registerCryptoDeclarations()...)
	allDeclarations = append(allDeclarations, registerRandomDeclarations()...)
	allDeclarations = append(allDeclarations, registerMiscDeclarations()...)

	c.envOptions = []cel.EnvOption{
		cel.Container("lib"),
		cel.Types(&UrlType{}, &Request{}, &Response{}, &Reverse{}),
		//nolint:staticcheck // SA1019: cel.Declarations已废弃但CEL库尚未提供替代方案
		cel.Declarations(
			decls.NewIdent("request", decls.NewObjectType("lib.Request"), nil),
			decls.NewIdent("response", decls.NewObjectType("lib.Response"), nil),
			decls.NewIdent("reverse", decls.NewObjectType("lib.Reverse"), nil),
		),
		//nolint:staticcheck // SA1019: cel.Declarations已废弃但CEL库尚未提供替代方案
		cel.Declarations(allDeclarations...),
	}

	// 收集所有函数实现
	var allImplementations []*functions.Overload
	allImplementations = append(allImplementations, registerStringImplementations()...)
	allImplementations = append(allImplementations, registerEncodingImplementations()...)
	allImplementations = append(allImplementations, registerCryptoImplementations()...)
	allImplementations = append(allImplementations, registerRandomImplementations()...)
	allImplementations = append(allImplementations, registerMiscImplementations()...)

	c.programOptions = []cel.ProgramOption{
		//nolint:staticcheck // SA1019: cel.Functions已废弃但CEL库尚未提供替代方案
		cel.Functions(allImplementations...),
	}

	return c
}

// CompileOptions 返回环境编译选项
func (c *CustomLib) CompileOptions() []cel.EnvOption {
	return c.envOptions
}

// ProgramOptions 返回程序运行选项
// 返回空切片，函数实现通过 GetBaseProgramOptions() 在 Evaluate() 时注入
// 这避免了多次创建环境时重复注册函数导致的冲突
func (c *CustomLib) ProgramOptions() []cel.ProgramOption {
	return nil
}

// UpdateCompileOptions 更新编译选项，处理不同类型的变量声明
func (c *CustomLib) UpdateCompileOptions(args StrMap) {
	for _, item := range args {
		key, value := item.Key, item.Value

		// 根据函数前缀确定变量类型
		var declaration *exprpb.Decl
		switch {
		case strings.HasPrefix(value, "randomInt"):
			// randomInt 函数返回整型
			//nolint:staticcheck // SA1019: decls.NewIdent已废弃但CEL库尚未提供替代方案
			declaration = decls.NewIdent(key, decls.Int, nil)
		case strings.HasPrefix(value, "newReverse"):
			// newReverse 函数返回 Reverse 对象
			//nolint:staticcheck // SA1019: decls.NewIdent已废弃但CEL库尚未提供替代方案
			declaration = decls.NewIdent(key, decls.NewObjectType("lib.Reverse"), nil)
		default:
			// 默认声明为字符串类型
			//nolint:staticcheck // SA1019: decls.NewIdent已废弃但CEL库尚未提供替代方案
			declaration = decls.NewIdent(key, decls.String, nil)
		}

		//nolint:staticcheck // SA1019: cel.Declarations已废弃但CEL库尚未提供替代方案
		c.envOptions = append(c.envOptions, cel.Declarations(declaration))
	}
}

// 随机数生成器（带互斥锁保护，确保并发安全）
//
//nolint:gosec // G404: 用于生成测试数据，非加密用途
var (
	randSource = rand.New(rand.NewSource(time.Now().UnixNano()))
	randMu     sync.Mutex
)

// randomLowercase 生成指定长度的小写字母随机字符串
func randomLowercase(n int) string {
	const lowercase = "abcdefghijklmnopqrstuvwxyz"
	randMu.Lock()
	defer randMu.Unlock()
	return RandomStr(randSource, lowercase, n)
}

// randomUppercase 生成指定长度的大写字母随机字符串
func randomUppercase(n int) string {
	const uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	randMu.Lock()
	defer randMu.Unlock()
	return RandomStr(randSource, uppercase, n)
}

// randomString 生成指定长度的随机字符串（包含大小写字母和数字）
func randomString(n int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	randMu.Lock()
	defer randMu.Unlock()
	return RandomStr(randSource, charset, n)
}

// reverseCheck 检查 DNS 记录是否存在
// 使用包级pocDNSLog变量，由InitPOCConfig初始化
func reverseCheck(r *Reverse, timeout int64) bool {
	// 检查必要条件（使用包级配置变量）
	if ceyeAPI == "" || r.Domain == "" || !pocDNSLog.Load() {
		return false
	}

	// 等待指定时间
	time.Sleep(time.Second * time.Duration(timeout))

	// 提取子域名
	sub := strings.Split(r.Domain, ".")[0]

	// 构造 API 请求 TargetURL
	apiURL := fmt.Sprintf("http://api.ceye.io/v1/records?token=%s&type=dns&filter=%s",
		ceyeAPI, sub)

	// 创建并发送请求
	req, _ := http.NewRequest("GET", apiURL, nil)
	resp, err := DoRequest(req, false)
	if err != nil {
		return false
	}

	// 检查响应内容
	hasData := !bytes.Contains(resp.Body, []byte(`"data": []`))
	isOK := bytes.Contains(resp.Body, []byte(`"message": "OK"`))

	if hasData && isOK {
		common.LogDebug(apiURL)
		return true
	}
	return false
}

// RandomStr 生成指定长度的随机字符串
func RandomStr(randSource *rand.Rand, letterBytes string, n int) string {
	const (
		// 用 6 位比特表示一个字母索引
		letterIdxBits = 6
		// 生成掩码：000111111
		letterIdxMask = 1<<letterIdxBits - 1
		// 63 位能存储的字母索引数量
		letterIdxMax = 63 / letterIdxBits
	)

	// 预分配结果数组
	randBytes := make([]byte, n)

	// 使用位操作生成随机字符串
	for i, cache, remain := n-1, randSource.Int63(), letterIdxMax; i >= 0; {
		// 当可用的随机位用完时，重新获取随机数
		if remain == 0 {
			cache, remain = randSource.Int63(), letterIdxMax
		}

		// 获取字符集中的随机索引
		if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
			randBytes[i] = letterBytes[idx]
			i--
		}

		// 右移已使用的位，更新计数器
		cache >>= letterIdxBits
		remain--
	}

	return string(randBytes)
}

// DoRequest 执行 HTTP 请求
func DoRequest(req *http.Request, redirect bool) (*Response, error) {
	// 处理请求头
	if req.Body != nil && req.Body != http.NoBody {
		// 设置 Content-Length
		req.Header.Set("Content-Length", strconv.Itoa(int(req.ContentLength)))

		// 如果未指定 Content-Type，设置默认值
		if req.Header.Get("Content-Type") == "" {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
	}

	// 执行请求
	// 检查发包限制
	if canSend, reason := common.CanSendPacket(); !canSend {
		common.LogError(i18n.Tr("webscan_request_restricted", req.URL.String(), reason))
		return nil, fmt.Errorf("发包受限: %s", reason)
	}

	var (
		oResp *http.Response
		err   error
	)

	if redirect {
		oResp, err = Client.Do(req)
	} else {
		oResp, err = ClientNoRedirect.Do(req)
	}

	if err != nil {
		// HTTP请求失败，计为TCP失败
		common.GetGlobalState().IncrementTCPFailedPacketCount()
		return nil, fmt.Errorf("请求执行失败: %w", err)
	}

	// HTTP请求成功，计为TCP成功
	common.GetGlobalState().IncrementTCPSuccessPacketCount()
	defer func() { _ = oResp.Body.Close() }()

	// 解析响应
	resp, err := ParseResponse(oResp)
	if err != nil {
		common.LogError(i18n.Tr("webscan_response_parse_failed", err))
	}

	return resp, err
}

// ParseURL 解析 TargetURL 并转换为自定义 TargetURL 类型
func ParseURL(u *url.URL) *UrlType {
	return &UrlType{
		Scheme:   u.Scheme,
		Domain:   u.Hostname(),
		Host:     u.Host,
		Port:     u.Port(),
		Path:     u.EscapedPath(),
		Query:    u.RawQuery,
		Fragment: u.Fragment,
	}
}

// ParseRequest 将标准 HTTP 请求转换为自定义请求对象
func ParseRequest(oReq *http.Request) (*Request, error) {
	req := &Request{
		Method:      oReq.Method,
		URL:         ParseURL(oReq.URL),
		Headers:     make(map[string]string),
		ContentType: oReq.Header.Get("Content-Type"),
	}

	// 复制请求头
	for k := range oReq.Header {
		req.Headers[k] = oReq.Header.Get(k)
	}

	// 处理请求体
	if oReq.Body != nil && oReq.Body != http.NoBody {
		data, err := io.ReadAll(oReq.Body)
		if err != nil {
			return nil, fmt.Errorf("读取请求体失败: %w", err)
		}
		req.Body = data
		// 重新设置请求体，允许后续重复读取
		oReq.Body = io.NopCloser(bytes.NewBuffer(data))
	}

	return req, nil
}

// ParseResponse 将标准 HTTP 响应转换为自定义响应对象
func ParseResponse(oResp *http.Response) (*Response, error) {
	resp := Response{
		Status:      int32(oResp.StatusCode),
		URL:         ParseURL(oResp.Request.URL),
		Headers:     make(map[string]string),
		ContentType: oResp.Header.Get("Content-Type"),
	}

	// 复制响应头，合并多值头部为分号分隔的字符串
	for k := range oResp.Header {
		resp.Headers[k] = strings.Join(oResp.Header.Values(k), ";")
	}

	// 读取并解析响应体
	body, err := getRespBody(oResp)
	if err != nil {
		return nil, fmt.Errorf("处理响应体失败: %w", err)
	}
	resp.Body = body

	return &resp, nil
}

// getRespBody 读取 HTTP 响应体并处理可能的 gzip 压缩
func getRespBody(oResp *http.Response) ([]byte, error) {
	// 读取原始响应体
	body, err := io.ReadAll(oResp.Body)
	if err != nil && !errors.Is(err, io.EOF) && len(body) == 0 {
		return nil, err
	}

	// 处理 gzip 压缩
	if strings.Contains(oResp.Header.Get("Content-Encoding"), "gzip") {
		reader, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return body, nil // 如果解压失败，返回原始数据
		}
		defer func() { _ = reader.Close() }()

		decompressed, err := io.ReadAll(reader)
		if err != nil && !errors.Is(err, io.EOF) && len(decompressed) == 0 {
			return nil, err
		}
		if len(decompressed) == 0 && len(body) != 0 {
			return body, nil
		}
		return decompressed, nil
	}

	return body, nil
}
