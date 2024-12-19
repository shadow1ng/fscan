package lib

import (
	"bytes"
	"compress/gzip"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker/decls"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/interpreter/functions"
	"github.com/shadow1ng/fscan/Common"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// NewEnv 创建一个新的 CEL 环境
func NewEnv(c *CustomLib) (*cel.Env, error) {
	return cel.NewEnv(cel.Lib(c))
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

	// 创建程序
	program, err := env.Program(ast)
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

// UrlTypeToString 将 TargetURL 结构体转换为字符串
func UrlTypeToString(u *UrlType) string {
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

type CustomLib struct {
	envOptions     []cel.EnvOption
	programOptions []cel.ProgramOption
}

func NewEnvOption() CustomLib {
	c := CustomLib{}

	c.envOptions = []cel.EnvOption{
		cel.Container("lib"),
		cel.Types(
			&UrlType{},
			&Request{},
			&Response{},
			&Reverse{},
		),
		cel.Declarations(
			decls.NewIdent("request", decls.NewObjectType("lib.Request"), nil),
			decls.NewIdent("response", decls.NewObjectType("lib.Response"), nil),
			decls.NewIdent("reverse", decls.NewObjectType("lib.Reverse"), nil),
		),
		cel.Declarations(
			// functions
			decls.NewFunction("bcontains",
				decls.NewInstanceOverload("bytes_bcontains_bytes",
					[]*exprpb.Type{decls.Bytes, decls.Bytes},
					decls.Bool)),
			decls.NewFunction("bmatches",
				decls.NewInstanceOverload("string_bmatches_bytes",
					[]*exprpb.Type{decls.String, decls.Bytes},
					decls.Bool)),
			decls.NewFunction("md5",
				decls.NewOverload("md5_string",
					[]*exprpb.Type{decls.String},
					decls.String)),
			decls.NewFunction("randomInt",
				decls.NewOverload("randomInt_int_int",
					[]*exprpb.Type{decls.Int, decls.Int},
					decls.Int)),
			decls.NewFunction("randomLowercase",
				decls.NewOverload("randomLowercase_int",
					[]*exprpb.Type{decls.Int},
					decls.String)),
			decls.NewFunction("randomUppercase",
				decls.NewOverload("randomUppercase_int",
					[]*exprpb.Type{decls.Int},
					decls.String)),
			decls.NewFunction("randomString",
				decls.NewOverload("randomString_int",
					[]*exprpb.Type{decls.Int},
					decls.String)),
			decls.NewFunction("base64",
				decls.NewOverload("base64_string",
					[]*exprpb.Type{decls.String},
					decls.String)),
			decls.NewFunction("base64",
				decls.NewOverload("base64_bytes",
					[]*exprpb.Type{decls.Bytes},
					decls.String)),
			decls.NewFunction("base64Decode",
				decls.NewOverload("base64Decode_string",
					[]*exprpb.Type{decls.String},
					decls.String)),
			decls.NewFunction("base64Decode",
				decls.NewOverload("base64Decode_bytes",
					[]*exprpb.Type{decls.Bytes},
					decls.String)),
			decls.NewFunction("urlencode",
				decls.NewOverload("urlencode_string",
					[]*exprpb.Type{decls.String},
					decls.String)),
			decls.NewFunction("urlencode",
				decls.NewOverload("urlencode_bytes",
					[]*exprpb.Type{decls.Bytes},
					decls.String)),
			decls.NewFunction("urldecode",
				decls.NewOverload("urldecode_string",
					[]*exprpb.Type{decls.String},
					decls.String)),
			decls.NewFunction("urldecode",
				decls.NewOverload("urldecode_bytes",
					[]*exprpb.Type{decls.Bytes},
					decls.String)),
			decls.NewFunction("substr",
				decls.NewOverload("substr_string_int_int",
					[]*exprpb.Type{decls.String, decls.Int, decls.Int},
					decls.String)),
			decls.NewFunction("wait",
				decls.NewInstanceOverload("reverse_wait_int",
					[]*exprpb.Type{decls.Any, decls.Int},
					decls.Bool)),
			decls.NewFunction("icontains",
				decls.NewInstanceOverload("icontains_string",
					[]*exprpb.Type{decls.String, decls.String},
					decls.Bool)),
			decls.NewFunction("TDdate",
				decls.NewOverload("tongda_date",
					[]*exprpb.Type{},
					decls.String)),
			decls.NewFunction("shirokey",
				decls.NewOverload("shiro_key",
					[]*exprpb.Type{decls.String, decls.String},
					decls.String)),
			decls.NewFunction("startsWith",
				decls.NewInstanceOverload("startsWith_bytes",
					[]*exprpb.Type{decls.Bytes, decls.Bytes},
					decls.Bool)),
			decls.NewFunction("istartsWith",
				decls.NewInstanceOverload("startsWith_string",
					[]*exprpb.Type{decls.String, decls.String},
					decls.Bool)),
			decls.NewFunction("hexdecode",
				decls.NewInstanceOverload("hexdecode",
					[]*exprpb.Type{decls.String},
					decls.Bytes)),
		),
	}
	c.programOptions = []cel.ProgramOption{
		cel.Functions(
			&functions.Overload{
				Operator: "bytes_bcontains_bytes",
				Binary: func(lhs ref.Val, rhs ref.Val) ref.Val {
					v1, ok := lhs.(types.Bytes)
					if !ok {
						return types.ValOrErr(lhs, "unexpected type '%v' passed to bcontains", lhs.Type())
					}
					v2, ok := rhs.(types.Bytes)
					if !ok {
						return types.ValOrErr(rhs, "unexpected type '%v' passed to bcontains", rhs.Type())
					}
					return types.Bool(bytes.Contains(v1, v2))
				},
			},
			&functions.Overload{
				Operator: "string_bmatches_bytes",
				Binary: func(lhs ref.Val, rhs ref.Val) ref.Val {
					v1, ok := lhs.(types.String)
					if !ok {
						return types.ValOrErr(lhs, "unexpected type '%v' passed to bmatch", lhs.Type())
					}
					v2, ok := rhs.(types.Bytes)
					if !ok {
						return types.ValOrErr(rhs, "unexpected type '%v' passed to bmatch", rhs.Type())
					}
					ok, err := regexp.Match(string(v1), v2)
					if err != nil {
						return types.NewErr("%v", err)
					}
					return types.Bool(ok)
				},
			},
			&functions.Overload{
				Operator: "md5_string",
				Unary: func(value ref.Val) ref.Val {
					v, ok := value.(types.String)
					if !ok {
						return types.ValOrErr(value, "unexpected type '%v' passed to md5_string", value.Type())
					}
					return types.String(fmt.Sprintf("%x", md5.Sum([]byte(v))))
				},
			},
			&functions.Overload{
				Operator: "randomInt_int_int",
				Binary: func(lhs ref.Val, rhs ref.Val) ref.Val {
					from, ok := lhs.(types.Int)
					if !ok {
						return types.ValOrErr(lhs, "unexpected type '%v' passed to randomInt", lhs.Type())
					}
					to, ok := rhs.(types.Int)
					if !ok {
						return types.ValOrErr(rhs, "unexpected type '%v' passed to randomInt", rhs.Type())
					}
					min, max := int(from), int(to)
					return types.Int(rand.Intn(max-min) + min)
				},
			},
			&functions.Overload{
				Operator: "randomLowercase_int",
				Unary: func(value ref.Val) ref.Val {
					n, ok := value.(types.Int)
					if !ok {
						return types.ValOrErr(value, "unexpected type '%v' passed to randomLowercase", value.Type())
					}
					return types.String(randomLowercase(int(n)))
				},
			},
			&functions.Overload{
				Operator: "randomUppercase_int",
				Unary: func(value ref.Val) ref.Val {
					n, ok := value.(types.Int)
					if !ok {
						return types.ValOrErr(value, "unexpected type '%v' passed to randomUppercase", value.Type())
					}
					return types.String(randomUppercase(int(n)))
				},
			},
			&functions.Overload{
				Operator: "randomString_int",
				Unary: func(value ref.Val) ref.Val {
					n, ok := value.(types.Int)
					if !ok {
						return types.ValOrErr(value, "unexpected type '%v' passed to randomString", value.Type())
					}
					return types.String(randomString(int(n)))
				},
			},
			&functions.Overload{
				Operator: "base64_string",
				Unary: func(value ref.Val) ref.Val {
					v, ok := value.(types.String)
					if !ok {
						return types.ValOrErr(value, "unexpected type '%v' passed to base64_string", value.Type())
					}
					return types.String(base64.StdEncoding.EncodeToString([]byte(v)))
				},
			},
			&functions.Overload{
				Operator: "base64_bytes",
				Unary: func(value ref.Val) ref.Val {
					v, ok := value.(types.Bytes)
					if !ok {
						return types.ValOrErr(value, "unexpected type '%v' passed to base64_bytes", value.Type())
					}
					return types.String(base64.StdEncoding.EncodeToString(v))
				},
			},
			&functions.Overload{
				Operator: "base64Decode_string",
				Unary: func(value ref.Val) ref.Val {
					v, ok := value.(types.String)
					if !ok {
						return types.ValOrErr(value, "unexpected type '%v' passed to base64Decode_string", value.Type())
					}
					decodeBytes, err := base64.StdEncoding.DecodeString(string(v))
					if err != nil {
						return types.NewErr("%v", err)
					}
					return types.String(decodeBytes)
				},
			},
			&functions.Overload{
				Operator: "base64Decode_bytes",
				Unary: func(value ref.Val) ref.Val {
					v, ok := value.(types.Bytes)
					if !ok {
						return types.ValOrErr(value, "unexpected type '%v' passed to base64Decode_bytes", value.Type())
					}
					decodeBytes, err := base64.StdEncoding.DecodeString(string(v))
					if err != nil {
						return types.NewErr("%v", err)
					}
					return types.String(decodeBytes)
				},
			},
			&functions.Overload{
				Operator: "urlencode_string",
				Unary: func(value ref.Val) ref.Val {
					v, ok := value.(types.String)
					if !ok {
						return types.ValOrErr(value, "unexpected type '%v' passed to urlencode_string", value.Type())
					}
					return types.String(url.QueryEscape(string(v)))
				},
			},
			&functions.Overload{
				Operator: "urlencode_bytes",
				Unary: func(value ref.Val) ref.Val {
					v, ok := value.(types.Bytes)
					if !ok {
						return types.ValOrErr(value, "unexpected type '%v' passed to urlencode_bytes", value.Type())
					}
					return types.String(url.QueryEscape(string(v)))
				},
			},
			&functions.Overload{
				Operator: "urldecode_string",
				Unary: func(value ref.Val) ref.Val {
					v, ok := value.(types.String)
					if !ok {
						return types.ValOrErr(value, "unexpected type '%v' passed to urldecode_string", value.Type())
					}
					decodeString, err := url.QueryUnescape(string(v))
					if err != nil {
						return types.NewErr("%v", err)
					}
					return types.String(decodeString)
				},
			},
			&functions.Overload{
				Operator: "urldecode_bytes",
				Unary: func(value ref.Val) ref.Val {
					v, ok := value.(types.Bytes)
					if !ok {
						return types.ValOrErr(value, "unexpected type '%v' passed to urldecode_bytes", value.Type())
					}
					decodeString, err := url.QueryUnescape(string(v))
					if err != nil {
						return types.NewErr("%v", err)
					}
					return types.String(decodeString)
				},
			},
			&functions.Overload{
				Operator: "substr_string_int_int",
				Function: func(values ...ref.Val) ref.Val {
					if len(values) == 3 {
						str, ok := values[0].(types.String)
						if !ok {
							return types.NewErr("invalid string to 'substr'")
						}
						start, ok := values[1].(types.Int)
						if !ok {
							return types.NewErr("invalid start to 'substr'")
						}
						length, ok := values[2].(types.Int)
						if !ok {
							return types.NewErr("invalid length to 'substr'")
						}
						runes := []rune(str)
						if start < 0 || length < 0 || int(start+length) > len(runes) {
							return types.NewErr("invalid start or length to 'substr'")
						}
						return types.String(runes[start : start+length])
					} else {
						return types.NewErr("too many arguments to 'substr'")
					}
				},
			},
			&functions.Overload{
				Operator: "reverse_wait_int",
				Binary: func(lhs ref.Val, rhs ref.Val) ref.Val {
					reverse, ok := lhs.Value().(*Reverse)
					if !ok {
						return types.ValOrErr(lhs, "unexpected type '%v' passed to 'wait'", lhs.Type())
					}
					timeout, ok := rhs.Value().(int64)
					if !ok {
						return types.ValOrErr(rhs, "unexpected type '%v' passed to 'wait'", rhs.Type())
					}
					return types.Bool(reverseCheck(reverse, timeout))
				},
			},
			&functions.Overload{
				Operator: "icontains_string",
				Binary: func(lhs ref.Val, rhs ref.Val) ref.Val {
					v1, ok := lhs.(types.String)
					if !ok {
						return types.ValOrErr(lhs, "unexpected type '%v' passed to bcontains", lhs.Type())
					}
					v2, ok := rhs.(types.String)
					if !ok {
						return types.ValOrErr(rhs, "unexpected type '%v' passed to bcontains", rhs.Type())
					}
					// 不区分大小写包含
					return types.Bool(strings.Contains(strings.ToLower(string(v1)), strings.ToLower(string(v2))))
				},
			},
			&functions.Overload{
				Operator: "tongda_date",
				Function: func(value ...ref.Val) ref.Val {
					return types.String(time.Now().Format("0601"))
				},
			},
			&functions.Overload{
				Operator: "shiro_key",
				Binary: func(key ref.Val, mode ref.Val) ref.Val {
					v1, ok := key.(types.String)
					if !ok {
						return types.ValOrErr(key, "unexpected type '%v' passed to shiro_key", key.Type())
					}
					v2, ok := mode.(types.String)
					if !ok {
						return types.ValOrErr(mode, "unexpected type '%v' passed to shiro_mode", mode.Type())
					}
					cookie := GetShrioCookie(string(v1), string(v2))
					if cookie == "" {
						return types.NewErr("%v", "key b64decode failed")
					}
					return types.String(cookie)
				},
			},
			&functions.Overload{
				Operator: "startsWith_bytes",
				Binary: func(lhs ref.Val, rhs ref.Val) ref.Val {
					v1, ok := lhs.(types.Bytes)
					if !ok {
						return types.ValOrErr(lhs, "unexpected type '%v' passed to startsWith_bytes", lhs.Type())
					}
					v2, ok := rhs.(types.Bytes)
					if !ok {
						return types.ValOrErr(rhs, "unexpected type '%v' passed to startsWith_bytes", rhs.Type())
					}
					// 不区分大小写包含
					return types.Bool(bytes.HasPrefix(v1, v2))
				},
			},
			&functions.Overload{
				Operator: "startsWith_string",
				Binary: func(lhs ref.Val, rhs ref.Val) ref.Val {
					v1, ok := lhs.(types.String)
					if !ok {
						return types.ValOrErr(lhs, "unexpected type '%v' passed to startsWith_string", lhs.Type())
					}
					v2, ok := rhs.(types.String)
					if !ok {
						return types.ValOrErr(rhs, "unexpected type '%v' passed to startsWith_string", rhs.Type())
					}
					// 不区分大小写包含
					return types.Bool(strings.HasPrefix(strings.ToLower(string(v1)), strings.ToLower(string(v2))))
				},
			},
			&functions.Overload{
				Operator: "hexdecode",
				Unary: func(lhs ref.Val) ref.Val {
					v1, ok := lhs.(types.String)
					if !ok {
						return types.ValOrErr(lhs, "unexpected type '%v' passed to hexdecode", lhs.Type())
					}
					out, err := hex.DecodeString(string(v1))
					if err != nil {
						return types.ValOrErr(lhs, "hexdecode error: %v", err)
					}
					// 不区分大小写包含
					return types.Bytes(out)
				},
			},
		),
	}
	return c
}

// CompileOptions 返回环境编译选项
func (c *CustomLib) CompileOptions() []cel.EnvOption {
	return c.envOptions
}

// ProgramOptions 返回程序运行选项
func (c *CustomLib) ProgramOptions() []cel.ProgramOption {
	return c.programOptions
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
			declaration = decls.NewIdent(key, decls.Int, nil)
		case strings.HasPrefix(value, "newReverse"):
			// newReverse 函数返回 Reverse 对象
			declaration = decls.NewIdent(key, decls.NewObjectType("lib.Reverse"), nil)
		default:
			// 默认声明为字符串类型
			declaration = decls.NewIdent(key, decls.String, nil)
		}

		c.envOptions = append(c.envOptions, cel.Declarations(declaration))
	}
}

// 初始化随机数生成器
var randSource = rand.New(rand.NewSource(time.Now().Unix()))

// randomLowercase 生成指定长度的小写字母随机字符串
func randomLowercase(n int) string {
	const lowercase = "abcdefghijklmnopqrstuvwxyz"
	return RandomStr(randSource, lowercase, n)
}

// randomUppercase 生成指定长度的大写字母随机字符串
func randomUppercase(n int) string {
	const uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	return RandomStr(randSource, uppercase, n)
}

// randomString 生成指定长度的随机字符串（包含大小写字母和数字）
func randomString(n int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	return RandomStr(randSource, charset, n)
}

// reverseCheck 检查 DNS 记录是否存在
func reverseCheck(r *Reverse, timeout int64) bool {
	// 检查必要条件
	if ceyeApi == "" || r.Domain == "" || !Common.DnsLog {
		return false
	}

	// 等待指定时间
	time.Sleep(time.Second * time.Duration(timeout))

	// 提取子域名
	sub := strings.Split(r.Domain, ".")[0]

	// 构造 API 请求 TargetURL
	apiURL := fmt.Sprintf("http://api.ceye.io/v1/records?token=%s&type=dns&filter=%s",
		ceyeApi, sub)

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
		fmt.Println(apiURL)
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
		return nil, fmt.Errorf("请求执行失败: %w", err)
	}
	defer oResp.Body.Close()

	// 解析响应
	resp, err := ParseResponse(oResp)
	if err != nil {
		Common.LogError("响应解析失败: " + err.Error())
	}

	return resp, err
}

// ParseUrl 解析 TargetURL 并转换为自定义 TargetURL 类型
func ParseUrl(u *url.URL) *UrlType {
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
		Url:         ParseUrl(oReq.URL),
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
		Url:         ParseUrl(oResp.Request.URL),
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
	if err != nil && err != io.EOF && len(body) == 0 {
		return nil, err
	}

	// 处理 gzip 压缩
	if strings.Contains(oResp.Header.Get("Content-Encoding"), "gzip") {
		reader, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return body, nil // 如果解压失败，返回原始数据
		}
		defer reader.Close()

		decompressed, err := io.ReadAll(reader)
		if err != nil && err != io.EOF && len(decompressed) == 0 {
			return nil, err
		}
		if len(decompressed) == 0 && len(body) != 0 {
			return body, nil
		}
		return decompressed, nil
	}

	return body, nil
}
