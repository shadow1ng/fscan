package lib

import (
	"bytes"
	"regexp"
	"strings"

	"github.com/google/cel-go/checker/decls"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/interpreter/functions"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
)

// registerStringDeclarations 注册字符串相关的CEL函数声明
func registerStringDeclarations() []*exprpb.Decl {
	return []*exprpb.Decl{
		decls.NewFunction("bcontains",
			decls.NewInstanceOverload("bytes_bcontains_bytes",
				[]*exprpb.Type{decls.Bytes, decls.Bytes},
				decls.Bool)),
		decls.NewFunction("bmatches",
			decls.NewInstanceOverload("string_bmatches_bytes",
				[]*exprpb.Type{decls.String, decls.Bytes},
				decls.Bool)),
		decls.NewFunction("icontains",
			decls.NewInstanceOverload("icontains_string",
				[]*exprpb.Type{decls.String, decls.String},
				decls.Bool)),
		decls.NewFunction("substr",
			decls.NewOverload("substr_string_int_int",
				[]*exprpb.Type{decls.String, decls.Int, decls.Int},
				decls.String)),
		decls.NewFunction("startsWith",
			decls.NewInstanceOverload("startsWith_bytes",
				[]*exprpb.Type{decls.Bytes, decls.Bytes},
				decls.Bool)),
		decls.NewFunction("istartsWith",
			decls.NewInstanceOverload("startsWith_string",
				[]*exprpb.Type{decls.String, decls.String},
				decls.Bool)),
	}
}

// registerStringImplementations 注册字符串相关的CEL函数实现
func registerStringImplementations() []*functions.Overload {
	return []*functions.Overload{
		{
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
		{
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
				pattern := string(v1)
				var re *regexp.Regexp
				if cached, found := regexCache.Load(pattern); found {
					re, _ = cached.(*regexp.Regexp)
				} else {
					compiled, err := regexp.Compile(pattern)
					if err != nil {
						return types.NewErr("%v", err)
					}
					actual, _ := regexCache.LoadOrStore(pattern, compiled)
					re, _ = actual.(*regexp.Regexp)
				}
				return types.Bool(re.Match(v2))
			},
		},
		{
			Operator: "icontains_string",
			Binary: func(lhs ref.Val, rhs ref.Val) ref.Val {
				v1, ok := lhs.(types.String)
				if !ok {
					return types.ValOrErr(lhs, "unexpected type '%v' passed to icontains", lhs.Type())
				}
				v2, ok := rhs.(types.String)
				if !ok {
					return types.ValOrErr(rhs, "unexpected type '%v' passed to icontains", rhs.Type())
				}
				// 不区分大小写包含
				return types.Bool(strings.Contains(strings.ToLower(string(v1)), strings.ToLower(string(v2))))
			},
		},
		{
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
					if start < 0 || length < 0 || start > types.Int(len(runes)) || length > types.Int(len(runes))-start {
						return types.NewErr("invalid start or length to 'substr'")
					}
					return types.String(runes[int(start):int(start+length)])
				}
				return types.NewErr("invalid argument count to 'substr'")
			},
		},
		{
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
				return types.Bool(bytes.HasPrefix(v1, v2))
			},
		},
		{
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
				// 不区分大小写
				return types.Bool(strings.HasPrefix(strings.ToLower(string(v1)), strings.ToLower(string(v2))))
			},
		},
	}
}
