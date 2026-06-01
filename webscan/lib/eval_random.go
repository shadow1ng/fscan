package lib

import (
	"math/rand" //nolint:gosec // G404: math/rand用于生成POC测试数据，非加密用途

	"github.com/google/cel-go/checker/decls"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/interpreter/functions"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
)

// registerRandomDeclarations 注册随机函数的CEL声明
func registerRandomDeclarations() []*exprpb.Decl {
	return []*exprpb.Decl{
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
	}
}

// registerRandomImplementations 注册随机函数的CEL实现
func registerRandomImplementations() []*functions.Overload {
	return []*functions.Overload{
		{
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
			if max <= min {
				return types.NewErr("randomInt: max(%d) must be greater than min(%d)", max, min)
			}
			//nolint:gosec // G404: 用于生成POC测试随机数，非加密用途
			return types.Int(rand.Intn(max-min) + min)
			},
		},
		{
			Operator: "randomLowercase_int",
			Unary: func(value ref.Val) ref.Val {
				n, ok := value.(types.Int)
				if !ok {
					return types.ValOrErr(value, "unexpected type '%v' passed to randomLowercase", value.Type())
				}
				return types.String(randomLowercase(int(n)))
			},
		},
		{
			Operator: "randomUppercase_int",
			Unary: func(value ref.Val) ref.Val {
				n, ok := value.(types.Int)
				if !ok {
					return types.ValOrErr(value, "unexpected type '%v' passed to randomUppercase", value.Type())
				}
				return types.String(randomUppercase(int(n)))
			},
		},
		{
			Operator: "randomString_int",
			Unary: func(value ref.Val) ref.Val {
				n, ok := value.(types.Int)
				if !ok {
					return types.ValOrErr(value, "unexpected type '%v' passed to randomString", value.Type())
				}
				return types.String(randomString(int(n)))
			},
		},
	}
}
