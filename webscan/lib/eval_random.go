package lib

import (
	"fmt"
	"math/rand" //nolint:gosec // G404: math/rand用于生成POC测试数据，非加密用途

	"github.com/google/cel-go/checker/decls"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/interpreter/functions"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
)

const maxRandomStringLength = 4096

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
				min, max := int64(from), int64(to)
				span, err := randomIntSpan(min, max)
				if err != nil {
					return types.NewErr("%v", err)
				}
				//nolint:gosec // G404: 用于生成POC测试随机数，非加密用途
				return types.Int(rand.Int63n(span) + min)
			},
		},
		{
			Operator: "randomLowercase_int",
			Unary: func(value ref.Val) ref.Val {
				n, ok := value.(types.Int)
				if !ok {
					return types.ValOrErr(value, "unexpected type '%v' passed to randomLowercase", value.Type())
				}
				length, err := validateRandomStringLength(n)
				if err != nil {
					return types.NewErr("%v", err)
				}
				return types.String(randomLowercase(length))
			},
		},
		{
			Operator: "randomUppercase_int",
			Unary: func(value ref.Val) ref.Val {
				n, ok := value.(types.Int)
				if !ok {
					return types.ValOrErr(value, "unexpected type '%v' passed to randomUppercase", value.Type())
				}
				length, err := validateRandomStringLength(n)
				if err != nil {
					return types.NewErr("%v", err)
				}
				return types.String(randomUppercase(length))
			},
		},
		{
			Operator: "randomString_int",
			Unary: func(value ref.Val) ref.Val {
				n, ok := value.(types.Int)
				if !ok {
					return types.ValOrErr(value, "unexpected type '%v' passed to randomString", value.Type())
				}
				length, err := validateRandomStringLength(n)
				if err != nil {
					return types.NewErr("%v", err)
				}
				return types.String(randomString(length))
			},
		},
	}
}

func randomIntSpan(min, max int64) (int64, error) {
	if max <= min {
		return 0, fmt.Errorf("randomInt: max(%d) must be greater than min(%d)", max, min)
	}
	const maxInt64 = int64(^uint64(0) >> 1)
	if min < 0 && max > maxInt64+min {
		return 0, fmt.Errorf("randomInt: range too large")
	}
	return max - min, nil
}

func validateRandomStringLength(n types.Int) (int, error) {
	if n < 0 || n > maxRandomStringLength {
		return 0, fmt.Errorf("random string length must be between 0 and %d", maxRandomStringLength)
	}
	return int(n), nil
}
