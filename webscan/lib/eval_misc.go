package lib

import (
	"time"

	"github.com/google/cel-go/checker/decls"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/interpreter/functions"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
)

// registerMiscDeclarations 注册杂项函数的CEL声明
func registerMiscDeclarations() []*exprpb.Decl {
	return []*exprpb.Decl{
		decls.NewFunction("wait",
			decls.NewInstanceOverload("reverse_wait_int",
				[]*exprpb.Type{decls.Any, decls.Int},
				decls.Bool)),
		decls.NewFunction("TDdate",
			decls.NewOverload("tongda_date",
				[]*exprpb.Type{},
				decls.String)),
	}
}

// registerMiscImplementations 注册杂项函数的CEL实现
func registerMiscImplementations() []*functions.Overload {
	return []*functions.Overload{
		{
			Operator: "reverse_wait_int",
			Binary: func(lhs ref.Val, rhs ref.Val) ref.Val {
				reverse, ok := lhs.Value().(*Reverse)
				if !ok || reverse == nil {
					return types.ValOrErr(lhs, "unexpected type '%v' passed to wait", lhs.Type())
				}
				timeout, ok := rhs.(types.Int)
				if !ok {
					return types.ValOrErr(rhs, "unexpected type '%v' passed to wait", rhs.Type())
				}
				return types.Bool(reverseCheck(reverse, int64(timeout)))
			},
		},
		{
			Operator: "tongda_date",
			Function: func(value ...ref.Val) ref.Val {
				return types.String(time.Now().Format("0601"))
			},
		},
	}
}
