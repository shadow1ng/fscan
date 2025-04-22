package rpc

import (
	"context"
	"net"
	"net/http"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/shadow1ng/fscan/Common"
	pb "github.com/shadow1ng/fscan/RPC/lib"
	"github.com/shadow1ng/fscan/RPC/service"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// 启动 gRPC + HTTP Gateway 服务（仅当设置了 API 地址时）
func StartApiServer() error {
	if Common.ApiAddr == "" {
		return nil
	}

	grpcAddr := "127.0.0.1:50051"
	httpAddr := validateHTTPAddr(Common.ApiAddr, ":8088")

	go runGRPCServer(grpcAddr)

	if err := runHTTPGateway(httpAddr, grpcAddr); err != nil {
		Common.LogError("HTTP 启动失败: " + err.Error())
		return err
	}

	return nil
}

// 启动 gRPC 服务
func runGRPCServer(addr string) {
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		Common.LogError("监听失败: " + err.Error())
		return
	}
	s := grpc.NewServer()
	pb.RegisterFscanServiceServer(s, &service.FscanService{})
	Common.LogSuccess("✅ gRPC 服务已启动，地址: " + addr)
	if err := s.Serve(lis); err != nil {
		Common.LogError("gRPC 启动失败: " + err.Error())
	}
}

// 启动 HTTP Gateway
func runHTTPGateway(httpAddr, grpcAddr string) error {
	ctx := context.Background()
	mux := runtime.NewServeMux()
	opts := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}

	err := pb.RegisterFscanServiceHandlerFromEndpoint(ctx, mux, grpcAddr, opts)
	if err != nil {
		return err
	}

	// 使用中间件包装 mux
	handler := applyMiddlewares(mux)

	Common.LogSuccess("✅ HTTP Gateway 已启动，地址: " + httpAddr)
	return http.ListenAndServe(httpAddr, handler)
}

// 注册 HTTP 中间件
func applyMiddlewares(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		handler.ServeHTTP(w, r)
	})
}

// 校验监听地址格式，格式非法使用默认
func validateHTTPAddr(input, fallback string) string {
	if input == "" {
		Common.LogInfo("未指定 API 地址，使用默认地址: " + fallback)
		return fallback
	}
	_, _, err := net.SplitHostPort(input)
	if err != nil {
		Common.LogError("无效的 API 地址格式 [" + input + "]，使用默认地址: " + fallback)
		return fallback
	}
	return input
}
