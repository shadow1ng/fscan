package rpc

import (
	"context"
	"log"
	"net"
	"net/http"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	pb "github.com/shadow1ng/fscan/RPC/lib"
	"github.com/shadow1ng/fscan/RPC/service"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// 暴露的启动函数（可供外部调用）
func StartHTTPServer() {
	go runGRPCServer() // 启动 gRPC 服务
	if err := runHTTPGateway(); err != nil {
		log.Fatalf("HTTP 启动失败: %v", err)
	}
}

// 启动 gRPC 服务
func runGRPCServer() {
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("监听失败: %v", err)
	}
	s := grpc.NewServer()
	pb.RegisterFscanServiceServer(s, &service.FscanService{})
	log.Println("✅ gRPC 服务已启动，端口 50051")
	if err := s.Serve(lis); err != nil {
		log.Fatalf("gRPC 启动失败: %v", err)
	}
}

// 启动 HTTP Gateway 服务
func runHTTPGateway() error {
	ctx := context.Background()
	mux := runtime.NewServeMux()
	opts := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}

	err := pb.RegisterFscanServiceHandlerFromEndpoint(ctx, mux, "localhost:50051", opts)
	if err != nil {
		return err
	}

	// 包裹 mux，加上 CORS 支持
	handler := allowCORS(mux)

	log.Println("✅ HTTP Gateway 已启动，端口 8080")
	return http.ListenAndServe(":8080", handler)
}

// 添加 CORS 支持
func allowCORS(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		h.ServeHTTP(w, r)
	})
}
