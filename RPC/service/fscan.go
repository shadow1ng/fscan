package service

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/shadow1ng/fscan/Common"
	"github.com/shadow1ng/fscan/Core"
	pb "github.com/shadow1ng/fscan/RPC/lib"
)

type FscanService struct {
	pb.UnimplementedFscanServiceServer
	scanMutex  sync.Mutex
	isScanning int32 // 原子变量，用于标记是否正在扫描
}

func (s *FscanService) StartScan(ctx context.Context, req *pb.StartScanRequest) (*pb.StartScanResponse, error) {
	if !atomic.CompareAndSwapInt32(&s.isScanning, 0, 1) {
		return &pb.StartScanResponse{
			TaskId:  "",
			Message: "已有扫描任务正在运行，请稍后重试",
		}, nil
	}

	taskID := "uuid"

	go func(taskID string, req *pb.StartScanRequest) {
		defer atomic.StoreInt32(&s.isScanning, 0)

		s.scanMutex.Lock()
		defer s.scanMutex.Unlock()

		Common.LogDebug("异步执行扫描请求，目标: " + req.Arg + ", " + req.Secret)

		var info Common.HostInfo
		if err := Common.FlagFromRemote(&info, req.Arg); err != nil {
			return
		}
		if err := Common.Parse(&info); err != nil {
			return
		}
		//TODO: 结果保存需要在output模块中设计
		if err := Common.InitOutput(); err != nil {
			Common.LogError(fmt.Sprintf("初始化输出系统失败: %v", err))
			return
		}

		Core.Scan(info)
	}(taskID, req)

	return &pb.StartScanResponse{
		TaskId:  taskID,
		Message: "扫描任务已启动",
	}, nil
}

// GetScanResults 用于获取指定任务 ID 的扫描结果。
// 参数：
// - ctx：请求上下文。
// - req：TaskResultsRequest，包含任务 ID。
// 返回值：
// - TaskResultsResponse：包含结果列表、任务状态等信息。
// - error：执行中出现的错误信息。
func (s *FscanService) GetScanResults(ctx context.Context, req *pb.TaskResultsRequest) (*pb.TaskResultsResponse, error) {
	// TODO: 实现根据任务 ID 查询任务结果，可以从缓存、数据库或临时文件中获取。
	// 此处为模拟数据

	result := &pb.ScanResult{
		Time:        time.Now().Format(time.RFC3339),
		Type:        "port",
		Target:      "192.168.1.1:80",
		Status:      "open",
		DetailsJson: `{"banner":"nginx"}`,
	}

	return &pb.TaskResultsResponse{
		TaskId:   req.TaskId,
		Results:  []*pb.ScanResult{result},
		Finished: true, // TODO: 判断任务是否真正完成
	}, nil
}

// StreamScanResults 用于通过流式返回任务扫描结果，适合长时间扫描过程。
// 参数：
// - req：TaskResultsRequest，包含任务 ID。
// - stream：用于向客户端持续推送结果。
// 返回值：
// - error：执行中出现的错误信息。
func (s *FscanService) StreamScanResults(req *pb.TaskResultsRequest, stream pb.FscanService_StreamScanResultsServer) error {
	// TODO: 根据任务 ID 逐步查询任务结果，并通过 stream.Send 发送给客户端。
	// 可以监听任务进度，逐步推送最新结果。

	for i := 0; i < 5; i++ {
		result := &pb.ScanResult{
			Time:        time.Now().Format(time.RFC3339),
			Type:        "vuln",
			Target:      "192.168.1.1",
			Status:      "found",
			DetailsJson: `{"vuln":"CVE-2021-12345"}`,
		}
		if err := stream.Send(result); err != nil {
			return err
		}
		time.Sleep(1 * time.Second) // 模拟异步推送过程
	}
	return nil
}
