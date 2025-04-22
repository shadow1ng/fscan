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
	structpb "google.golang.org/protobuf/types/known/structpb"
)

type FscanService struct {
	pb.UnimplementedFscanServiceServer
	scanMutex     sync.Mutex
	isScanning    int32
	scanStartTime time.Time // 记录扫描开始时间
}

func (s *FscanService) StartScan(ctx context.Context, req *pb.StartScanRequest) (*pb.StartScanResponse, error) {
	if !atomic.CompareAndSwapInt32(&s.isScanning, 0, 1) {
		return &pb.StartScanResponse{
			TaskId:  "current",
			Message: "已有扫描任务正在运行，请稍后重试",
		}, nil
	}

	s.scanStartTime = time.Now() // 记录任务开始时间

	go func(req *pb.StartScanRequest) {
		defer atomic.StoreInt32(&s.isScanning, 0)

		s.scanMutex.Lock()
		defer s.scanMutex.Unlock()

		Common.LogDebug("异步执行扫描请求，目标: " + req.Arg)

		var info Common.HostInfo
		if err := Common.FlagFromRemote(&info, req.Arg); err != nil {
			return
		}
		if err := Common.Parse(&info); err != nil {
			return
		}
		if err := Common.CloseOutput(); err != nil {
			Common.LogError(fmt.Sprintf("关闭输出系统失败: %v", err))
			return
		}
		if err := Common.InitOutput(); err != nil {
			Common.LogError(fmt.Sprintf("初始化输出系统失败: %v", err))
			return
		}

		Core.Scan(info)

		Common.LogDebug("扫描任务完成")
	}(req)

	return &pb.StartScanResponse{
		TaskId:  "current",
		Message: "成功启动扫描任务",
	}, nil
}

func (s *FscanService) GetScanResults(ctx context.Context, req *pb.TaskResultsRequest) (*pb.TaskResultsResponse, error) {
	results, err := Common.GetResults()
	if err != nil {
		return nil, fmt.Errorf("读取结果失败: %w", err)
	}

	pbResults := make([]*pb.ScanResult, 0, len(results))
	for _, r := range results {
		detailsStruct, err := structpb.NewStruct(r.Details)
		if err != nil {
			Common.LogError(fmt.Sprintf("转换为 Struct 失败: %v", err))
			continue
		}

		pbResults = append(pbResults, &pb.ScanResult{
			Time:        r.Time.Format(time.RFC3339),
			Type:        string(r.Type),
			Target:      r.Target,
			Status:      r.Status,
			DetailsJson: detailsStruct,
		})
	}

	finished := atomic.LoadInt32(&s.isScanning) == 0
	return &pb.TaskResultsResponse{
		TaskId:   req.Filter.TaskId,
		Results:  pbResults,
		Finished: finished,
	}, nil
}
