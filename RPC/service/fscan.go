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
	// 获取扫描结果
	results, err := Common.GetResults()
	if err != nil {
		// 记录详细错误信息
		Common.LogError(fmt.Sprintf("读取结果失败: %v", err))
		return nil, fmt.Errorf("读取结果失败: %w", err)
	}

	// 创建一个用于存储转换后的pb扫描结果的切片
	pbResults := make([]*pb.ScanResult, 0, len(results))

	// 遍历每一项结果，进行转换
	for _, r := range results {
		// 尝试将详情转换为Struct
		detailsStruct, err := structpb.NewStruct(r.Details)
		if err != nil {
			// 记录转换失败的详细信息，并跳过当前项
			Common.LogError(fmt.Sprintf("转换为 Struct 失败 (Target: %s, Type: %s): %v", r.Target, r.Type, err))
			continue
		}

		// 将转换后的结果添加到 pbResults
		pbResults = append(pbResults, &pb.ScanResult{
			Time:        r.Time.Format(time.RFC3339), // 使用 RFC3339 格式化时间
			Type:        string(r.Type),
			Target:      r.Target,
			Status:      r.Status,
			DetailsJson: detailsStruct,
		})
	}

	// 通过原子操作判断扫描是否完成
	finished := atomic.LoadInt32(&s.isScanning) == 0

	// 如果任务未完成，计算 Total 和 End，仅在需要时计算
	var total, end int64
	if !finished {
		total = Common.Num
		end = Common.End
	}

	// 返回响应
	return &pb.TaskResultsResponse{
		Results:  pbResults,
		Finished: finished,
		Total:    total, // 返回 Total
		End:      end,   // 返回 End
	}, nil
}
