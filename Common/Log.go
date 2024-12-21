package Common

import (
	"encoding/json"
	"fmt"
	"github.com/fatih/color"
	"io"
	"log"
	"os"
	"strings"
	"sync"
	"time"
)

// 记录扫描状态的全局变量
var (
	Num        int64                // 总任务数
	End        int64                // 已完成数
	Results    = make(chan *string) // 结果通道
	LogSucTime int64                // 最近成功日志时间
	LogErrTime int64                // 最近错误日志时间
	WaitTime   int64                // 等待时间
	Silent     bool                 // 静默模式
	Nocolor    bool                 // 禁用颜色
	JsonOutput bool                 // JSON输出
	LogWG      sync.WaitGroup       // 日志同步等待组
)

// JsonText JSON输出的结构体
type JsonText struct {
	Type string `json:"type"` // 消息类型
	Text string `json:"text"` // 消息内容
}

// init 初始化日志配置
func init() {
	log.SetOutput(io.Discard)
	LogSucTime = time.Now().Unix()
	go SaveLog()
}

// LogSuccess 记录成功信息
func LogSuccess(result string) {
	LogWG.Add(1)
	LogSucTime = time.Now().Unix()
	Results <- &result
}

// SaveLog 保存日志信息
func SaveLog() {
	for result := range Results {
		// 打印日志
		if !Silent {
			if Nocolor {
				fmt.Println(*result)
			} else {
				switch {
				case strings.HasPrefix(*result, "[+] 信息扫描"):
					color.Green(*result)
				case strings.HasPrefix(*result, "[+]"):
					color.Red(*result)
				default:
					fmt.Println(*result)
				}
			}
		}

		// 保存到文件
		if IsSave {
			WriteFile(*result, Outputfile)
		}
		LogWG.Done()
	}
}

// WriteFile 写入文件
func WriteFile(result string, filename string) {
	// 打开文件
	fl, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		fmt.Printf("[-] 打开文件失败 %s: %v\n", filename, err)
		return
	}
	defer fl.Close()

	if JsonOutput {
		// 解析JSON格式
		var scantype, text string
		if strings.HasPrefix(result, "[+]") || strings.HasPrefix(result, "[*]") || strings.HasPrefix(result, "[-]") {
			index := strings.Index(result[4:], " ")
			if index == -1 {
				scantype = "msg"
				text = result[4:]
			} else {
				scantype = result[4 : 4+index]
				text = result[4+index+1:]
			}
		} else {
			scantype = "msg"
			text = result
		}

		// 构造JSON对象
		jsonText := JsonText{
			Type: scantype,
			Text: text,
		}

		// 序列化JSON
		jsonData, err := json.Marshal(jsonText)
		if err != nil {
			fmt.Printf("[-] JSON序列化失败: %v\n", err)
			jsonText = JsonText{
				Type: "msg",
				Text: result,
			}
			jsonData, _ = json.Marshal(jsonText)
		}
		jsonData = append(jsonData, []byte(",\n")...)
		_, err = fl.Write(jsonData)
	} else {
		_, err = fl.Write([]byte(result + "\n"))
	}

	if err != nil {
		fmt.Printf("[-] 写入文件失败 %s: %v\n", filename, err)
	}
}

// LogError 记录错误信息
func LogError(errinfo interface{}) {
	if WaitTime == 0 {
		fmt.Printf("[*] 已完成 %v/%v %v\n", End, Num, errinfo)
	} else if (time.Now().Unix()-LogSucTime) > WaitTime && (time.Now().Unix()-LogErrTime) > WaitTime {
		fmt.Printf("[*] 已完成 %v/%v %v\n", End, Num, errinfo)
		LogErrTime = time.Now().Unix()
	}
}

// CheckErrs 检查是否为已知错误
func CheckErrs(err error) bool {
	if err == nil {
		return false
	}

	// 已知错误列表
	errs := []string{
		"closed by the remote host", "too many connections",
		"EOF", "A connection attempt failed",
		"established connection failed", "connection attempt failed",
		"Unable to read", "is not allowed to connect to this",
		"no pg_hba.conf entry",
		"No connection could be made",
		"invalid packet size",
		"bad connection",
	}

	// 检查错误是否匹配
	errLower := strings.ToLower(err.Error())
	for _, key := range errs {
		if strings.Contains(errLower, strings.ToLower(key)) {
			return true
		}
	}

	return false
}
