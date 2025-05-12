package WebScan

import (
	"crypto/md5"
	"fmt"
	"github.com/shadow1ng/fscan/Common"
	"github.com/shadow1ng/fscan/WebScan/info"
	"regexp"
)

// CheckDatas 存储HTTP响应的检查数据
type CheckDatas struct {
	Body    []byte // 响应体
	Headers string // 响应头
}

// InfoCheck 检查URL的指纹信息
func InfoCheck(Url string, CheckData *[]CheckDatas) []string {
	var matchedInfos []string

	// 遍历检查数据
	for _, data := range *CheckData {
		// 规则匹配检查
		for _, rule := range info.RuleDatas {
			var matched bool
			var err error

			// 根据规则类型选择匹配内容
			switch rule.Type {
			case "code":
				matched, err = regexp.MatchString(rule.Rule, string(data.Body))
			default:
				matched, err = regexp.MatchString(rule.Rule, data.Headers)
			}

			// 处理匹配错误
			if err != nil {
				Common.LogError(fmt.Sprintf("规则匹配错误 [%s]: %v", rule.Name, err))
				continue
			}

			// 添加匹配成功的规则名
			if matched {
				matchedInfos = append(matchedInfos, rule.Name)
			}
		}

		// MD5匹配检查暂时注释
		/*
		   if flag, name := CalcMd5(data.Body); flag {
		       matchedInfos = append(matchedInfos, name)
		   }
		*/
	}

	// 去重处理
	matchedInfos = removeDuplicateElement(matchedInfos)

	// 输出结果
	if len(matchedInfos) > 0 {
		result := fmt.Sprintf("发现指纹 目标: %-25v 指纹: %s", Url, matchedInfos)
		Common.LogInfo(result)
		return matchedInfos
	}

	return []string{}
}

// CalcMd5 计算内容的MD5并与指纹库比对
func CalcMd5(Body []byte) (bool, string) {
	contentMd5 := fmt.Sprintf("%x", md5.Sum(Body))

	// 比对MD5指纹库
	for _, md5Info := range info.Md5Datas {
		if contentMd5 == md5Info.Md5Str {
			return true, md5Info.Name
		}
	}

	return false, ""
}

// removeDuplicateElement 移除切片中的重复元素
func removeDuplicateElement(items []string) []string {
	// 预分配空间
	result := make([]string, 0, len(items))
	seen := make(map[string]struct{}, len(items))

	// 使用map去重
	for _, item := range items {
		if _, exists := seen[item]; !exists {
			seen[item] = struct{}{}
			result = append(result, item)
		}
	}

	return result
}
