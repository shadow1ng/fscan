package WebScan

import (
	"crypto/md5"
	"fmt"
	"github.com/shadow1ng/fscan/WebScan/info"
	"github.com/shadow1ng/fscan/common"
	"regexp"
	"strings"
)

type CheckDatas struct {
	Body    []byte
	Headers string
}

func InfoCheck(Url string, CheckData []CheckDatas) {
	var matched bool
	var infoname []string

	for _, data := range CheckData {
		for _, rule := range info.RuleDatas {
			if rule.Type == "code" {
				matched, _ = regexp.MatchString(rule.Rule, string(data.Body))
			} else {
				matched, _ = regexp.MatchString(rule.Rule, data.Headers)
			}
			if matched == true {
				infoname = append(infoname, rule.Name)
			}
		}
		flag, name := CalcMd5(data.Body)

		if flag == true {
			infoname = append(infoname, name)
		}
	}

	infostr := RemoveMore(infoname)

	if len(infoname) > 0 {
		result := fmt.Sprintf("[+] InfoScan:%-25v %s ", Url, infostr)
		common.LogSuccess(result)
	}
}

func CalcMd5(Body []byte) (bool, string) {
	has := md5.Sum(Body)
	md5str := fmt.Sprintf("%x", has)
	for _, md5data := range info.Md5Datas {
		if md5str == md5data.Md5Str {
			return true, md5data.Name
		}
	}
	return false, ""
}

func RemoveMore(a []string) (infostr string) {
	var ret []string
	for i := 0; i < len(a); i++ {
		if (i > 0 && a[i-1] == a[i]) || len(a[i]) == 0 {
			continue
		}
		ret = append(ret, a[i])
	}
	infostr = strings.ReplaceAll(fmt.Sprintf("%s ", ret), "[", "")
	infostr = strings.ReplaceAll(infostr, "]", "")
	return
}
