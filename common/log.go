package common

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

var Num int64
var End int64
var Results = make(chan *string)
var LogSucTime int64
var LogErrTime int64
var WaitTime int64
var Silent bool
var Nocolor bool
var JsonOutput bool
var LogWG sync.WaitGroup

type JsonText struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

func init() {
	log.SetOutput(io.Discard)
	LogSucTime = time.Now().Unix()
	go SaveLog()
}

func LogSuccess(result string) {
	LogWG.Add(1)
	LogSucTime = time.Now().Unix()
	Results <- &result
}

func SaveLog() {
	for result := range Results {
		if !Silent {
			if Nocolor {
				fmt.Println(*result)
			} else {
				if strings.HasPrefix(*result, "[+] InfoScan") {
					color.Green(*result)
				} else if strings.HasPrefix(*result, "[+]") {
					color.Red(*result)
				} else {
					fmt.Println(*result)
				}
			}
		}
		if IsSave {
			WriteFile(*result, Outputfile)
		}
		LogWG.Done()
	}
}

func WriteFile(result string, filename string) {
	fl, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		fmt.Printf("Open %s error, %v\n", filename, err)
		return
	}
	if JsonOutput {
		var scantype string
		var text string
		if strings.HasPrefix(result, "[+]") || strings.HasPrefix(result, "[*]") || strings.HasPrefix(result, "[-]") {
			//找到第二个空格的位置
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
		jsonText := JsonText{
			Type: scantype,
			Text: text,
		}
		jsonData, err := json.Marshal(jsonText)
		if err != nil {
			fmt.Println(err)
			jsonText = JsonText{
				Type: "msg",
				Text: result,
			}
			jsonData, err = json.Marshal(jsonText)
			if err != nil {
				fmt.Println(err)
				jsonData = []byte(result)
			}
		}
		jsonData = append(jsonData, []byte(",\n")...)
		_, err = fl.Write(jsonData)
	} else {
		_, err = fl.Write([]byte(result + "\n"))
	}
	fl.Close()
	if err != nil {
		fmt.Printf("Write %s error, %v\n", filename, err)
	}
}

func LogError(errinfo interface{}) {
	if WaitTime == 0 {
		fmt.Printf("已完成 %v/%v %v \n", End, Num, errinfo)
	} else if (time.Now().Unix()-LogSucTime) > WaitTime && (time.Now().Unix()-LogErrTime) > WaitTime {
		fmt.Printf("已完成 %v/%v %v \n", End, Num, errinfo)
		LogErrTime = time.Now().Unix()
	}
}

func CheckErrs(err error) bool {
	if err == nil {
		return false
	}
	errs := []string{
		"closed by the remote host", "too many connections",
		"i/o timeout", "EOF", "A connection attempt failed",
		"established connection failed", "connection attempt failed",
		"Unable to read", "is not allowed to connect to this",
		"no pg_hba.conf entry",
		"No connection could be made",
		"invalid packet size",
		"bad connection",
	}
	for _, key := range errs {
		if strings.Contains(strings.ToLower(err.Error()), strings.ToLower(key)) {
			return true
		}
	}
	return false
}
