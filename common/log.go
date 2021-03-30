package common

import (
	"fmt"
	"os"
	"strings"
	"time"
)

var Num int64
var End int64
var Results = make(chan string)
var Worker = 0
var Start = true
var LogSucTime int64
var LogErr bool
var LogErrTime int64

func LogSuccess(result string) {
	Worker++
	LogSucTime = time.Now().Unix()
	if Start {
		go SaveLog()
		Start = false
	}
	Results <- result
}

func SaveLog() {
	for result := range Results {
		fmt.Println(result)
		if IsSave {
			WriteFile(result, Outputfile)
		}
		Worker--
	}
}

func WriteFile(result string, filename string) {
	var text = []byte(result + "\n")
	fl, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0777)
	if err != nil {
		fmt.Printf("Open %s error, %v\n", filename, err)
		return
	}
	_, err = fl.Write(text)
	fl.Close()
	if err != nil {
		fmt.Printf("write %s error, %v\n", filename, err)
	}
}

func WaitSave() {
	for {
		if Worker <= 0 {
			close(Results)
			return
		}
	}
}

func LogError(errinfo interface{}) {
	if LogErr {
		if (time.Now().Unix()-LogSucTime) > 10 && (time.Now().Unix()-LogErrTime) > 10 {
			fmt.Println(errinfo)
			fmt.Println(fmt.Sprintf("已完成 %v/%v", End, Num))
			LogErrTime = time.Now().Unix()
		}
	} else {
		if (time.Now().Unix()-LogSucTime) > 60 && (time.Now().Unix()-LogErrTime) > 60 {
			fmt.Println(errinfo)
			fmt.Println(fmt.Sprintf("已完成 %v/%v", End, Num))
			LogErrTime = time.Now().Unix()
		}
	}
}

func CheckErrs(err error) bool {
	if err == nil {
		return false
	}
	errs := []string{"closed by the remote host", "too many connections", "i/o timeout", "EOF", "A connection attempt failed", "established connection failed", "connection attempt failed", "Unable to read", "is not allowed to connect to this", "no pg_hba.conf entry"}
	for _, key := range errs {
		if strings.Contains(strings.ToLower(err.Error()), strings.ToLower(key)) {
			return true
		}
	}
	return false
}
