package common

import (
	"os"
	"sync"

	log "github.com/sirupsen/logrus"
)

func init() {
	log.SetFormatter(&log.TextFormatter{
		DisableColors: false,
		FullTimestamp: true})
}

func LogPrint(args ...interface{}) {
	log.Println(args...)
}

func LogSuccess(result string) {
	mutex := &sync.Mutex{}
	mutex.Lock()
	log.Println(result)
	if IsSave {
		WriteFile(result, Outputfile)
	}
	mutex.Unlock()
}
func WriteFile(result string, filename string) {
	var text = []byte(result + "\n")
	fl, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0777)
	if err != nil {
		log.Println("open file error : ", err)
		return
	}
	defer fl.Close()
	_, err = fl.Write(text)
	if err != nil {
		log.Println("write file error ", err)
	}
}

//err := ioutil.WriteFile(filename, text, 0666)
//if err!= nil{
//	fmt.Println(err)
//}
//var f *os.File
//var err error
//if checkFileIsExist(filename) { //如果文件存在
//	f, err = os.OpenFile(filename, os.O_APPEND, 0666) //打开文件
//	fmt.Println("文件存在")
//} else {
//	f, err = os.Create(filename) //创建文件
//	fmt.Println("文件不存在")
//}
//func checkFileIsExist(filename string) bool {
//	var exist = true
//	if _, err := os.Stat(filename); os.IsNotExist(err) {
//		exist = false
//	}
//	return exist
//}
