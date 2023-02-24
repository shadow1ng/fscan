package common

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// 多线程暴力破解模块

type BruteList struct {
	user string
	pass string
}

type BruteFunc interface {
	Attack(info *HostInfo, user string, pass string, timeout int64) (flag bool, err error)
}

type BruteThreader struct {
	wg        sync.WaitGroup
	mutex     sync.Mutex
	signal    bool
	num       int
	bruteType string
	bruteFunc BruteFunc
	info      *HostInfo
	timeout   int64
}

func InitBruteThread(bruteType string, info *HostInfo, timeout int64, bruteFunc BruteFunc) (b *BruteThreader) {

	bt := &BruteThreader{
		num:       0,
		bruteType: bruteType,
		bruteFunc: bruteFunc,
		info:      info,
		timeout:   timeout,
	}

	return bt
}

func (t *BruteThreader) Run() (tmperr error) {

	brList, total := t.generateData()
	for i := 0; i < BruteThread; i++ {
		t.wg.Add(1)
		go t.worker(brList, total)
	}
	close(brList)
	go func() {
		t.wg.Wait()
		t.signal = true
	}()
	for !t.signal {
	}

	return tmperr
}

func (t *BruteThreader) generateData() (data chan BruteList, total int) {
	var all = len(Userdict[t.bruteType]) * len(Passwords)
	brList := make(chan BruteList, all)
	for _, user := range Userdict[t.bruteType] {
		for _, pass := range Passwords {
			pass = strings.Replace(pass, "{user}", user, -1)
			brList <- BruteList{user, pass}
		}
	}
	return brList, all
}

func (t *BruteThreader) worker(brList chan BruteList, all int) (tmperr error) {
	defer t.wg.Done()
	starttime := time.Now().Unix()
	for one := range brList {
		if t.signal == true {
			return
		}
		go t.incrNum(&t.num, &t.mutex)
		user, pass := one.user, one.pass
		flag, err := t.bruteFunc.Attack(t.info, user, pass, t.timeout)
		if flag == true && err == nil {
			var result string
			if Domain != "" {
				result = fmt.Sprintf("[+] %v:%v:%v:%v\\%v %v", t.bruteType, t.info.Host, t.info.Ports, Domain, user, pass)
			} else {
				result = fmt.Sprintf("[+] %v:%v:%v:%v %v", t.bruteType, t.info.Host, t.info.Ports, user, pass)
			}
			LogSuccess(result)
			t.signal = true
			return
		} else {
			errlog := fmt.Sprintf("[-] (%v/%v) %v %v:%v %v %v %v", t.num, all, t.bruteType, t.info.Host, t.info.Ports, user, pass, err)
			LogError(errlog)
			tmperr = err
			if CheckErrs(err) {
				return err
			}
			if time.Now().Unix()-starttime > (int64(all) * t.timeout) {
				return err
			}
		}
	}
	return
}

func (t *BruteThreader) incrNum(num *int, mutex *sync.Mutex) {
	mutex.Lock()
	*num = *num + 1
	mutex.Unlock()
}
