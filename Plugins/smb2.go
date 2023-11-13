package Plugins

import (
	"fmt"
	"github.com/shadow1ng/fscan/common"
	"net"
	"os"
	"strings"
	"time"

	"github.com/hirochachacha/go-smb2"
)

func SmbScan2(info *common.HostInfo) (tmperr error) {
	if common.IsBrute {
		return nil
	}
	hasprint := false
	starttime := time.Now().Unix()
	hash := common.HashBytes
	for _, user := range common.Userdict["smb"] {
	PASS:
		for _, pass := range common.Passwords {
			pass = strings.Replace(pass, "{user}", user, -1)
			flag, err, flag2 := Smb2Con(info, user, pass, hash, hasprint)
			if flag2 {
				hasprint = true
			}
			if flag == true {
				var result string
				if common.Domain != "" {
					result = fmt.Sprintf("[+] SMB2 %v:%v:%v\\%v ", info.Host, info.Ports, common.Domain, user)
				} else {
					result = fmt.Sprintf("[+] SMB2 %v:%v:%v ", info.Host, info.Ports, user)
				}
				if len(hash) > 0 {
					result += "hash: " + common.Hash
				} else {
					result += pass
				}
				common.LogSuccess(result)
				return err
			} else {
				var errlog string
				if len(common.Hash) > 0 {
					errlog = fmt.Sprintf("[-] smb2 %v:%v %v %v %v", info.Host, 445, user, common.Hash, err)
				} else {
					errlog = fmt.Sprintf("[-] smb2 %v:%v %v %v %v", info.Host, 445, user, pass, err)
				}
				errlog = strings.Replace(errlog, "\n", " ", -1)
				common.LogError(errlog)
				tmperr = err
				if common.CheckErrs(err) {
					return err
				}
				if time.Now().Unix()-starttime > (int64(len(common.Userdict["smb"])*len(common.Passwords)) * common.Timeout) {
					return err
				}
			}
			if len(common.Hash) > 0 {
				break PASS
			}
		}
	}
	return tmperr
}

func Smb2Con(info *common.HostInfo, user string, pass string, hash []byte, hasprint bool) (flag bool, err error, flag2 bool) {
	conn, err := net.DialTimeout("tcp", info.Host+":445", time.Duration(common.Timeout)*time.Second)
	if err != nil {
		return
	}
	defer conn.Close()
	initiator := smb2.NTLMInitiator{
		User:   user,
		Domain: common.Domain,
	}
	if len(hash) > 0 {
		initiator.Hash = hash
	} else {
		initiator.Password = pass
	}
	d := &smb2.Dialer{
		Initiator: &initiator,
	}

	s, err := d.Dial(conn)
	if err != nil {
		return
	}
	defer s.Logoff()
	names, err := s.ListSharenames()
	if err != nil {
		return
	}
	if !hasprint {
		var result string
		if common.Domain != "" {
			result = fmt.Sprintf("[*] SMB2-shares %v:%v:%v\\%v ", info.Host, info.Ports, common.Domain, user)
		} else {
			result = fmt.Sprintf("[*] SMB2-shares %v:%v:%v ", info.Host, info.Ports, user)
		}
		if len(hash) > 0 {
			result += "hash: " + common.Hash
		} else {
			result += pass
		}
		result = fmt.Sprintf("%v shares: %v", result, names)
		common.LogSuccess(result)
		flag2 = true
	}
	fs, err := s.Mount("C$")
	if err != nil {
		return
	}
	defer fs.Umount()
	path := `Windows\win.ini`
	f, err := fs.OpenFile(path, os.O_RDONLY, 0666)
	if err != nil {
		return
	}
	defer f.Close()
	flag = true
	return
	//bs, err := ioutil.ReadAll(f)
	//if err != nil {
	//	return
	//}
	//fmt.Println(string(bs))
	//return

}

//if info.Path == ""{
//}
//path = info.Path
//f, err := fs.OpenFile(path, os.O_RDONLY, 0666)
//if err != nil {
//	return
//}
//flag = true
//_, err = f.Seek(0, io.SeekStart)
//if err != nil {
//	return
//}
//bs, err := ioutil.ReadAll(f)
//if err != nil {
//	return
//}
//fmt.Println(string(bs))
//return
//f, err := fs.Create(`Users\Public\Videos\hello.txt`)
//if err != nil {
//	return
//}
//flag = true
//
//_, err = f.Write([]byte("Hello world!"))
//if err != nil {
//	return
//}
//
//_, err = f.Seek(0, io.SeekStart)
//if err != nil {
//	return
//}
//bs, err := ioutil.ReadAll(f)
//if err != nil {
//	return
//}
//fmt.Println(string(bs))
//return
