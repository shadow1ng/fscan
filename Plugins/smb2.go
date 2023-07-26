package Plugins

import (
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/shadow1ng/fscan/common"

	"github.com/hirochachacha/go-smb2"
)

func SmbScan2(info common.HostInfo, flags common.Flags) (tmperr error) {
	if flags.IsBrute {
		return nil
	}
	hasprint := false
	starttime := time.Now().Unix()
	hash := flags.HashBytes
	for _, user := range common.Userdict["smb"] {
	PASS:
		for _, pass := range common.Passwords {
			pass = strings.Replace(pass, "{user}", user, -1)
			flag, err, flag2 := Smb2Con(info, flags, user, pass, hash, hasprint)
			if flag2 {
				hasprint = true
			}
			if flag {
				var result string
				if flags.Domain != "" {
					result = fmt.Sprintf("[+] SMB2:%v:%v:%v\\%v ", info.Host, info.Ports, flags.Domain, user)
				} else {
					result = fmt.Sprintf("[+] SMB2:%v:%v:%v ", info.Host, info.Ports, user)
				}
				if len(hash) > 0 {
					result += "hash: " + flags.Hash
				} else {
					result += pass
				}
				common.LogSuccess(result)
				return err
			} else {
				var errlog string
				if len(flags.Hash) > 0 {
					errlog = fmt.Sprintf("[-] smb2 %v:%v %v %v %v", info.Host, 445, user, flags.Hash, err)
				} else {
					errlog = fmt.Sprintf("[-] smb2 %v:%v %v %v %v", info.Host, 445, user, pass, err)
				}
				errlog = strings.Replace(errlog, "\n", " ", -1)
				common.LogError(errlog)
				tmperr = err
				if common.CheckErrs(err) {
					return err
				}
				if time.Now().Unix()-starttime > (int64(len(common.Userdict["smb"])*len(common.Passwords)) * flags.Timeout) {
					return err
				}
			}
			if len(flags.Hash) > 0 {
				break PASS
			}
		}
	}
	return tmperr
}

func Smb2Con(info common.HostInfo, flags common.Flags, user string, pass string, hash []byte, hasprint bool) (flag bool, err error, flag2 bool) {
	conn, err := net.DialTimeout("tcp", info.Host+":445", time.Duration(flags.Timeout)*time.Second)
	defer func() {
		if conn != nil {
			conn.Close()
		}
	}()
	if err != nil {
		return
	}
	initiator := smb2.NTLMInitiator{
		User:   user,
		Domain: flags.Domain,
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
		if flags.Domain != "" {
			result = fmt.Sprintf("[*] SMB2-shares:%v:%v:%v\\%v ", info.Host, info.Ports, flags.Domain, user)
		} else {
			result = fmt.Sprintf("[*] SMB2-shares:%v:%v:%v ", info.Host, info.Ports, user)
		}
		if len(hash) > 0 {
			result += "hash: " + flags.Hash
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

}
