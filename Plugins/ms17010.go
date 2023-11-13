package Plugins

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/shadow1ng/fscan/common"
	"strings"
	"time"
)

var (
	negotiateProtocolRequest_enc  = "G8o+kd/4y8chPCaObKK8L9+tJVFBb7ntWH/EXJ74635V3UTXA4TFOc6uabZfuLr0Xisnk7OsKJZ2Xdd3l8HNLdMOYZXAX5ZXnMC4qI+1d/MXA2TmidXeqGt8d9UEF5VesQlhP051GGBSldkJkVrP/fzn4gvLXcwgAYee3Zi2opAvuM6ScXrMkcbx200ThnOOEx98/7ArteornbRiXQjnr6dkJEUDTS43AW6Jl3OK2876Yaz5iYBx+DW5WjiLcMR+b58NJRxm4FlVpusZjBpzEs4XOEqglk6QIWfWbFZYgdNLy3WaFkkgDjmB1+6LhpYSOaTsh4EM0rwZq2Z4Lr8TE5WcPkb/JNsWNbibKlwtNtp94fIYvAWgxt5mn/oXpfUD"
	sessionSetupRequest_enc       = "52HeCQEbsSwiSXg98sdD64qyRou0jARlvfQi1ekDHS77Nk/8dYftNXlFahLEYWIxYYJ8u53db9OaDfAvOEkuox+p+Ic1VL70r9Q5HuL+NMyeyeN5T5el07X5cT66oBDJnScs1XdvM6CBRtj1kUs2h40Z5Vj9EGzGk99SFXjSqbtGfKFBp0DhL5wPQKsoiXYLKKh9NQiOhOMWHYy/C+Iwhf3Qr8d1Wbs2vgEzaWZqIJ3BM3z+dhRBszQoQftszC16TUhGQc48XPFHN74VRxXgVe6xNQwqrWEpA4hcQeF1+QqRVHxuN+PFR7qwEcU1JbnTNISaSrqEe8GtRo1r2rs7+lOFmbe4qqyUMgHhZ6Pwu1bkhrocMUUzWQBogAvXwFb8"
	treeConnectRequest_enc        = "+b/lRcmLzH0c0BYhiTaYNvTVdYz1OdYYDKhzGn/3T3P4b6pAR8D+xPdlb7O4D4A9KMyeIBphDPmEtFy44rtto2dadFoit350nghebxbYA0pTCWIBd1kN0BGMEidRDBwLOpZE6Qpph/DlziDjjfXUz955dr0cigc9ETHD/+f3fELKsopTPkbCsudgCs48mlbXcL13GVG5cGwKzRuP4ezcdKbYzq1DX2I7RNeBtw/vAlYh6etKLv7s+YyZ/r8m0fBY9A57j+XrsmZAyTWbhPJkCg=="
	transNamedPipeRequest_enc     = "k/RGiUQ/tw1yiqioUIqirzGC1SxTAmQmtnfKd1qiLish7FQYxvE+h4/p7RKgWemIWRXDf2XSJ3K0LUIX0vv1gx2eb4NatU7Qosnrhebz3gUo7u25P5BZH1QKdagzPqtitVjASpxIjB3uNWtYMrXGkkuAm8QEitberc+mP0vnzZ8Nv/xiiGBko8O4P/wCKaN2KZVDLbv2jrN8V/1zY6fvWA=="
	trans2SessionSetupRequest_enc = "JqNw6PUKcWOYFisUoUCyD24wnML2Yd8kumx9hJnFWbhM2TQkRvKHsOMWzPVfggRrLl8sLQFqzk8bv8Rpox3uS61l480Mv7HdBPeBeBeFudZMntXBUa4pWUH8D9EXCjoUqgAdvw6kGbPOOKUq3WmNb0GDCZapqQwyUKKMHmNIUMVMAOyVfKeEMJA6LViGwyvHVMNZ1XWLr0xafKfEuz4qoHiDyVWomGjJt8DQd6+jgLk="
	negotiateProtocolRequest, _   = hex.DecodeString(AesDecrypt(negotiateProtocolRequest_enc, key))
	sessionSetupRequest, _        = hex.DecodeString(AesDecrypt(sessionSetupRequest_enc, key))
	treeConnectRequest, _         = hex.DecodeString(AesDecrypt(treeConnectRequest_enc, key))
	transNamedPipeRequest, _      = hex.DecodeString(AesDecrypt(transNamedPipeRequest_enc, key))
	trans2SessionSetupRequest, _  = hex.DecodeString(AesDecrypt(trans2SessionSetupRequest_enc, key))
)

func MS17010(info *common.HostInfo) error {
	if common.IsBrute {
		return nil
	}
	err := MS17010Scan(info)
	if err != nil {
		errlog := fmt.Sprintf("[-] Ms17010 %v %v", info.Host, err)
		common.LogError(errlog)
	}
	return err
}

func MS17010Scan(info *common.HostInfo) error {
	ip := info.Host
	// connecting to a host in LAN if reachable should be very quick
	conn, err := common.WrapperTcpWithTimeout("tcp", ip+":445", time.Duration(common.Timeout)*time.Second)
	if err != nil {
		//fmt.Printf("failed to connect to %s\n", ip)
		return err
	}
	defer conn.Close()
	err = conn.SetDeadline(time.Now().Add(time.Duration(common.Timeout) * time.Second))
	if err != nil {
		//fmt.Printf("failed to connect to %s\n", ip)
		return err
	}
	_, err = conn.Write(negotiateProtocolRequest)
	if err != nil {
		return err
	}
	reply := make([]byte, 1024)
	// let alone half packet
	if n, err := conn.Read(reply); err != nil || n < 36 {
		return err
	}

	if binary.LittleEndian.Uint32(reply[9:13]) != 0 {
		// status != 0
		return err
	}

	_, err = conn.Write(sessionSetupRequest)
	if err != nil {
		return err
	}
	n, err := conn.Read(reply)
	if err != nil || n < 36 {
		return err
	}

	if binary.LittleEndian.Uint32(reply[9:13]) != 0 {
		// status != 0
		//fmt.Printf("can't determine whether %s is vulnerable or not\n", ip)
		var Err = errors.New("can't determine whether target is vulnerable or not")
		return Err
	}

	// extract OS info
	var os string
	sessionSetupResponse := reply[36:n]
	if wordCount := sessionSetupResponse[0]; wordCount != 0 {
		// find byte count
		byteCount := binary.LittleEndian.Uint16(sessionSetupResponse[7:9])
		if n != int(byteCount)+45 {
			fmt.Println("[-]", ip+":445", "ms17010 invalid session setup AndX response")
		} else {
			// two continous null bytes indicates end of a unicode string
			for i := 10; i < len(sessionSetupResponse)-1; i++ {
				if sessionSetupResponse[i] == 0 && sessionSetupResponse[i+1] == 0 {
					os = string(sessionSetupResponse[10:i])
					os = strings.Replace(os, string([]byte{0x00}), "", -1)
					break
				}
			}
		}

	}
	userID := reply[32:34]
	treeConnectRequest[32] = userID[0]
	treeConnectRequest[33] = userID[1]
	// TODO change the ip in tree path though it doesn't matter
	_, err = conn.Write(treeConnectRequest)
	if err != nil {
		return err
	}
	if n, err := conn.Read(reply); err != nil || n < 36 {
		return err
	}

	treeID := reply[28:30]
	transNamedPipeRequest[28] = treeID[0]
	transNamedPipeRequest[29] = treeID[1]
	transNamedPipeRequest[32] = userID[0]
	transNamedPipeRequest[33] = userID[1]

	_, err = conn.Write(transNamedPipeRequest)
	if err != nil {
		return err
	}
	if n, err := conn.Read(reply); err != nil || n < 36 {
		return err
	}

	if reply[9] == 0x05 && reply[10] == 0x02 && reply[11] == 0x00 && reply[12] == 0xc0 {
		//fmt.Printf("%s\tMS17-010\t(%s)\n", ip, os)
		//if runtime.GOOS=="windows" {fmt.Printf("%s\tMS17-010\t(%s)\n", ip, os)
		//} else{fmt.Printf("\033[33m%s\tMS17-010\t(%s)\033[0m\n", ip, os)}
		result := fmt.Sprintf("[+] MS17-010 %s\t(%s)", ip, os)
		common.LogSuccess(result)
		defer func() {
			if common.SC != "" {
				MS17010EXP(info)
			}
		}()
		// detect present of DOUBLEPULSAR SMB implant
		trans2SessionSetupRequest[28] = treeID[0]
		trans2SessionSetupRequest[29] = treeID[1]
		trans2SessionSetupRequest[32] = userID[0]
		trans2SessionSetupRequest[33] = userID[1]

		_, err = conn.Write(trans2SessionSetupRequest)
		if err != nil {
			return err
		}
		if n, err := conn.Read(reply); err != nil || n < 36 {
			return err
		}

		if reply[34] == 0x51 {
			result := fmt.Sprintf("[+] MS17-010 %s has DOUBLEPULSAR SMB IMPLANT", ip)
			common.LogSuccess(result)
		}

	} else {
		result := fmt.Sprintf("[*] OsInfo %s\t(%s)", ip, os)
		common.LogSuccess(result)
	}
	return err

}
