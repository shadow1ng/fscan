package Plugins

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/shadow1ng/fscan/common"
	"strings"
	"time"
	"bytes"
    "crypto/aes"
    "crypto/cipher"
    "encoding/base64"
)

func AesEncrypt(orig string, key string) string {
    
    origData := []byte(orig)
    k := []byte(key)
    block, _ := aes.NewCipher(k)
    
    blockSize := block.BlockSize()
    
    origData = PKCS7Padding(origData, blockSize)
    
    blockMode := cipher.NewCBCEncrypter(block, k[:blockSize])
    
    cryted := make([]byte, len(origData))
    
    blockMode.CryptBlocks(cryted, origData)
    return base64.StdEncoding.EncodeToString(cryted)
}
func AesDecrypt(cryted string, key string) string {
    
    crytedByte, _ := base64.StdEncoding.DecodeString(cryted)
    k := []byte(key)
    
    block, _ := aes.NewCipher(k)
    
    blockSize := block.BlockSize()
    
    blockMode := cipher.NewCBCDecrypter(block, k[:blockSize])
    
    orig := make([]byte, len(crytedByte))
    
    blockMode.CryptBlocks(orig, crytedByte)
    
    orig = PKCS7UnPadding(orig)
    return string(orig)
}

func PKCS7Padding(ciphertext []byte, blocksize int) []byte {
    padding := blocksize - len(ciphertext)%blocksize
    padtext := bytes.Repeat([]byte{byte(padding)}, padding)
    return append(ciphertext, padtext...)
}

func PKCS7UnPadding(origData []byte) []byte {
    length := len(origData)
    unpadding := int(origData[length-1])
    return origData[:(length - unpadding)]
}

var (
	key ="0123456789topsec"
	negotiateProtocolRequest_enc ="PnS50rhbh1nkb4JDjAnoOuFjxijddlAUbLUDi6xFyu5FGu3ui3aKZg7uqp/KfbQdSL1oEjs+/vXFWUrIaX5UGuEzNMwMbbLjRJjRqnrxi9puFZlBy92ioaf/0eVPeVsd/y21mEz0uWxYrw1Q5OJO9ibgKVFWBwH4oDSJgfwIRRI/Erob5s1WwVOTKRFwbbwKkaNi2OPSok4Qit4Be5/Ugl0P4iXal47TgUouo/Tnm/hafQuiUEnU/NHgwyax8O0WEkBBV9RQ6tEIpyGBoVXqNHBD2svOLCHXtOZ0JR8lpmBbVqVYmOnbvC/TtUphlltyD2XaI2eM6P9snMEs/tH6AjvSzy4MiArc2ehCvI8KkrzRr2Ely6+sQPikE4ILDXJV"
	sessionSetupRequest_enc ="OSuNN6y67H6V31XBAy0ObMjquG9VG30Be+HtUPppjqzUa+j1Sb1RXnlMhmNKBfdA060UgJhPAWEA0mHvgtuZINyl673/8Gly0NYdXSDAsvHsrUZZ4F/ghxQlRasFqo91RTCYyT2uR2mblhUC8HbEPjgUCmbGG4JGACJRMtHrWMAEyynCLd+RGGAUp5rceIaeEnHSUOjs1IIyjfmsi0HxdjNYlNX2BvFe5saBdjc92k3RQrYruaN6Y4eKMAZcR188ZF9UDelR3OP+guwAmOs6DfvNoo+f236V2Vfofq9y66/aKE5Z6pIF1+d5J+kPiYgyC4pt59rRR5lAW8VNS18frmeaob/f3DhikECQRxLyHs4oFiWKpVLq6Gw4eR0Xg6LR"
	treeConnectRequest_enc ="Io2yBzE7AkWMamTGFTL9O7P9ExaQpPaIEO/w+j1dFE/2ZQtpWH36u7Kv6Sj962hbLoT0EbqKeh7OzgDVkdz4DIeFapPixtiGQ8bI5Gl+NDUB3gdWDei9HNVbpGV2v/2tMF/hFesLnPLlB5m1mVweDofFPNwexEzHSaDYcBD4wddaX/N8qPdxKUx3inIMd4kKLnKyq5lyqerqG1XLvyB3XFHmWrGsg57YNMOJR4j4T3N/ydl3B92FcO6zH0qntEn4dsWinnutQznDHQ1AuV1Bag=="
	transNamedPipeRequest_enc  ="Tudw0vZes6K4es+7e3d3wwSSJ4MwynBWhFM5oH+z1gNUbPCKa6XjKwyeD+PT/PNHnp+Tl7RDHVq3TOMQgCgQBXP02QeO2oW6adqUOLIBIIyhrPdWHP2Z7wrQNuwHoS2DgSDpBneQqnJcfVjv8dYFzYENz3oIYX74IkAgHb+NCAPwNdVkDLjm5Z0qG4Qu40V/2kNgNjLP0ucy3oSoPL6FFQ=="
	trans2SessionSetupRequest_enc  ="rJEocuY9iMIM8KGtr4RlvGxp6meKD7h/ROQSKYiLQ6m5p1Qa3vrDkengdGcp930bh39NIW21eKe1Zr2dt/zXB6lYlXmQ/bgAsNEQW2cvWMs1yA2z8Ua6SIq46DynJDCQV2oWTuYKaqcy68Tno91vHsO8khooMT7bzx4EUbgN9zhKva/CkTKPXOrHBjcF9Wpv5XJDCmhLAD5EqL317Cdqgfcd+59kitYFva7N2st4aMc="
	negotiateProtocolRequest, _  = hex.DecodeString(AesDecrypt(negotiateProtocolRequest_enc, key))
	sessionSetupRequest, _       = hex.DecodeString(AesDecrypt(sessionSetupRequest_enc, key))
	treeConnectRequest, _        = hex.DecodeString(AesDecrypt(treeConnectRequest_enc, key))
	transNamedPipeRequest, _     = hex.DecodeString(AesDecrypt(transNamedPipeRequest_enc, key))
	trans2SessionSetupRequest, _ = hex.DecodeString(AesDecrypt(trans2SessionSetupRequest_enc, key))
	
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
	defer func() {
		if conn != nil {
			conn.Close()
		}
	}()
	if err != nil {
		//fmt.Printf("failed to connect to %s\n", ip)
		return err
	}
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
		result := fmt.Sprintf("[+] %s\tMS17-010\t(%s)", ip, os)
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
			result := fmt.Sprintf("[+] %s has DOUBLEPULSAR SMB IMPLANT", ip)
			common.LogSuccess(result)
		}

	} else {
		result := fmt.Sprintf("[*] %s  (%s)", ip, os)
		common.LogSuccess(result)
	}
	return err

}
