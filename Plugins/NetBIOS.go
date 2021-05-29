package Plugins

import (
	"bytes"
	"fmt"
	"github.com/shadow1ng/fscan/common"
	"net"
	"strconv"
	"strings"
	"time"
)

var (
	UNIQUE_NAMES = map[string]string{
		"\x00": "Workstation Service",
		"\x03": "Messenger Service",
		"\x06": "RAS Server Service",
		"\x1F": "NetDDE Service",
		"\x20": "Server Service",
		"\x21": "RAS Client Service",
		"\xBE": "Network Monitor Agent",
		"\xBF": "Network Monitor Application",
		"\x1D": "Master Browser",
		"\x1B": "Domain Master Browser",
	}

	GROUP_NAMES = map[string]string{
		"\x00": "Domain Name",
		"\x1C": "Domain Controllers",
		"\x1E": "Browser Service Elections",
	}

	NetBIOS_ITEM_TYPE = map[string]string{
		"\x01\x00": "NetBIOS computer name",
		"\x02\x00": "NetBIOS domain name",
		"\x03\x00": "DNS computer name",
		"\x04\x00": "DNS domain name",
		"\x05\x00": "DNS tree name",
		"\x07\x00": "Time stamp",
	}
)

type NbnsName struct {
	unique    string
	group     string
	msg       string
	osversion string
}

func NetBIOS(info *common.HostInfo) error {
	nbname, err := NetBIOS1(info)
	var msg, isdc string

	if strings.Contains(nbname.msg, "Domain Controllers") {
		isdc = "[+]DC"
	}
	msg += fmt.Sprintf("[*] %-15s%-5s %s\\%-15s   %s", info.Host, isdc, nbname.group, nbname.unique, nbname.osversion)

	if info.Scantype == "netbios" {
		msg += "\n-------------------------------------------\n" + nbname.msg
	}
	if len(nbname.group) > 0 || len(nbname.unique) > 0 {
		common.LogSuccess(msg)
	}
	return err
}

func NetBIOS1(info *common.HostInfo) (nbname NbnsName, err error) {
	nbname, err = GetNbnsname(info)
	var payload0 []byte
	if err == nil {
		name := netbiosEncode(nbname.unique)
		payload0 = append(payload0, []byte("\x81\x00\x00D ")...)
		payload0 = append(payload0, name...)
		payload0 = append(payload0, []byte("\x00 EOENEBFACACACACACACACACACACACACA\x00")...)
	}
	realhost := fmt.Sprintf("%s:%v", info.Host, info.Ports)
	conn, err := net.DialTimeout("tcp", realhost, time.Duration(info.Timeout)*time.Second)
	if err != nil {
		return
	}
	err = conn.SetDeadline(time.Now().Add(time.Duration(info.Timeout) * time.Second))
	if err != nil {
		return
	}
	defer conn.Close()

	if info.Ports == "139" && len(payload0) > 0 {
		_, err1 := conn.Write(payload0)
		if err1 != nil {
			return
		}
		_, err1 = readbytes(conn)
		if err1 != nil {
			return
		}
	}

	payload1 := []byte("\x00\x00\x00\x85\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x18\x53\xc8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xfe\x00\x00\x00\x00\x00\x62\x00\x02\x50\x43\x20\x4e\x45\x54\x57\x4f\x52\x4b\x20\x50\x52\x4f\x47\x52\x41\x4d\x20\x31\x2e\x30\x00\x02\x4c\x41\x4e\x4d\x41\x4e\x31\x2e\x30\x00\x02\x57\x69\x6e\x64\x6f\x77\x73\x20\x66\x6f\x72\x20\x57\x6f\x72\x6b\x67\x72\x6f\x75\x70\x73\x20\x33\x2e\x31\x61\x00\x02\x4c\x4d\x31\x2e\x32\x58\x30\x30\x32\x00\x02\x4c\x41\x4e\x4d\x41\x4e\x32\x2e\x31\x00\x02\x4e\x54\x20\x4c\x4d\x20\x30\x2e\x31\x32\x00")
	payload2 := []byte("\x00\x00\x01\x0a\xff\x53\x4d\x42\x73\x00\x00\x00\x00\x18\x07\xc8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xfe\x00\x00\x40\x00\x0c\xff\x00\x0a\x01\x04\x41\x32\x00\x00\x00\x00\x00\x00\x00\x4a\x00\x00\x00\x00\x00\xd4\x00\x00\xa0\xcf\x00\x60\x48\x06\x06\x2b\x06\x01\x05\x05\x02\xa0\x3e\x30\x3c\xa0\x0e\x30\x0c\x06\x0a\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a\xa2\x2a\x04\x28\x4e\x54\x4c\x4d\x53\x53\x50\x00\x01\x00\x00\x00\x07\x82\x08\xa2\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05\x02\xce\x0e\x00\x00\x00\x0f\x00\x57\x00\x69\x00\x6e\x00\x64\x00\x6f\x00\x77\x00\x73\x00\x20\x00\x53\x00\x65\x00\x72\x00\x76\x00\x65\x00\x72\x00\x20\x00\x32\x00\x30\x00\x30\x00\x33\x00\x20\x00\x33\x00\x37\x00\x39\x00\x30\x00\x20\x00\x53\x00\x65\x00\x72\x00\x76\x00\x69\x00\x63\x00\x65\x00\x20\x00\x50\x00\x61\x00\x63\x00\x6b\x00\x20\x00\x32\x00\x00\x00\x00\x00\x57\x00\x69\x00\x6e\x00\x64\x00\x6f\x00\x77\x00\x73\x00\x20\x00\x53\x00\x65\x00\x72\x00\x76\x00\x65\x00\x72\x00\x20\x00\x32\x00\x30\x00\x30\x00\x33\x00\x20\x00\x35\x00\x2e\x00\x32\x00\x00\x00\x00\x00")
	_, err = conn.Write(payload1)
	if err != nil {
		return
	}
	_, err = readbytes(conn)
	if err != nil {
		return
	}

	_, err = conn.Write(payload2)
	if err != nil {
		return
	}
	ret, err := readbytes(conn)
	if err != nil || len(ret) < 45 {
		return
	}

	num1, err := bytetoint(ret[43:44][0])
	if err != nil {
		return
	}
	num2, err := bytetoint(ret[44:45][0])
	if err != nil {
		return
	}
	length := num1 + num2*256
	if len(ret) < 48+length {
		return
	}
	os_version := ret[47+length:]
	tmp1 := bytes.ReplaceAll(os_version, []byte{0x00, 0x00}, []byte{124})
	tmp1 = bytes.ReplaceAll(tmp1, []byte{0x00}, []byte{})
	msg1 := string(tmp1[:len(tmp1)-1])
	nbname.osversion = msg1
	index1 := strings.Index(msg1, "|")
	if index1 > 0 {
		nbname.osversion = nbname.osversion[:index1]
	}
	nbname.msg += "-------------------------------------------\n"
	nbname.msg += msg1 + "\n"
	start := bytes.Index(ret, []byte("NTLMSSP"))
	if len(ret) < start+45 {
		return
	}
	num1, err = bytetoint(ret[start+40 : start+41][0])
	if err != nil {
		return
	}
	num2, err = bytetoint(ret[start+41 : start+42][0])
	if err != nil {
		return
	}
	length = num1 + num2*256
	num1, err = bytetoint(ret[start+44 : start+45][0])
	if err != nil {
		return
	}
	offset, err := bytetoint(ret[start+44 : start+45][0])
	if err != nil || len(ret) < start+offset+length {
		return
	}
	index := start + offset
	for index < start+offset+length {
		item_type := ret[index : index+2]
		num1, err = bytetoint(ret[index+2 : index+3][0])
		if err != nil {
			return
		}
		num2, err = bytetoint(ret[index+3 : index+4][0])
		if err != nil {
			return
		}
		item_length := num1 + num2*256
		item_content := bytes.ReplaceAll(ret[index+4:index+4+item_length], []byte{0x00}, []byte{})
		index += 4 + item_length
		if string(item_type) == "\x07\x00" {
			//Time stamp, 暂时不想处理
		} else if NetBIOS_ITEM_TYPE[string(item_type)] != "" {
			nbname.msg += fmt.Sprintf("%-22s: %s\n", NetBIOS_ITEM_TYPE[string(item_type)], string(item_content))
		} else if string(item_type) == "\x00\x00" {
			break
		} else {
			nbname.msg += fmt.Sprintf("Unknown: %s\n", string(item_content))
		}
	}
	return nbname, err
}

func GetNbnsname(info *common.HostInfo) (nbname NbnsName, err error) {
	senddata1 := []byte{102, 102, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 32, 67, 75, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 0, 0, 33, 0, 1}
	realhost := fmt.Sprintf("%s:%v", info.Host, 137)
	conn, err := net.DialTimeout("udp", realhost, time.Duration(info.Timeout)*time.Second)
	if err != nil {
		return
	}
	err = conn.SetDeadline(time.Now().Add(time.Duration(info.Timeout) * time.Second))
	if err != nil {
		return
	}
	defer conn.Close()
	_, err = conn.Write(senddata1)
	if err != nil {
		return
	}
	text, err := readbytes(conn)
	if err != nil {
		return
	}
	if len(text) < 57 {
		return nbname, fmt.Errorf("no names available")
	}
	num, err := bytetoint(text[56:57][0])
	if err != nil {
		return
	}
	data := text[57:]
	var msg string
	for i := 0; i < num; i++ {
		if len(data) < 18*i+16 {
			break
		}
		name := string(data[18*i : 18*i+15])
		flag_bit := data[18*i+15 : 18*i+16]
		if GROUP_NAMES[string(flag_bit)] != "" && string(flag_bit) != "\x00" {
			msg += fmt.Sprintf("%s G %s\n", name, GROUP_NAMES[string(flag_bit)])
		} else if UNIQUE_NAMES[string(flag_bit)] != "" && string(flag_bit) != "\x00" {
			msg += fmt.Sprintf("%s U %s\n", name, UNIQUE_NAMES[string(flag_bit)])
		} else if string(flag_bit) == "\x00" || len(data) >= 18*i+18 {
			name_flags := data[18*i+16 : 18*i+18][0]
			if name_flags >= 128 {
				nbname.group = strings.Replace(name, " ", "", -1)
				msg += fmt.Sprintf("%s G %s\n", name, GROUP_NAMES[string(flag_bit)])
			} else {
				nbname.unique = strings.Replace(name, " ", "", -1)
				msg += fmt.Sprintf("%s U %s\n", name, UNIQUE_NAMES[string(flag_bit)])
			}
		} else {
			msg += fmt.Sprintf("%s \n", name)
		}
	}
	nbname.msg += msg
	return
}

func readbytes(conn net.Conn) (result []byte, err error) {
	buf := make([]byte, 4096)
	for {
		count, err := conn.Read(buf)
		if err != nil {
			break
		}
		result = append(result, buf[0:count]...)
		if count < 4096 {
			break
		}
	}
	return result, err
}

func bytetoint(text byte) (int, error) {
	num1 := fmt.Sprintf("%v", text)
	num, err := strconv.Atoi(num1)
	return num, err
}

func netbiosEncode(name string) (output []byte) {
	var names []int
	src := fmt.Sprintf("%-16s", name)
	for _, a := range src {
		char_ord := int(a)
		high_4_bits := char_ord >> 4
		low_4_bits := char_ord & 0x0f
		names = append(names, high_4_bits, low_4_bits)
	}
	for _, one := range names {
		out := (one + 0x41)
		output = append(output, byte(out))
	}
	return
}
