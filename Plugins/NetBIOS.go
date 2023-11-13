package Plugins

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/shadow1ng/fscan/common"
	"gopkg.in/yaml.v3"
	"net"
	"strconv"
	"strings"
	"time"
)

var errNetBIOS = errors.New("netbios error")

func NetBIOS(info *common.HostInfo) error {
	netbios, _ := NetBIOS1(info)
	output := netbios.String()
	if len(output) > 0 {
		result := fmt.Sprintf("[*] NetBios %-15s %s", info.Host, output)
		common.LogSuccess(result)
		return nil
	}
	return errNetBIOS
}

func NetBIOS1(info *common.HostInfo) (netbios NetBiosInfo, err error) {
	netbios, err = GetNbnsname(info)
	var payload0 []byte
	if netbios.ServerService != "" || netbios.WorkstationService != "" {
		ss := netbios.ServerService
		if ss == "" {
			ss = netbios.WorkstationService
		}
		name := netbiosEncode(ss)
		payload0 = append(payload0, []byte("\x81\x00\x00D ")...)
		payload0 = append(payload0, name...)
		payload0 = append(payload0, []byte("\x00 EOENEBFACACACACACACACACACACACACA\x00")...)
	}
	realhost := fmt.Sprintf("%s:%v", info.Host, info.Ports)
	var conn net.Conn
	conn, err = common.WrapperTcpWithTimeout("tcp", realhost, time.Duration(common.Timeout)*time.Second)
	if err != nil {
		return
	}
	defer conn.Close()
	err = conn.SetDeadline(time.Now().Add(time.Duration(common.Timeout) * time.Second))
	if err != nil {
		return
	}

	if info.Ports == "139" && len(payload0) > 0 {
		_, err1 := conn.Write(payload0)
		if err1 != nil {
			return
		}
		_, err1 = ReadBytes(conn)
		if err1 != nil {
			return
		}
	}

	_, err = conn.Write(NegotiateSMBv1Data1)
	if err != nil {
		return
	}
	_, err = ReadBytes(conn)
	if err != nil {
		return
	}

	_, err = conn.Write(NegotiateSMBv1Data2)
	if err != nil {
		return
	}
	var ret []byte
	ret, err = ReadBytes(conn)
	if err != nil {
		return
	}
	netbios2, err := ParseNTLM(ret)
	JoinNetBios(&netbios, &netbios2)
	return
}

func GetNbnsname(info *common.HostInfo) (netbios NetBiosInfo, err error) {
	senddata1 := []byte{102, 102, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 32, 67, 75, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 0, 0, 33, 0, 1}
	//senddata1 := []byte("ff\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00 CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00!\x00\x01")
	realhost := fmt.Sprintf("%s:137", info.Host)
	conn, err := net.DialTimeout("udp", realhost, time.Duration(common.Timeout)*time.Second)
	if err != nil {
		return
	}
	defer conn.Close()
	err = conn.SetDeadline(time.Now().Add(time.Duration(common.Timeout) * time.Second))
	if err != nil {
		return
	}
	_, err = conn.Write(senddata1)
	if err != nil {
		return
	}
	text, _ := ReadBytes(conn)
	netbios, err = ParseNetBios(text)
	return
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

var (
	UNIQUE_NAMES = map[string]string{
		"\x00": "WorkstationService",
		"\x03": "Messenger Service",
		"\x06": "RAS Server Service",
		"\x1F": "NetDDE Service",
		"\x20": "ServerService",
		"\x21": "RAS Client Service",
		"\xBE": "Network Monitor Agent",
		"\xBF": "Network Monitor Application",
		"\x1D": "Master Browser",
		"\x1B": "Domain Master Browser",
	}

	GROUP_NAMES = map[string]string{
		"\x00": "DomainName",
		"\x1C": "DomainControllers",
		"\x1E": "Browser Service Elections",
	}

	NetBIOS_ITEM_TYPE = map[string]string{
		"\x01\x00": "NetBiosComputerName",
		"\x02\x00": "NetBiosDomainName",
		"\x03\x00": "ComputerName",
		"\x04\x00": "DomainName",
		"\x05\x00": "DNS tree name",
		"\x07\x00": "Time stamp",
	}
	NegotiateSMBv1Data1 = []byte{
		0x00, 0x00, 0x00, 0x85, 0xFF, 0x53, 0x4D, 0x42, 0x72, 0x00, 0x00, 0x00, 0x00, 0x18, 0x53, 0xC8,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFE,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x62, 0x00, 0x02, 0x50, 0x43, 0x20, 0x4E, 0x45, 0x54, 0x57, 0x4F,
		0x52, 0x4B, 0x20, 0x50, 0x52, 0x4F, 0x47, 0x52, 0x41, 0x4D, 0x20, 0x31, 0x2E, 0x30, 0x00, 0x02,
		0x4C, 0x41, 0x4E, 0x4D, 0x41, 0x4E, 0x31, 0x2E, 0x30, 0x00, 0x02, 0x57, 0x69, 0x6E, 0x64, 0x6F,
		0x77, 0x73, 0x20, 0x66, 0x6F, 0x72, 0x20, 0x57, 0x6F, 0x72, 0x6B, 0x67, 0x72, 0x6F, 0x75, 0x70,
		0x73, 0x20, 0x33, 0x2E, 0x31, 0x61, 0x00, 0x02, 0x4C, 0x4D, 0x31, 0x2E, 0x32, 0x58, 0x30, 0x30,
		0x32, 0x00, 0x02, 0x4C, 0x41, 0x4E, 0x4D, 0x41, 0x4E, 0x32, 0x2E, 0x31, 0x00, 0x02, 0x4E, 0x54,
		0x20, 0x4C, 0x4D, 0x20, 0x30, 0x2E, 0x31, 0x32, 0x00,
	}
	NegotiateSMBv1Data2 = []byte{
		0x00, 0x00, 0x01, 0x0A, 0xFF, 0x53, 0x4D, 0x42, 0x73, 0x00, 0x00, 0x00, 0x00, 0x18, 0x07, 0xC8,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFE,
		0x00, 0x00, 0x40, 0x00, 0x0C, 0xFF, 0x00, 0x0A, 0x01, 0x04, 0x41, 0x32, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x4A, 0x00, 0x00, 0x00, 0x00, 0x00, 0xD4, 0x00, 0x00, 0xA0, 0xCF, 0x00, 0x60,
		0x48, 0x06, 0x06, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x02, 0xA0, 0x3E, 0x30, 0x3C, 0xA0, 0x0E, 0x30,
		0x0C, 0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0A, 0xA2, 0x2A, 0x04,
		0x28, 0x4E, 0x54, 0x4C, 0x4D, 0x53, 0x53, 0x50, 0x00, 0x01, 0x00, 0x00, 0x00, 0x07, 0x82, 0x08,
		0xA2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x05, 0x02, 0xCE, 0x0E, 0x00, 0x00, 0x00, 0x0F, 0x00, 0x57, 0x00, 0x69, 0x00, 0x6E, 0x00,
		0x64, 0x00, 0x6F, 0x00, 0x77, 0x00, 0x73, 0x00, 0x20, 0x00, 0x53, 0x00, 0x65, 0x00, 0x72, 0x00,
		0x76, 0x00, 0x65, 0x00, 0x72, 0x00, 0x20, 0x00, 0x32, 0x00, 0x30, 0x00, 0x30, 0x00, 0x33, 0x00,
		0x20, 0x00, 0x33, 0x00, 0x37, 0x00, 0x39, 0x00, 0x30, 0x00, 0x20, 0x00, 0x53, 0x00, 0x65, 0x00,
		0x72, 0x00, 0x76, 0x00, 0x69, 0x00, 0x63, 0x00, 0x65, 0x00, 0x20, 0x00, 0x50, 0x00, 0x61, 0x00,
		0x63, 0x00, 0x6B, 0x00, 0x20, 0x00, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x57, 0x00, 0x69, 0x00,
		0x6E, 0x00, 0x64, 0x00, 0x6F, 0x00, 0x77, 0x00, 0x73, 0x00, 0x20, 0x00, 0x53, 0x00, 0x65, 0x00,
		0x72, 0x00, 0x76, 0x00, 0x65, 0x00, 0x72, 0x00, 0x20, 0x00, 0x32, 0x00, 0x30, 0x00, 0x30, 0x00,
		0x33, 0x00, 0x20, 0x00, 0x35, 0x00, 0x2E, 0x00, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
)

type NetBiosInfo struct {
	GroupName          string
	WorkstationService string `yaml:"WorkstationService"`
	ServerService      string `yaml:"ServerService"`
	DomainName         string `yaml:"DomainName"`
	DomainControllers  string `yaml:"DomainControllers"`
	ComputerName       string `yaml:"ComputerName"`
	OsVersion          string `yaml:"OsVersion"`
	NetDomainName      string `yaml:"NetBiosDomainName"`
	NetComputerName    string `yaml:"NetBiosComputerName"`
}

func (info *NetBiosInfo) String() (output string) {
	var text string
	//ComputerName 信息比较全
	if info.ComputerName != "" {
		if !strings.Contains(info.ComputerName, ".") && info.GroupName != "" {
			text = fmt.Sprintf("%s\\%s", info.GroupName, info.ComputerName)
		} else {
			text = info.ComputerName
		}
	} else {
		//组信息
		if info.DomainName != "" {
			text += info.DomainName
			text += "\\"
		} else if info.NetDomainName != "" {
			text += info.NetDomainName
			text += "\\"
		}
		//机器名
		if info.ServerService != "" {
			text += info.ServerService
		} else if info.WorkstationService != "" {
			text += info.WorkstationService
		} else if info.NetComputerName != "" {
			text += info.NetComputerName
		}
	}
	if text == "" {
	} else if info.DomainControllers != "" {
		output = fmt.Sprintf("[+] DC:%-24s", text)
	} else {
		output = fmt.Sprintf("%-30s", text)
	}
	if info.OsVersion != "" {
		output += "      " + info.OsVersion
	}
	return
}

func ParseNetBios(input []byte) (netbios NetBiosInfo, err error) {
	if len(input) < 57 {
		err = errNetBIOS
		return
	}
	data := input[57:]
	var num int
	num, err = bytetoint(input[56:57][0])
	if err != nil {
		return
	}
	var msg string
	for i := 0; i < num; i++ {
		if len(data) < 18*i+16 {
			break
		}
		name := string(data[18*i : 18*i+15])
		flag_bit := data[18*i+15 : 18*i+16]
		if GROUP_NAMES[string(flag_bit)] != "" && string(flag_bit) != "\x00" {
			msg += fmt.Sprintf("%s: %s\n", GROUP_NAMES[string(flag_bit)], name)
		} else if UNIQUE_NAMES[string(flag_bit)] != "" && string(flag_bit) != "\x00" {
			msg += fmt.Sprintf("%s: %s\n", UNIQUE_NAMES[string(flag_bit)], name)
		} else if string(flag_bit) == "\x00" || len(data) >= 18*i+18 {
			name_flags := data[18*i+16 : 18*i+18][0]
			if name_flags >= 128 {
				msg += fmt.Sprintf("%s: %s\n", GROUP_NAMES[string(flag_bit)], name)
			} else {
				msg += fmt.Sprintf("%s: %s\n", UNIQUE_NAMES[string(flag_bit)], name)
			}
		} else {
			msg += fmt.Sprintf("%s \n", name)
		}
	}
	if len(msg) == 0 {
		err = errNetBIOS
		return
	}
	err = yaml.Unmarshal([]byte(msg), &netbios)
	if netbios.DomainName != "" {
		netbios.GroupName = netbios.DomainName
	}
	return
}

func ParseNTLM(ret []byte) (netbios NetBiosInfo, err error) {
	if len(ret) < 47 {
		err = errNetBIOS
		return
	}
	var num1, num2 int
	num1, err = bytetoint(ret[43:44][0])
	if err != nil {
		return
	}
	num2, err = bytetoint(ret[44:45][0])
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
	ostext := string(tmp1[:len(tmp1)-1])
	ss := strings.Split(ostext, "|")
	netbios.OsVersion = ss[0]
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
	_, err = bytetoint(ret[start+44 : start+45][0])
	if err != nil {
		return
	}
	offset, err := bytetoint(ret[start+44 : start+45][0])
	if err != nil || len(ret) < start+offset+length {
		return
	}
	var msg string
	index := start + offset
	for index < start+offset+length {
		item_type := ret[index : index+2]
		num1, err = bytetoint(ret[index+2 : index+3][0])
		if err != nil {
			continue
		}
		num2, err = bytetoint(ret[index+3 : index+4][0])
		if err != nil {
			continue
		}
		item_length := num1 + num2*256
		item_content := bytes.ReplaceAll(ret[index+4:index+4+item_length], []byte{0x00}, []byte{})
		index += 4 + item_length
		if string(item_type) == "\x07\x00" {
			//Time stamp, 不需要输出
		} else if NetBIOS_ITEM_TYPE[string(item_type)] != "" {
			msg += fmt.Sprintf("%s: %s\n", NetBIOS_ITEM_TYPE[string(item_type)], string(item_content))
		} else if string(item_type) == "\x00\x00" {
			break
		}
	}
	err = yaml.Unmarshal([]byte(msg), &netbios)
	return
}

func JoinNetBios(netbios1, netbios2 *NetBiosInfo) *NetBiosInfo {
	netbios1.ComputerName = netbios2.ComputerName
	netbios1.NetDomainName = netbios2.NetDomainName
	netbios1.NetComputerName = netbios2.NetComputerName
	if netbios2.DomainName != "" {
		netbios1.DomainName = netbios2.DomainName
	}
	netbios1.OsVersion = netbios2.OsVersion
	return netbios1
}
