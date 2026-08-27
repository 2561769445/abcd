package gopocs

import (
	"crypto/sha1"
	"abcd/ddout"
	"abcd/structs"
	_ "embed"
	"encoding/binary"
	"fmt"
	"github.com/projectdiscovery/gologger"
	"net"
	"time"
)

//go:embed dict/mysql.txt
var mysqlUserPasswdDict string

func MysqlScan(info *structs.HostInfo) (tmperr error) {
	if structs.GlobalConfig.NoServiceBruteForce {
		return
	}
	starttime := time.Now().Unix()

	userPasswdList := sortUserPassword(info, mysqlUserPasswdDict, []string{"mysql"})

	for _, userPass := range userPasswdList {
		flag, err := MysqlConn(info, userPass.UserName, userPass.Password)
		if flag == true && err == nil {
			return err
		} else {
			tmperr = err
			if CheckErrs(err) {
				return err
			}
			if time.Now().Unix()-starttime > (int64(len(userPasswdList)) * 6) {
				gologger.AuditTimeLogger("[Go] [MYSQL] Timeout,break! %s:%v", info.Host, info.Ports)
				return err
			}
		}
	}
	gologger.AuditTimeLogger("[Go] [MYSQL] done! %s:%v", info.Host, info.Ports)
	return tmperr
}

func mysqlReadFull(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		if err != nil {
			return total, err
		}
		total += n
	}
	return total, nil
}

func mysqlReadPacket(conn net.Conn) (byte, []byte, error) {
	hdr := make([]byte, 4)
	if _, err := mysqlReadFull(conn, hdr); err != nil {
		return 0, nil, err
	}
	ln := int(hdr[0]) | int(hdr[1])<<8 | int(hdr[2])<<16
	body := make([]byte, ln)
	if _, err := mysqlReadFull(conn, body); err != nil {
		return hdr[3], nil, err
	}
	return hdr[3], body, nil
}

func mysqlScrambleNative(pass, salt []byte) []byte {
	s1 := sha1.Sum(pass)
	s2 := sha1.Sum(s1[:])
	h := sha1.New()
	h.Write(salt)
	h.Write(s2[:])
	dig := h.Sum(nil)
	out := make([]byte, len(dig))
	for i := range dig {
		out[i] = dig[i] ^ s1[i]
	}
	return out
}

// MysqlConn ? TCP ?? MySQL ???? (??? database/sql, ????????)
func MysqlConn(info *structs.HostInfo, user string, pass string) (flag bool, err error) {
	flag = false
	Host, Port, Username, Password := info.Host, info.Ports, user, pass

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%v:%v", Host, Port), 6*time.Second)
	if err != nil {
		return flag, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(8 * time.Second))

	// 1. ? Server Greeting
	_, greeting, err := mysqlReadPacket(conn)
	if err != nil {
		return flag, fmt.Errorf("read greeting: %v", err)
	}
	if len(greeting) < 32 || greeting[0] != 0x0a {
		return flag, fmt.Errorf("invalid greeting")
	}

	// 2. ? greeting ?? salt (???\0 + connid4 + salt1(8) + \0 + caps2 + charset1 + status2 + caps_hi2 + saltlen1 + 10?? + salt2)
	verEnd := -1
	for i := 1; i < len(greeting); i++ {
		if greeting[i] == 0 {
			verEnd = i
			break
		}
	}
	if verEnd < 0 || verEnd+5+8+1+2+1+2+2+1+10+12 > len(greeting) {
		return flag, fmt.Errorf("greeting too short")
	}
	pos := verEnd + 1 + 4 // ?????? connid
	var salt []byte
	salt = append(salt, greeting[pos:pos+8]...)
	pos += 8 + 1 + 2 + 1 + 2 + 2 + 1 + 10
	salt = append(salt, greeting[pos:pos+12]...)
	salt = salt[:20]

	// 3. ?? HandshakeResponse
	caps := uint32(0x000002FF | 0x00008000 | 0x00080000 | 0x00000800)
	auth := mysqlScrambleNative([]byte(Password), salt)
	data := make([]byte, 0, 96)
	var b4 [4]byte
	binary.LittleEndian.PutUint32(b4[:], caps)
	data = append(data, b4[:]...)
	binary.LittleEndian.PutUint32(b4[:], 16777216)
	data = append(data, b4[:]...)
	data = append(data, 0x21) // utf8_general_ci
	data = append(data, make([]byte, 23)...)
	data = append(data, []byte(Username)...)
	data = append(data, 0)
	data = append(data, byte(len(auth)))
	data = append(data, auth...)
	data = append(data, 0) // db
	data = append(data, []byte("mysql_native_password")...)
	data = append(data, 0)

	var hdr [4]byte
	hdr[0] = byte(len(data))
	hdr[1] = byte(len(data) >> 8)
	hdr[2] = byte(len(data) >> 16)
	hdr[3] = 1
	if _, err := conn.Write(append(hdr[:], data...)); err != nil {
		return flag, err
	}

	// 4. ?????: 0x00=OK, 0xff=ERR
	_, resp, err := mysqlReadPacket(conn)
	if err != nil {
		return flag, fmt.Errorf("auth resp: %v", err)
	}
	if len(resp) > 0 && resp[0] == 0x00 {
		flag = true
		result := fmt.Sprintf("Mysql://%v:%v:%v %v", Host, Port, Username, Password)
		showData := fmt.Sprintf("Host: %v:%v\nUsername: %v\nPassword: %v\n", Host, Port, Username, Password)
		ddout.FormatOutput(ddout.OutputMessage{
			Type:     "GoPoc",
			IP:       "",
			IPs:      nil,
			Port:     "",
			Protocol: "",
			Web:      ddout.WebInfo{},
			Finger:   nil,
			Domain:   "",
			GoPoc: ddout.GoPocsResultType{PocName: "Mysql-Login",
				Security:    "High",
				Target:      Host + ":" + Port,
				InfoLeft:    showData,
				InfoRight:   "MySQL weak password",
				Description: "Mysql???",
				ShowMsg:     result},
			AdditionalMsg: "",
		})
		GoPocWriteResult(structs.GoPocsResultType{
			PocName:     "Mysql-Login",
			Security:    "High",
			Target:      Host + ":" + Port,
			InfoLeft:    showData,
			InfoRight:   "MySQL weak password",
			Description: "Mysql???",
		})
		return flag, nil
	}
	if len(resp) > 0 && resp[0] == 0xff {
		return flag, fmt.Errorf("access denied")
	}
	return flag, fmt.Errorf("unexpected response")
}
