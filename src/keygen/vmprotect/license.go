package vmprotect

import (
	"bytes"
	"crypto/sha1"
	"encoding/base64"
	_ "encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"math/rand"
	"strconv"
	"strings"
	"time"
)

type License struct {
	Name, Email          string
	Expiration, MaxBuild time.Time
	HardwareId           []byte
	RunningTimeLimit     int
	UserData             []byte
	ProductCode          string
	Version              int
}

type Config struct {
	Algorithm   string
	Bits        int
	Private     string
	Modules     string
	ProductCode string
}

func base10Encode(str []byte) string {
	var result = new(big.Int)
	for _, r := range str {
		result.Mul(result, big.NewInt(256))
		result.Add(result, big.NewInt(int64(r)))
	}

	return result.String()
}

func base10Decode(data *big.Int) string {
	var buffer bytes.Buffer

	var res string
	for {
		if data.Cmp(big.NewInt(0)) <= 0 {
			break
		}
		var m = new(big.Int)
		data.DivMod(data, big.NewInt(256), m)
		res = string(m.Uint64()&0xff) + res

		var _buffer bytes.Buffer
		_buffer.WriteByte(uint8(m.Uint64() & 0xff))
		_buffer.Write(buffer.Bytes())
		buffer = _buffer
	}

	return buffer.String()
}

func powmod(paramBase string, paramExponent string, paramModules string) (*big.Int, error) {
	var base = new(big.Int)
	if _, success := base.SetString(paramBase, 10); !success {
		return nil, errors.New(fmt.Sprintf("Error in powmod, can't convert paramBase: %v", paramBase))
	}

	var exponent = new(big.Int)
	if _, success := exponent.SetString(paramExponent, 10); !success {
		return nil, errors.New(fmt.Sprintf("Error in powmod, can't convert paramExponent: %v", paramExponent))
	}

	var modulus = new(big.Int)
	if _, success := modulus.SetString(paramModules, 10); !success {
		return nil, errors.New(fmt.Sprintf("Error in powmod, can't convert paramModules: %v", paramModules))
	}

	zero := big.NewInt(0)

	if modulus.Cmp(zero) == 0 {
		return nil, errors.New("Modulus is zero. ")
	}

	if exponent.Cmp(zero) == 0 {
		return nil, errors.New("Exponent is zero. ")
	}

	var square = new(big.Int)
	square.Mod(base, modulus)
	var result = big.NewInt(1)

	for {
		if exponent.Cmp(big.NewInt(0)) <= 0 {
			break
		}

		var tmpExp = new(big.Int)
		tmpExp.Mod(exponent, big.NewInt(2))

		if tmpExp.Cmp(big.NewInt(0)) != 0 {
			var tmpResult = result
			tmpResult.Mul(result, square)
			result.Mod(tmpResult, modulus)
		}

		var tmpSquare = square
		square.Mod(tmpSquare.Mul(square, square), modulus)
		exponent.Div(exponent, big.NewInt(2))
	}

	return result, nil
}

func decodeSerial(strBin, public, modulus string) (string, error) {
	tmpModules, err := base64.StdEncoding.DecodeString(modulus)
	if err != nil {
		return "", errors.New(fmt.Sprintf("Error in decodeSerial, can't base64 decode modulus: %v", modulus))
	}

	tmpPublic, err := base64.StdEncoding.DecodeString(public)
	if err != nil {
		return "", errors.New(fmt.Sprintf("Error in decodeSerial, can't base64 decode public: %v", public))
	}

	res, err := powmod(base10Encode([]byte(strBin)), base10Encode(tmpPublic), base10Encode(tmpModules))
	if err != nil {
		return "", err
	}

	return base10Decode(res), nil
}

func packSerial(license License) ([]byte, error) {
	var ln = bytes.NewBuffer([]byte{})
	// 1. version
	ln.WriteByte(1)
	ln.WriteByte(1)
	// 2. username
	lenName := len(license.Name)
	if lenName > 0 {
		if lenName > 255 {
			return nil, errors.New("License->Name too long")
		}

		ln.WriteByte(2)
		ln.WriteByte(byte(lenName))
		ln.WriteString(license.Name)
	}
	// 3. e-mail
	lenEmail := len(license.Email)
	if lenEmail > 0 {
		if lenEmail > 255 {
			return nil, errors.New("License->Email too long")
		}

		ln.WriteByte(3)
		ln.WriteByte(byte(lenEmail))
		ln.WriteString(license.Email)
	}
	// 4. hardware_id
	hardwareIdLen := len(license.HardwareId)
	if hardwareIdLen > 0 {
		if hardwareIdLen % 4 != 0 {
			return nil, errors.New("Invalid HWID (not multiple of 4): " + strconv.Itoa(hardwareIdLen))
		}

		ln.WriteByte(4)
		ln.WriteByte(byte(hardwareIdLen))
		ln.Write(license.HardwareId)
	}
	// 5. date of expiration
	if !license.Expiration.IsZero() {
		year := license.Expiration.Year()
		month := license.Expiration.Month()
		day := license.Expiration.Day()
		ln.WriteByte(5)
		ln.WriteByte(byte(day))
		ln.WriteByte(byte(month))
		ln.WriteByte(byte(year % 256))
		ln.WriteByte(byte(year / 256))
	}
	// 6. running time limit
	if license.RunningTimeLimit > 0 {
		if license.RunningTimeLimit > 255 {
			return nil, errors.New("Running time limit is incorrect: " + strconv.Itoa(license.RunningTimeLimit))
		}

		ln.WriteByte(6)
		ln.WriteByte(byte(license.RunningTimeLimit))
	}
	// 7. product code
	productCodeLen := len(license.ProductCode)
	if productCodeLen > 0 {
		pc, err := base64.StdEncoding.DecodeString(license.ProductCode)
		if err != nil {
			return nil, err
		}

		pcLen := len(pc)
		if pcLen != 8 {
			return nil, errors.New("Product code has invalid size: " + strconv.Itoa(pcLen))
		}

		ln.WriteByte(7)
		ln.Write(pc)
	}
	// 8. user data
	userDataLen := len(license.UserData)
	if userDataLen > 0 {
		if userDataLen > 255 {
			return nil, errors.New("User data is too long: " + strconv.Itoa(userDataLen))
		}

		ln.WriteByte(8)
		ln.WriteByte(byte(userDataLen))
		ln.Write(license.UserData)
	}
	// 9. max build date
	if !license.MaxBuild.IsZero() {
		year := license.MaxBuild.Year()
		month := license.MaxBuild.Month()
		day := license.MaxBuild.Day()
		ln.WriteByte(9)
		ln.WriteByte(byte(day))
		ln.WriteByte(byte(month))
		ln.WriteByte(byte(year % 256))
		ln.WriteByte(byte(year / 256))
	}

	if ln.Len() == 0 {
		return nil, errors.New("Pack serial failed. ")
	}

	return ln.Bytes(), nil
}

func unpackSerial(strBin string) (*License, error) {
	var license = new(License)

	//skip front padding until \0
	var i int = 1
	for ; i < len(strBin); i++ {
		if int(strBin[i]) == 0 {
			break
		}
	}

	snLen := len(strBin)
	if i == snLen {
		return nil, errors.New("Serial number parsing error (len). ")
	}

	i++
	var start = i
	var end int = 0

	for i := start; i < len(strBin); {
		ch := int(strBin[i])
		i++

		if ch == 1 {
			license.Version = int(strBin[i])
			i++
		} else if ch == 2 {
			length := int(strBin[i])
			i++
			license.Name = strBin[i : i+length]
			i += length
		} else if ch == 3 {
			length := int(strBin[i])
			i++
			license.Email = strBin[i : i+length]
			i += length
		} else if ch == 4 {
			length := int(strBin[i])
			i++
			//license.HardwareId = []byte(strBin[i : i+8])
			license.HardwareId = []byte(strBin[i : i+length])
			i += length
		} else if ch == 5 {
			license.Expiration = time.Date(int(strBin[i+2])+int(strBin[i+3])*256, time.Month(int(strBin[i+1])), int(strBin[i]), 0, 0, 0, 0, time.UTC)
			i += 4
		} else if ch == 6 {
			license.RunningTimeLimit = int(strBin[i])
			i++
		} else if ch == 7 {
			license.ProductCode = base64.StdEncoding.EncodeToString([]byte(strBin[i : i+8]))
			i += 8
		} else if ch == 8 {
			length := int(strBin[i])
			i++
			license.UserData = []byte(strBin[i : i+length])
			i += length
		} else if ch == 9 {
			license.MaxBuild = time.Date(int(strBin[i+2])+int(strBin[i+3])*256, time.Month(int(strBin[i+1])), int(strBin[i]), 0, 0, 0, 0, time.UTC)
			i += 4
		} else if ch == 255 {
			end = i - 1
			break
		} else {
			fmt.Println("ERROR", start, i, ch)
			return nil, errors.New("Serial number parsing error (chunk). ")
		}
	}

	if end == 0 || snLen-end < 4 {
		return nil, errors.New("Serial number CRC error. ")
	}

	var sha1HashArr = sha1.Sum([]byte(strBin[start:end]))
	var revHashArr = make([]byte, 4)
	for i := 0; i < 4; i++ {
		revHashArr[3-i] = sha1HashArr[i]
	}

	var hashArr = []byte(strBin[end+1 : end+1+4])

	if bytes.Compare(revHashArr, hashArr) != 0 {
		return nil, errors.New("Serial number CRC error. ")
	}

	return license, nil
}

func filterSerial(serial string) string {
	//noinspection SpellCheckingInspection
	alphabet := []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
	var buffer bytes.Buffer
	serialLen := len(serial)
	for i := 0; i < serialLen; {
		ch := serial[i]
		// ASCII
		if ch < 0x80 {
			if bytes.IndexByte(alphabet, ch) != -1 {
				buffer.WriteByte(ch)
			}

			i++
			//UNICODE
		} else if ch < 0xC0 {
			i++
		} else if ch < 0xE0 {
			i += 2
		} else if ch < 0xF0 {
			i += 3
		} else if ch < 0xF8 {
			i += 4
		}
	}

	return buffer.String()
}

func ParseLicense(serial, public, modulus, productCode string, bits int) (*License, error) {
	bytesLen := bits / 8

	tmpSerial, err := base64.StdEncoding.DecodeString(filterSerial(serial))

	if err != nil {
		return nil, errors.New("Invalid serial number encoding. ")
	}

	if len(tmpSerial) < (bytesLen-6) || len(tmpSerial) > (bytesLen+6) {
		return nil, errors.New("Invalid length. ")
	}

	strBin, err := decodeSerial(string(tmpSerial), public, modulus)
	if err != nil {
		return nil, err
	}

	license, err := unpackSerial(strBin)
	if err != nil {
		return nil, err
	}

	if license.Version < 0 || len(license.ProductCode) == 0 {
		return nil, errors.New("Incomplete serial number. ")
	}

	if license.Version != 1 {
		return nil, errors.New("Unsupported version. ")
	}

	if strings.Compare(license.ProductCode, productCode) != 0 {
		return nil, errors.New("Invalid product code. ")
	}

	return license, err
}

var SupportBits = []interface{} {128, 256, 512, 1024, 2048, 4096}

func NewConfig(algorithm string, bits int, private string, modules string, productCode string) (keygen *Config, err error) {
	if len(algorithm) == 0 || !(isIn(bits, SupportBits)) ||
		len(private) == 0 || len(modules) == 0 || len(productCode) == 0 {
		return nil, errors.New("配置有误")
	}

	return &Config{Algorithm:algorithm, Bits:bits, Private:private, Modules:modules, ProductCode:productCode}, nil
}

func (l License) Generate(config Config) (string, error) {
	// product code should be added always
	l.ProductCode = config.ProductCode
	serial, err := packSerial(l)

	if err != nil {
		return "", err
	}

	s1 := sha1.New()
	s1.Write([]byte(serial))
	hash := s1.Sum(nil)

	serial = append(serial, byte(255))
	for i := 3; i >= 0; i-- {
		serial = append(serial, hash[i])
	}

	paddingFront := []byte{0, 2}
	size := rand.Intn(8) + 8

	for i := 0; i < size; i++ {
		paddingFront = append(paddingFront, byte(rand.Intn(254) + 1))
	}

	paddingFront = append(paddingFront, 0)
	contentSize := len(serial) + len(paddingFront)
	rest := config.Bits/ 8 - contentSize
	if rest < 0 {
		return "", errors.New("content is too bug to fit in key: " + strconv.Itoa(contentSize) + ", maximal allowed is " + strconv.Itoa(config.Bits/ 8))
	}

	paddingBack := []byte{}
	for i := 0; i < rest; i++ {
		paddingBack = append(paddingBack, byte(rand.Intn(255)))
	}

	finalSerial := append(paddingFront, serial...)
	finalSerial = append(finalSerial, paddingBack...)

	// RSA Encrypt

	rawModules, err := base64.StdEncoding.DecodeString(config.Modules)

	if err != nil {
		return "", errors.New("Modules base64Decode failed: " + err.Error())
	}

	n := base10Encode(rawModules)

	rawPrivate, err := base64.StdEncoding.DecodeString(config.Private)

	if err != nil {
		return "", errors.New("rawPrivate base64Decode failed" + err.Error())
	}

	d := base10Encode(rawPrivate)
	base10FinalSerial := base10Encode(finalSerial)
	res, err := powmod(base10FinalSerial, d, n)

	if err != nil {
		return "", errors.New("powmod is failed: " + err.Error())
	}

	result := base10Decode(res)
	result = base64.StdEncoding.EncodeToString([]byte(result))

	return result, nil
}

func isIn(search interface{}, in []interface{}) bool {
	for _, v := range in {
		if v == search {
			return true
		}
	}

	return false
}

