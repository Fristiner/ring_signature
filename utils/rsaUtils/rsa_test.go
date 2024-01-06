package rsaUtils

import (
	"fmt"
	"io"
	"os"
	"testing"
	"time"
)

func TestRsa(t *testing.T) {
	err := GenerateRSAKey(1024)
	if err != nil {
		return
	}
	key, err := ReadPublicKey("public.pem")
	if err != nil {
		return
	}
	fmt.Println("公钥2为： ", key)
	privateKey, err := ReadPrivateKey("private.pem")
	if err != nil {
		return
	}
	file, err := os.Open("private.pem")
	if err != nil {
		return
	}
	stat, _ := file.Stat()
	length := stat.Size()
	bytes := make([]byte, length)
	// file.Write(bytes)
	_, _ = file.Read(bytes)

	fmt.Println(string(bytes))

	fmt.Println("私钥2为：", privateKey)

}

func Test2(t *testing.T) {
	file1, file2, _ := GenerateRSAKeyByFile(1024)
	fmt.Println(file2)
	fmt.Println(file1)
	stat, _ := file1.Stat()
	println(stat.Size())
	bytes := make([]byte, stat.Size())
	_, _ = file1.Read(bytes)
	create, _ := os.Create("aaa.pem")
	// create.Write(bytes)
	_, err := io.Copy(create, file2)
	if err != nil {
		return
	}

	fmt.Println(string(bytes))

	// file1.Read()

}

func TestName(t *testing.T) {
	file1, file2, err := GenerateRSAKeyWithFile(1024)
	if err != nil {
		return
	}
	fmt.Println(file2)

	fmt.Println(file1)

	stat, _ := file1.Stat()

	bytes := make([]byte, stat.Size())

	_, _ = file1.Read(bytes)

	fmt.Println(string(bytes))

	file1.Close()

	file2.Close()

}

func Test1(t *testing.T) {
	nano := time.Now().UnixNano()
	fmt.Println(nano)

}
