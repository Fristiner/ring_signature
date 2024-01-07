package models

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"testing"
)

// 测试
func TestName(t *testing.T) {
	InitRSAData()

	fmt.Println(RsaData)
	key, _ := rsa.GenerateKey(rand.Reader, 1024)
	RsaData.PrivateKey = append(RsaData.PrivateKey, key)
	RsaData.PublicKey = append(RsaData.PublicKey, &key.PublicKey)

	fmt.Println(RsaData)
	publicKey := RsaData.PublicKey

	fmt.Println(publicKey)
}
