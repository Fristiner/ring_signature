package models

import (
	"crypto/rand"
	"crypto/rsa"
)

// 存放缓存 data privateKeys

type RSAData struct {
	PrivateKey []*rsa.PrivateKey
	PublicKey  []*rsa.PublicKey
}

var RsaData RSAData

func add() {

}

func InitRSAData() {
	size := 4
	for i := 0; i < size; i++ {
		generateKey, _ := rsa.GenerateKey(rand.Reader, 1024)
		RsaData.PrivateKey = append(RsaData.PrivateKey, generateKey)
		RsaData.PublicKey = append(RsaData.PublicKey, &generateKey.PublicKey)
	}
}
