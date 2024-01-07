package models

type Keys struct {
	// 1.privateKeys
	PrivateKeys string `json:"privateKeys"`
	// 2.msg
	Msg string `json:"msg"`
}

type SignVerify struct {
	PublicKeys string `json:"publicKeys"`
	Msg        string `json:"msg"`
	Signature  string `json:"signature"`
}
