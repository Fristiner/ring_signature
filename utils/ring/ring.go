package ring

import (
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"math/rand"
	"strings"
	"time"
)

type ring struct {
	PubKeys []*rsa.PublicKey
	PriKey  *rsa.PrivateKey
	L       uint     // rsaUtils 密钥长度
	N       int      // 组成员个数
	Q       *big.Int // 与密钥长度相对应的随机数阈值
	P       *big.Int // 作为对称加密key的hash结果
}

// L是rsa密钥长度
func (ring *ring) init(pubkeys []*rsa.PublicKey, prikey *rsa.PrivateKey, L uint) {
	ring.PubKeys = make([]*rsa.PublicKey, 0, len(pubkeys))
	ring.PubKeys = append(ring.PubKeys, pubkeys...)
	ring.PriKey = prikey
	ring.L = L
	ring.N = len(pubkeys)
	ring.Q = big.NewInt(1)
	ring.Q.Lsh(ring.Q, L)
	ring.P = big.NewInt(0)
}

// m是消息，z是密钥对应的公钥在环成员的位置，从0开始
func (ring *ring) sign(m string, z int) []*big.Int {
	ring.hash(m)
	// xs保存的是所有x的值
	xs := make([]*big.Int, ring.N)
	temp := big.NewInt(0)
	c := big.NewInt(0)
	v := big.NewInt(0)
	u := big.NewInt(0)

	var rand1 *rand.Rand
	rand1 = rand.New(rand.NewSource(time.Now().Unix()))
	// pick random v, c=eEk(u), u = myY xor v
	u.Set(temp.Rand(rand1, ring.Q))
	v.Set(ring.eEk(u))
	c.Set(v)

	// loop 得到签名成员之后的成员顺序
	var loop []int
	for i := int(0); i < ring.N; i++ {
		loop = append(loop, i)
	}
	loop = append(loop, loop...)
	loop = loop[z+1 : z+ring.N]
	// 随机选取E
	for _, i := range loop {
		xs[i] = big.NewInt(0)
		xs[i].Set(temp.Rand(rand1, ring.Q))
		temp.SetInt64(int64(ring.PubKeys[i].E))
		yi := ring.g(xs[i], temp, ring.PubKeys[i].N)
		v = ring.eEk(v.Xor(v, yi))
		if (i+1)%ring.N == 0 {
			c.Set(v)
		}
	}

	// cal myX from myY
	xs[z] = big.NewInt(0)
	xs[z].Set(ring.g(temp.Xor(v, u), ring.PriKey.D, ring.PriKey.N))
	// re为最后一名成员得到的v
	re := []*big.Int{c}
	return append(re, xs[:]...)
}

func (ring *ring) verify(m string, X []*big.Int) int {
	var y []*big.Int
	r := big.NewInt(0)
	temp := big.NewInt(0)
	ring.hash(m)
	// 生成所有yi
	for i := 0; i < len(X)-1; i++ {
		temp = big.NewInt(int64(ring.PubKeys[i].E))
		y = append(y, ring.g(X[i+1], temp, ring.PubKeys[i].N))
	}
	// 一轮过后是否相同，Ckv（y1...yn）=eEk(yn xor eEk(yn-1 xor ... eEk(y1 xor v)...)) = v
	r.Set(X[0])
	for i := 0; i < ring.N; i++ {
		r = ring.eEk(temp.Xor(r, y[i]))
	}
	return r.Cmp(X[0])
}

// 导入 errors 包，用于创建 error 对象

// 修改函数的签名，增加一个 error 类型的返回值
func (ring *ring) verify2(m string, X []*big.Int) (int, error) {
	var y []*big.Int
	r := big.NewInt(0)
	temp := big.NewInt(0)
	ring.hash(m)
	// 生成所有yi
	for i := 0; i < len(X)-1; i++ {
		temp = big.NewInt(int64(ring.PubKeys[i].E))
		y = append(y, ring.g(X[i+1], temp, ring.PubKeys[i].N))
	}
	// 一轮过后是否相同，Ckv（y1...yn）=eEk(yn xor eEk(yn-1 xor ... eEk(y1 xor v)...)) = v
	// 检查 X 是否为空
	if len(X) == 0 {
		// 如果为空，返回一个错误
		return -1, errors.New("X is empty")
	}
	r.Set(X[0])
	for i := 0; i < ring.N; i++ {
		r = ring.eEk(temp.Xor(r, y[i]))
	}
	// 如果 r 和 X[0] 相等，返回 0 和 nil
	if r.Cmp(X[0]) == 0 {
		return 0, nil
	}
	// 如果 r 和 X[0] 不相等，返回 -1 和一个 error 对象
	return -1, errors.New("verification failed")
}

// 求出明文的hash放入P中作为k，更新成sha256
func (ring *ring) hash(m string) {
	a := sha256.Sum256([]byte(m))
	ring.P.SetBytes(a[:])
}

// 对称加密函数，在这里使用单向hash
func (ring *ring) eEk(x *big.Int) *big.Int {
	msg := x.String() + ring.P.String()
	re := big.NewInt(0)
	a := sha256.Sum256([]byte(msg))
	return re.SetBytes(a[:])
}

// g的函数，针对传入的e不同功能不同，实现限门函数作用，但不引入随机数
func (ring *ring) g(x *big.Int, e *big.Int, n *big.Int) *big.Int {
	temp1 := big.NewInt(0)
	temp2 := big.NewInt(0)
	temp3 := big.NewInt(0)
	temp4 := big.NewInt(0)
	q := big.NewInt(0)
	r := big.NewInt(0)
	q, r = temp1.DivMod(x, n, temp2)
	rslt := big.NewInt(0)
	one := big.NewInt(1)
	temp3.Add(q, one)
	temp3.Mul(temp3, n)
	temp4.Lsh(one, ring.L)
	temp4.Sub(temp4, one)
	if temp3.Cmp(temp4) <= 0 {
		rslt.Mul(q, n)
		temp3.Exp(r, e, n)
		rslt.Add(rslt, temp3)
	} else {
		rslt = x
	}
	return rslt
}

func SignWrapper(size int, num int, msg string, key []*rsa.PublicKey, mySecret *rsa.PrivateKey) []*big.Int {
	r := new(ring)
	r.init(key, mySecret, 1024)
	return r.sign(msg, num)
}

func VerifyWrapper(msg string, key []*rsa.PublicKey, X []*big.Int) bool {
	r := new(ring)
	r.init(key, nil, 1024)
	re := r.verify(msg, X)
	if re == 0 {
		return true
	} else {
		return false
	}
}
func VerifyWrapper2(msg string, key []*rsa.PublicKey, X []*big.Int) (bool, error) {
	r := new(ring)
	r.init(key, nil, 1024)
	// verify := r.verify(msg, X)
	// re := verify
	re, err := r.verify2(msg, X)
	if err != nil {
		return false, err
	}
	if re == 0 {
		return true, nil
	} else {
		return false, nil
	}
}

// EncodeSignature 将 []*big.Int 类型的数字签名转换为 base64 编码的字符串，并返回
func EncodeSignature(signature []*big.Int) string {
	var s string
	for _, v := range signature {
		temp := v.String()
		// fmt.Println(temp)
		s += temp + " "
	}
	encodeToString := base64.StdEncoding.EncodeToString([]byte(s))
	return encodeToString
}

// DecodeSignature 将 base64 编码的字符串转换为 []*big.Int 类型的数字签名，并返回
func DecodeSignature(s string) ([]*big.Int, error) {
	// 1.先进行解码
	bytes, _ := base64.StdEncoding.DecodeString(s)
	fmt.Println(string(bytes))
	// 解码成功
	DecodeCode := string(bytes)
	slice := strings.Fields(DecodeCode)
	// 定义一个空的 []*big.Int 切片，用于存储转换后的值
	bigSlice := make([]*big.Int, 0)
	// 使用 for 循环，遍历分割后的字符串切片
	for _, s := range slice {
		// 使用 big.Int 的 SetString 方法，将字符串转换为 *big.Int 类型的值
		bigNum, ok := new(big.Int).SetString(s, 10)
		// 检查转换是否成功
		if !ok {
			// fmt.Println("error converting string to big int")
			return nil, errors.New("error converting string to big int")
		}
		// 将 *big.Int 类型的值追加到 []*big.Int 切片中
		bigSlice = append(bigSlice, bigNum)
	}
	// 打印 []*big.Int 切片的内容
	fmt.Println(bigSlice)
	return bigSlice, nil
}

// // DecodeSignature 将 base64 编码的字符串转换为 []*big.Int 类型的数字签名，并返回
// func DecodeSignature(s string) ([]*big.Int, error) {
// 	// 使用 base64.StdEncoding.DecodeString 函数，传入 base64 编码的字符串，得到一个字节切片
// 	bytes, err := base64.StdEncoding.DecodeString(s)
// 	fmt.Println(string(bytes))
//
// 	if err != nil {
// 		return nil, err
// 	}
// 	// 定义一个空的 []*big.Int 切片，用于存储数字签名的每个元素
// 	signature := make([]*big.Int, 0)
// 	// 使用 for 循环，从字节切片中分割出每个元素的二进制数据
// 	for i := 0; i < len(bytes); i += 16 {
// 		// 如果字节切片的长度不是 16 的倍数，说明 base64 编码的字符串不是一个有效的数字签名，返回一个错误信息
// 		if i+16 > len(bytes) {
// 			return nil, errors.New("invalid signature")
// 		}
// 		// 从字节切片中截取 16 个字节，作为一个元素的二进制数据
// 		element := bytes[i : i+16]
// 		// 使用 new(big.Int).SetBytes 函数，传入元素的二进制数据，得到一个 *big.Int 类型的值
// 		bigElement := new(big.Int).SetBytes(element)
// 		// 将 *big.Int 类型的值追加到 []*big.Int 切片中
// 		signature = append(signature, bigElement)
// 	}
// 	// 返回 []*big.Int 类型的数字签名
// 	return signature, nil
// }
//
// // DecodeSignature2 将 base64 编码的字符串转换为 []*big.Int 类型的数字签名，并返回
// func DecodeSignature2(s string) ([]*big.Int, error) {
// 	// 使用 base64.StdEncoding.DecodeString 函数，传入 base64 编码的字符串，得到一个字节切片
// 	bytes, err := base64.StdEncoding.DecodeString(s)
// 	if err != nil {
// 		return nil, err
// 	}
// 	// 定义一个空的 []*big.Int 切片，用于存储数字签名的每个元素
// 	signature := make([]*big.Int, 0)
// 	// 使用 for 循环，从字节切片中分割出每个元素的二进制数据
// 	for i := 0; i < len(bytes); i += 8 {
// 		// 如果字节切片的长度不是 8 的倍数，说明 base64 编码的字符串不是一个有效的数字签名，返回一个错误信息
// 		if i+8 > len(bytes) {
// 			return nil, errors.New("invalid signature")
// 		}
// 		// 从字节切片中截取 8 个字节，作为一个元素的二进制数据
// 		element := bytes[i : i+8]
// 		// 使用 new(big.Int).SetBytes 函数，传入元素的二进制数据，得到一个 *big.Int 类型的值
// 		bigElement := new(big.Int).SetBytes(element)
// 		// 将 *big.Int 类型的值追加到 []*big.Int 切片中
// 		signature = append(signature, bigElement)
// 	}
// 	// 返回 []*big.Int 类型的数字签名
// 	return signature, nil
// }
//
// func DecodeSignature3(s string) ([]*big.Int, error) {
// 	// 使用 base64.RawStdEncoding.DecodeString 函数，传入 base64 编码的字符串，得到一个字节切片
// 	bytes, err := base64.RawStdEncoding.DecodeString(s)
// 	// fmt.Println(string(bytes))
//
// 	if err != nil {
// 		return nil, err
// 	}
// 	// 定义一个空的 []*big.Int 切片，用于存储数字签名的每个元素
// 	signature := make([]*big.Int, 0)
// 	// 定义一个数组，用于存储数字签名的每个元素的长度
// 	lengths := [5]int{77, 310, 309, 309, 309}
// 	// 定义一个变量，用于记录当前正在处理的数字签名的元素的索引
// 	index := 0
// 	// 使用 for 循环，从字节切片中分割出每个元素的二进制数据
// 	for i := 0; i < len(bytes)-1; i++ {
// 		// 如果索引超出了数组的范围，说明 base64 编码的字符串不是一个有效的数字签名，返回一个错误信息
// 		if index >= len(lengths) {
// 			return nil, errors.New("invalid signature")
// 		}
// 		// 从数组中获取当前元素的长度
// 		length := lengths[index]
// 		// 如果当前元素的长度超过了字节切片的剩余长度，说明 base64 编码的字符串不是一个有效的数字签名，返回一个错误信息
// 		if i+length > len(bytes) {
// 			return nil, errors.New("invalid signature")
// 		}
// 		// 定义一个空的 []byte 切片，用于存储当前元素的二进制数据
// 		element := make([]byte, 0)
// 		// 使用一个内层的 for 循环，从字节切片中截取当前元素的二进制数据
// 		for j := 0; j < length; j++ {
// 			// 将字节切片中的一个字节追加到 []byte 切片中
// 			element = append(element, bytes[i+j])
// 		}
// 		// 使用 new(big.Int).SetBytes 函数，传入当前元素的二进制数据，得到一个 *big.Int 类型的值
// 		bigElement := new(big.Int).SetBytes(element)
// 		// 将 *big.Int 类型的值追加到 []*big.Int 切片中
// 		signature = append(signature, bigElement)
// 		// 将 i 变量增加当前元素的长度，以便跳过已经处理过的字节
// 		i += length
// 		// 将 index 变量增加 1，以便处理下一个元素
// 		index++
// 	}
// 	// 返回 []*big.Int 类型的数字签名
// 	return signature, nil
// }
