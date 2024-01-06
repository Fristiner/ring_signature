package rsaUtils

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"os"

	gonanoid "github.com/matoous/go-nanoid"
)

// GenerateRSAKey 生成 RSA 公钥和私钥，并保存到文件中
//
//	@Description:
//	@param bits
//	@return error
func GenerateRSAKey(bits int) error {
	// 生成私钥
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return err
	}
	fmt.Println("私钥为：", privateKey)
	// 获取公钥
	publicKey := privateKey.PublicKey
	fmt.Println("公钥为：", publicKey)
	// 编码私钥
	privateKeyBytes, _ := x509.MarshalPKCS8PrivateKey(privateKey)
	// 编码公钥
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&publicKey)
	if err != nil {
		return err
	}
	// 创建私钥的 PEM 数据
	privateKeyBlock := pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyBytes,
	}
	// 创建公钥的 PEM 数据
	publicKeyBlock := pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}
	// 创建私钥文件
	privateFile, err := os.Create("private.pem")
	if err != nil {
		return err
	}
	defer func(privateFile *os.File) {
		_ = privateFile.Close()
	}(privateFile)
	// 将私钥写入文件
	err = pem.Encode(privateFile, &privateKeyBlock)
	if err != nil {
		return err
	}
	// 创建公钥文件
	publicFile, err := os.Create("public.pem")
	if err != nil {
		return err
	}
	defer func(publicFile *os.File) {
		_ = publicFile.Close()
	}(publicFile)

	// 将公钥写入文件
	err = pem.Encode(publicFile, &publicKeyBlock)
	if err != nil {
		return err
	}
	// 返回 nil 表示成功
	return nil
}

// GenerateRSAKeyWithFile
//
//	@Description:  先返回私钥再返回公钥
//	@param bits
//	@return *os.File
//	@return *os.File
//	@return error
func GenerateRSAKeyWithFile(bits int) (*os.File, *os.File, error) {
	// 生成私钥
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, err
	}
	// fmt.Println("私钥为：", privateKey)
	// 获取公钥
	publicKey := privateKey.PublicKey
	// fmt.Println("公钥为：", publicKey)
	// 编码私钥
	privateKeyBytes, _ := x509.MarshalPKCS8PrivateKey(privateKey)
	// 编码公钥
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&publicKey)
	if err != nil {
		return nil, nil, err
	}
	// 创建私钥的 PEM 数据
	privateKeyBlock := pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyBytes,
	}
	// 创建公钥的 PEM 数据
	publicKeyBlock := pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}
	// 创建私钥文件

	// stringName := time.Now().UnixNano()
	// publicName := "private"+ stringName+".pem"
	// u := uuid.New()
	// id := u.String()
	//

	id, err1 := gonanoid.Nanoid(10)
	if err1 != nil {
		return nil, nil, err1
	}

	publicName := "file/public-" + id + ".pem"
	privateName := "file/private-" + id + ".pem"
	privateFile, err := os.Create(privateName)
	if err != nil {
		return nil, nil, err
	}
	// defer func(privateFile *os.File) {
	// 	_ = privateFile.Close()
	// }(privateFile)
	// 将私钥写入文件
	err = pem.Encode(privateFile, &privateKeyBlock)
	if err != nil {
		return nil, nil, err
	}
	// 创建公钥文件
	publicFile, err := os.Create(publicName)
	if err != nil {
		return nil, nil, err
	}
	// defer func(publicFile *os.File) {
	// 	_ = publicFile.Close()
	// }(publicFile)

	// 将公钥写入文件
	err = pem.Encode(publicFile, &publicKeyBlock)
	if err != nil {
		return nil, nil, err
	}
	_ = privateFile.Close()
	_ = publicFile.Close()

	file2, err := os.Open(publicName)
	if err != nil {
		return nil, nil, err
	}

	file1, err := os.Open(privateName)
	if err != nil {
		return nil, nil, err
	}

	return file1, file2, nil

	// fmt.Println("publicFile", publicFile)
	// 返回 nil 表示成功
	// return privateFile, publicFile, nil
}

// ReadPublicKey 从文件中读取公钥，并返回一个 *rsaUtils.PublicKey 类型的值
func ReadPublicKey(filename string) (*rsa.PublicKey, error) {
	// 打开公钥文件
	publicFile, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer publicFile.Close()
	// 读取公钥文件的内容
	publicBytes, err := io.ReadAll(publicFile)
	if err != nil {
		return nil, err
	}
	// 解码公钥文件的内容，得到 PEM 数据
	publicBlock, _ := pem.Decode(publicBytes)
	if publicBlock == nil {
		return nil, fmt.Errorf("invalid public key data")
	}
	// 解析 PEM 数据，得到 X.509 编码
	publicInterface, err := x509.ParsePKIXPublicKey(publicBlock.Bytes)
	if err != nil {
		return nil, err
	}
	// 类型断言，得到公钥
	publicKey, ok := publicInterface.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not a RSA public key")
	}
	// 返回公钥
	return publicKey, nil
}

// ReadPrivateKey 从文件中读取私钥，并返回一个 *rsaUtils.PrivateKey 类型的值
func ReadPrivateKey(filename string) (*rsa.PrivateKey, error) {
	// 打开私钥文件
	privateFile, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer privateFile.Close()
	// 读取私钥文件的内容
	privateBytes, err := ioutil.ReadAll(privateFile)
	if err != nil {
		return nil, err
	}
	// 解码私钥文件的内容，得到 PEM 数据
	privateBlock, _ := pem.Decode(privateBytes)
	if privateBlock == nil {
		return nil, fmt.Errorf("invalid private key data")
	}
	// 解析 PEM 数据，得到 PKCS#8 编码
	privateInterface, err := x509.ParsePKCS8PrivateKey(privateBlock.Bytes)
	if err != nil {
		return nil, err
	}
	// 类型断言，得到私钥
	privateKey, ok := privateInterface.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("not a RSA private key")
	}
	// 返回私钥
	return privateKey, nil
}

// GenerateRSAKeyByFile 生成 RSA 公钥和私钥，并返回两个 os.File 类型的值，分别表示私钥文件和公钥文件
func GenerateRSAKeyByFile(bits int) (*os.File, *os.File, error) {
	// 生成私钥
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, err
	}
	fmt.Println("私钥为：", privateKey)
	// 获取公钥
	publicKey := privateKey.PublicKey
	fmt.Println("公钥为：", publicKey)
	// 编码私钥
	privateKeyBytes, _ := x509.MarshalPKCS8PrivateKey(privateKey)
	// 编码公钥
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&publicKey)
	if err != nil {
		return nil, nil, err
	}
	// 创建私钥的 PEM 数据
	privateKeyBlock := pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyBytes,
	}
	// 创建公钥的 PEM 数据
	publicKeyBlock := pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}
	// 创建私钥文件
	privateFile, err := os.Create("private.pem")
	if err != nil {
		return nil, nil, err
	}
	// 将私钥写入文件
	err = pem.Encode(privateFile, &privateKeyBlock)
	if err != nil {
		return nil, nil, err
	}
	// 创建公钥文件
	publicFile, err := os.Create("public.pem")
	if err != nil {
		return nil, nil, err
	}
	// 将公钥写入文件
	err = pem.Encode(publicFile, &publicKeyBlock)
	if err != nil {
		return nil, nil, err
	}
	// 返回私钥文件和公钥文件
	return privateFile, publicFile, nil
}

// func main() {
// 	// 调用 GenerateRSAKey 函数，传入 2048 作为密钥长度，得到私钥文件和公钥文件
// 	privateFile, publicFile, err := GenerateRSAKey(2048)
// 	if err != nil {
// 		// 如果出错，打印错误信息
// 		fmt.Println(err)
// 	} else {
// 		// 如果成功，打印提示信息
// 		fmt.Println("生成 RSA 公钥和私钥成功")
// 	}
// 	// 在这里可以使用私钥文件和公钥文件进行其他操作，例如传输或者关闭
// 	// 例如，打印文件名
// 	fmt.Println("私钥文件名:", privateFile.Name())
// 	fmt.Println("公钥文件名:", publicFile.Name())
// 	// 关闭文件
// 	privateFile.Close()
// 	publicFile.Close()
// }
// func main() {
// 	// 调用 ReadPublicKey 函数，传入公钥文件名，得到公钥
// 	publicKey, err := ReadPublicKey("public.pem")
// 	if err != nil {
// 		// 如果出错，打印错误信息
// 		fmt.Println(err)
// 	} else {
// 		// 如果成功，打印公钥
// 		fmt.Println("公钥:", publicKey)
// 	}
// 	// 调用 ReadPrivateKey 函数，传入私钥文件名，得到私钥
// 	privateKey, err := ReadPrivateKey("private.pem")
// 	if err != nil {
// 		// 如果出错，打印错误信息
// 		fmt.Println(err)
// 	} else {
// 		// 如果成功，打印私钥
// 		fmt.Println("私钥:", privateKey)
// 	}
// }

// func main() {
// 	// 调用 GenerateRSAKey 函数，传入 2048 作为密钥长度
// 	err := GenerateRSAKey(2048)
// 	if err != nil {
// 		// 如果出错，打印错误信息
// 		fmt.Println(err)
// 	} else {
// 		// 如果成功，打印提示信息
// 		fmt.Println("生成 RSA 公钥和私钥成功")
// 	}
// }
