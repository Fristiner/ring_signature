package api

import (
	"archive/zip"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/peter-matc/ring_signature/models"
	"github.com/peter-matc/ring_signature/utils/ring"
	"github.com/peter-matc/ring_signature/utils/rsaUtils"
)

// TODO：根据传过来的公钥和msg以及sign 进行校验

func Is(c *gin.Context) {
	// 1. 获得返回的数据
	msg := c.PostForm("msg")
	// publicKeys := c.PostForm("publicKeys")
	signature := c.PostForm("signature")
	// 2. 对返回的数据进行处理
	decodeSignature, err := ring.DecodeSignature(signature)
	if err != nil {
		return
	}
	ring.VerifyWrapper(msg, nil, decodeSignature)

	//

}

// Download
//
//	@Description: 返回公钥和私钥文件
//	@param c
func Download(c *gin.Context) {
	// 设置响应的头部信息，让前端知道这是一个多文件的压缩包
	c.Writer.Header().Set("Content-Type", "application/zip")
	c.Writer.Header().Set("Content-Disposition", "attachment; filename=keys.zip")
	// 创建一个 zip.Writer，关联到 c.Writer
	zw := zip.NewWriter(c.Writer)
	defer zw.Close()
	// 打开 private.pem 文件
	// privateFile, err := os.Open("file/private.pem")
	privateFile, publicFile, err := rsaUtils.GenerateRSAKeyWithFile(1024)
	if err != nil {
		// 如果出错，返回错误信息
		c.String(500, err.Error())
		return
	}
	defer func(privateFile *os.File) {
		_ = privateFile.Close()
	}(privateFile)
	// 创建一个 zip.FileHeader，设置文件名为 private.pem
	privateHeader, err := zw.Create("private.pem")
	if err != nil {
		// 如果出错，返回错误信息
		c.String(500, err.Error())
		return
	}
	// 将 private.pem 文件的内容复制到 zip.FileHeader 中
	_, err = io.Copy(privateHeader, privateFile)
	if err != nil {
		// 如果出错，返回错误信息
		c.String(500, err.Error())
		return
	}
	defer func(publicFile *os.File) {
		_ = publicFile.Close()
	}(publicFile)
	// 创建一个 zip.FileHeader，设置文件名为 public.pem
	publicHeader, err := zw.Create("public.pem")
	if err != nil {
		// 如果出错，返回错误信息
		c.String(500, err.Error())
		return
	}
	// 将 public.pem 文件的内容复制到 zip.FileHeader 中
	_, err = io.Copy(publicHeader, publicFile)
	if err != nil {
		// 如果出错，返回错误信息
		c.String(500, err.Error())
		return
	}
}

// TODO： 上传私钥来进行环签名 和 加密数据msg 使用form表格提交数据
//     privateKeys   msg
// 使用json 来传输    返回的是个json数据

// GetMsg
//
//	@Description:
//	@param c
func GetMsg(c *gin.Context) {
	// privateKeys
	privateKeys := c.PostForm("privateKeys")
	msg := c.PostForm("msg")

	// 获得了私钥和

	privateKey, err := rsaUtils.ReadPrivateString(privateKeys)
	if err != nil {
		// TODO： 传输的类型有问题需要处理
		return
	}

	// key := privateKey.PublicKey
	var key []*rsa.PrivateKey
	var pubkeys []*rsa.PublicKey
	size := 4

	for i := 0; i < size; i++ {
		generateKey, _ := rsa.GenerateKey(rand.Reader, 1024)
		key = append(key, generateKey)
		pubkeys = append(pubkeys, &generateKey.PublicKey)
	}

	pubkeys = append(pubkeys, &privateKey.PublicKey)

	// TODO： 使用一个缓存切片来维护
	signature := ring.SignWrapper(len(pubkeys), len(pubkeys)-1, msg, pubkeys, privateKey)

	encodeSignature := ring.EncodeSignature(signature)

	// 返回
	c.JSON(http.StatusOK, gin.H{
		"signature": encodeSignature,
	})

	// msg
}

// Sign
//
//	@Description: 产生数字签名并返回结果
//	@param c
func Sign(c *gin.Context) {
	// privateKeys : privates,
	//                    msg: msg,
	var key models.Keys

	err := c.BindJSON(&key)
	if err != nil {
		c.JSON(200, gin.H{
			"status": "no",
			"msg":    "传输的数据有问题",
		})
	}

	privateKey, err := rsaUtils.ReadPrivateString(key.PrivateKeys)
	if err != nil {
		return
	}

	// var keys []*rsa.PrivateKey
	// var pubkeys []*rsa.PublicKey
	// size := 4
	//
	// for i := 0; i < size; i++ {
	// 	generateKey, _ := rsa.GenerateKey(rand.Reader, 1024)
	// 	keys = append(keys, generateKey)
	// 	pubkeys = append(pubkeys, &generateKey.PublicKey)
	// }
	// models.RsaData
	models.RsaData.PrivateKey = append(models.RsaData.PrivateKey, privateKey)
	models.RsaData.PublicKey = append(models.RsaData.PublicKey, &privateKey.PublicKey)

	signature := ring.SignWrapper(len(models.RsaData.PublicKey),
		len(models.RsaData.PublicKey)-1,
		key.Msg,
		models.RsaData.PublicKey,
		privateKey)

	encodeSignature := ring.EncodeSignature(signature)

	// c.JSON(http.StatusOK, gin.H{
	// 	"status": "ok",
	// 	"msg":    encodeSignature,
	// })

	ResponseSuccess(c, encodeSignature)

	// 获得数据之后进行处理

}

// Verify
//
//	@Description: 验证数字签名
//	@param c
func Verify(c *gin.Context) {
	var signKey models.SignVerify
	err := c.BindJSON(&signKey)
	fmt.Println(signKey)

	if err != nil {
		ResponseError(c, CodeServerBusy)
		return
	}

	signature, err := ring.DecodeSignature(signKey.Signature)
	if err != nil {
		// 解析数字签名失败
		ResponseError(c, CodeDeSignERROR)
		return
	}
	// 获得数字签名编码前
	// fmt.Println(models.RsaData.PublicKey)
	fmt.Println(len(models.RsaData.PublicKey))
	// isOk := ring.VerifyWrapper(signKey.Msg, models.RsaData.PublicKey, signature)

	isOk, err := ring.VerifyWrapper2(signKey.Msg, models.RsaData.PublicKey, signature)
	if err != nil {
		ResponseError(c, CodeServerBusy)
		return
	}
	fmt.Println(isOk)
	if isOk {
		// 此时成功
		ResponseSuccess(c, "成功")
		return
	} else {
		ResponseError(c, CodeServerBusy)
		return
	}

}
