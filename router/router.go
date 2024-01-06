package router

import (
	"archive/zip"
	"io"

	"github.com/gin-gonic/gin"
	"github.com/peter-matc/ring_signature/utils/rsaUtils"
)

func Start() {
	r := gin.Default()

	r.LoadHTMLGlob("templates/*")

	r.Static("/assets", "./assets")
	r.GET("/file", func(context *gin.Context) {
		context.File("file/private.pem")
	})

	// r.GET("/download", func(c *gin.Context) {
	// 	// 打开 private.pem 文件
	// 	file, err := os.Open("file/private.pem")
	// 	if err != nil {
	// 		// 如果出错，返回错误信息
	// 		c.String(500, err.Error())
	// 		return
	// 	}
	// 	defer file.Close()
	// 	// 获取文件的大小
	// 	fileInfo, err := file.Stat()
	// 	if err != nil {
	// 		// 如果出错，返回错误信息
	// 		c.String(500, err.Error())
	// 		return
	// 	}
	// 	fileSize := fileInfo.Size()
	// 	// 设置响应的头部信息，让前端知道这是一个文件
	// 	c.Writer.WriteHeader(200)
	// 	c.Header("Content-Disposition", "attachment; filename=private.pem")
	// 	c.Header("Content-Type", "application/x-pem-file")
	// 	c.Header("Accept-Length", fmt.Sprintf("%d", fileSize))
	// 	// 使用 c.File 函数，传入文件对象，直接将文件内容发送给前端
	// 	c.File(file.Name())
	// })

	r.GET("/download", func(c *gin.Context) {
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
		defer privateFile.Close()
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
		// 打开 public.pem 文件
		// publicFile, err := os.Open("file/public.pem")
		// if err != nil {
		// 	// 如果出错，返回错误信息
		// 	c.String(500, err.Error())
		// 	return
		// }
		defer publicFile.Close()
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
	})

	err := r.Run(":8082")
	if err != nil {
		panic(err)
	}

}
