package router

import (
	"fmt"
	"io"
	"os"

	"github.com/gin-gonic/gin"
)

func aaa() {
	// 初始化 Gin 实例
	r := gin.Default()
	// 定义一个路由 /file，用于传输一个已经存在的文件
	r.GET("/file", func(c *gin.Context) {
		// 使用 c.File 函数，传入文件名，直接将文件内容发送给前端
		c.File("hello.txt")
	})
	// 定义一个路由 /content，用于传输一个动态生成的文件内容
	r.GET("/content", func(c *gin.Context) {
		// 定义一个文件内容，例如 "hello world"
		content := "hello world"
		// 设置响应的头部信息，例如文件名，文件类型，文件长度等
		c.Writer.WriteHeader(200)
		c.Header("Content-Disposition", "attachment; filename=hello.txt")
		c.Header("Content-Type", "application/text/plain")
		c.Header("Accept-Length", fmt.Sprintf("%d", len(content)))
		// 使用 c.Writer.Write 函数，传入文件内容的字节切片，将文件内容写入响应的正文中
		c.Writer.Write([]byte(content))
	})
	// 定义一个路由 /stream，用于传输一个大文件
	r.GET("/stream", func(c *gin.Context) {
		// 打开一个大文件，例如 "big.txt"
		file, err := os.Open("big.txt")
		if err != nil {
			// 如果出错，返回错误信息
			c.String(500, err.Error())
			return
		}
		defer file.Close()
		// 定义一个数据流生成器，用于分块读取文件内容
		stream := func(w io.Writer) bool {
			// 定义一个缓冲区，大小为 4KB
			buf := make([]byte, 4*1024)
			// 从文件中读取一块内容，存入缓冲区
			n, err := file.Read(buf)
			if err != nil {
				// 如果出错，返回 false，表示结束
				return false
			}
			// 将缓冲区的内容写入响应的正文中
			w.Write(buf[:n])
			// 返回 true，表示继续
			return true
		}
		// 使用 c.Stream 函数，传入数据流生成器，将文件内容分块发送给前端
		c.Stream(stream)
	})
	// 运行 Gin 实例，监听 8080 端口
	r.Run(":8080")
}
