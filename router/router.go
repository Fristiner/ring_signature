package router

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/peter-matc/ring_signature/api"
)

func Start() {

	// gin.DisableConsoleColor()
	//
	// logFile, err := os.Create("/file.log")
	// if err != nil {
	// 	// fmt.Println("")
	// 	fmt.Println("err ", err)
	// }

	// gin.DefaultWriter = logFile
	r := gin.Default()
	r.LoadHTMLGlob("templates/*")
	r.Static("/assets", "./assets")
	// 解决跨域问题
	r.Use(Cors())
	r.GET("/", func(context *gin.Context) {
		context.HTML(200, "index.html", nil)
	})
	r.GET("/download", api.Download)
	r.POST("/verify", api.Verify)
	r.POST("/sign", api.Sign)
	err := r.Run(":8082")
	// err := r.Run(":8082")
	if err != nil {
		panic(err)
	}

}

func CheckCors() gin.HandlerFunc {
	// 这里可以处理一些别的逻辑
	return func(c *gin.Context) {
		// 定义一个origin的map，只有在字典中的key才允许跨域请求
		var allowOrigins = map[string]struct{}{
			"http://127.0.0.1:5500": struct{}{},
			// "http://127.0.0.1":            struct{}{},
			"https://www.yangyanxing.com": struct{}{},
		}
		origin := c.Request.Header.Get("Origin") // 请求头部
		method := c.Request.Method
		if method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
		}
		if origin != "" {
			if _, ok := allowOrigins[origin]; ok {
				c.Header("Access-Control-Allow-Origin", origin)
				c.Header("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE, UPDATE")
				c.Header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, Authorization")
				c.Header("Access-Control-Expose-Headers", "Content-Length, Access-Control-Allow-Origin, Access-Control-Allow-Headers, Cache-Control, Content-Language, Content-Type")
				c.Header("Access-Control-Allow-Credentials", "true")
			}
		}
		c.Next()
	}
}

func Cors() gin.HandlerFunc {
	return func(c *gin.Context) {
		method := c.Request.Method
		origin := c.Request.Header.Get("Origin")
		if origin != "" {
			c.Header("Access-Control-Allow-Origin", "*") // 可将将 * 替换为指定的域名
			c.Header("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE, UPDATE")
			c.Header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, Authorization")
			c.Header("Access-Control-Expose-Headers", "Content-Length, Access-Control-Allow-Origin, Access-Control-Allow-Headers, Cache-Control, Content-Language, Content-Type")
			c.Header("Access-Control-Allow-Credentials", "true")
		}
		if method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
		}
		c.Next()
	}
}
