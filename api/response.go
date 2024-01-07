package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

type ResponseData struct {
	Code    MyCode `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data"`
}

func ResponseError(ctx *gin.Context, c MyCode) {
	rd := &ResponseData{
		Code:    c,
		Message: c.Msg(),
		Data:    nil,
	}
	ctx.JSON(http.StatusOK, rd)
}

func ResponseErrorWithMsg(ctx *gin.Context, code MyCode, errMsg string) {
	rd := &ResponseData{
		Code:    code,
		Message: errMsg,
		Data:    nil,
	}
	ctx.JSON(http.StatusOK, rd)
}

func ResponseSuccess(ctx *gin.Context, data any) {
	rd := &ResponseData{
		Code:    CodeSuccess,
		Message: CodeSuccess.Msg(),
		Data:    data,
	}
	ctx.JSON(http.StatusOK, rd)
}
