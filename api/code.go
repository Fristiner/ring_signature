package api

type MyCode int64

const (
	CodeSuccess MyCode = 1000

	CodeDeSignERROR = 1001

	CodeServerBusy MyCode = 1005
)

var msgFlags = map[MyCode]string{
	CodeSuccess:    "success",
	CodeServerBusy: "服务繁忙",
}

func (c MyCode) Msg() string {
	msg, ok := msgFlags[c]
	if ok {
		return msg
	}
	return msgFlags[CodeServerBusy]
}
