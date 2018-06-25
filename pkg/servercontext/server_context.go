package servercontext

import (
	"context"
)

type serverContextKey int

const (
	contextKeyId = serverContextKey(iota)
	contextKeyDn
	contextKeyAddr
)

func SetDn(ctx context.Context, dn string) context.Context {
	return context.WithValue(ctx, contextKeyDn, dn)
}

func GetDn(ctx context.Context) string {
	value := ctx.Value(contextKeyDn)
	if value == nil {
		return ""
	} else {
		return value.(string)
	}
}

func SetAddr(ctx context.Context, addr string) context.Context {
	return context.WithValue(ctx, contextKeyAddr, addr)
}

func GetAddr(ctx context.Context) string {
	value := ctx.Value(contextKeyAddr)
	if value == nil {
		return ""
	} else {
		return value.(string)
	}
}
