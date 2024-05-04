package grpcopamiddleware

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/open-policy-agent/opa/ast"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

func New(input GrpcOpaMiddlewareInput) (*GrpcOpaMiddleware, error) {
	var opaMiddleware GrpcOpaMiddleware

	// Process the env variables to send to OPA
	obj := ast.NewObject()
	env := ast.NewObject()

	for _, s := range os.Environ() {
		parts := strings.Split(s, "=")
		if len(parts) == 1 {
			env.Insert(ast.StringTerm(parts[0]), ast.NullTerm())
		} else {
			env.Insert(ast.StringTerm(parts[0]), ast.StringTerm(parts[1]))
		}
	}

	obj.Insert(ast.StringTerm("env"), ast.NewTerm(env))

	opaMiddleware.RegoEnv = ast.NewTerm(obj)

	opaMiddleware.RegoFiles = input.RegoFiles
	opaMiddleware.RegoQuery = input.RegoQuery

	return &opaMiddleware, nil
}

func (m *GrpcOpaMiddleware) UnaryServerInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	input := make(map[string]any)

	md, ok := metadata.FromIncomingContext(ctx)
	if ok {
		authHeader := md.Get("Authorization")
		if len(authHeader) > 0 {
			input["jwt"] = authHeader[0]
		}
	}

	input["endpoint"] = info.FullMethod

	auth, bindings, err := m.Evaluate(ctx, input)
	if err != nil {
		return nil, err
	}

	if !auth {
		return nil, fmt.Errorf("unauthorized")
	}

	var bindingSlice []string
	if claims, ok := bindings["claims"]; ok {
		for k, v := range claims.(map[string]interface{}) {
			bindingSlice = append(bindingSlice, k, fmt.Sprint(v))
		}
	}

	md.Set("bindings", bindingSlice...)

	newCtx := metadata.NewIncomingContext(ctx, md)

	return handler(newCtx, req)
}
