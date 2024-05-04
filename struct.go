package grpcopamiddleware

import "github.com/open-policy-agent/opa/ast"

type GrpcOpaMiddleware struct {
	//PreparedQuery rego.PreparedEvalQuery
	RegoEnv   *ast.Term
	RegoFiles []string
	RegoQuery string
}

type GrpcOpaMiddlewareInput struct {
	RegoEnv   *ast.Term
	RegoFiles []string
	RegoQuery string
}
