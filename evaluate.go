package grpcopamiddleware

import (
	"context"
	"fmt"

	"github.com/open-policy-agent/opa/rego"
)

func (m *GrpcOpaMiddleware) Evaluate(ctx context.Context, input map[string]interface{}) (bool, map[string]interface{}, error) {
	allow := false
	var bindings map[string]interface{}

	query, err := rego.New(
		rego.Load(m.RegoFiles, nil),
		rego.Runtime(m.RegoEnv),
		rego.Query(m.RegoQuery),
	).PrepareForEval(ctx)
	if err != nil {
		return allow, bindings, err
	}

	rs, err := query.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return allow, bindings, err
	} else if len(rs) == 0 {
		return allow, bindings, fmt.Errorf("no result")
	}

	if rs[0].Expressions[0].Value == nil {
		return allow, bindings, fmt.Errorf("no value")
	}

	bindings = rs[0].Expressions[0].Value.(map[string]interface{})

	if _, ok := bindings["allow"]; !ok {
		return allow, bindings, fmt.Errorf("no allow key")
	}

	allow = bindings["allow"].(bool)
	delete(bindings, "allow")

	return allow, bindings, nil
}
