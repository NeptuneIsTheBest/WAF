package policy

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/common/types/ref"
	"waf/internal/config"
)

type Expression struct{ program cel.Program }

func CompileExpression(source string) (*Expression, error) {
	if source == "" {
		source = "true"
	}
	if len(source) > 4096 {
		return nil, errors.New("expression exceeds 4096 bytes")
	}
	env, e := cel.NewEnv(cel.Variable("request", cel.MapType(cel.StringType, cel.DynType)), cel.Variable("client", cel.MapType(cel.StringType, cel.DynType)), cel.ParserRecursionLimit(32), cel.ParserExpressionSizeLimit(4096), cel.Function("in_cidr", cel.Overload("in_cidr_string_string", []*cel.Type{cel.StringType, cel.StringType}, cel.BoolType, cel.BinaryBinding(func(a, b ref.Val) ref.Val {
		ip, err := netip.ParseAddr(string(a.(types.String)))
		if err != nil {
			return types.False
		}
		p, err := netip.ParsePrefix(string(b.(types.String)))
		if err != nil {
			return types.False
		}
		return types.Bool(p.Contains(ip))
	}))))
	if e != nil {
		return nil, e
	}
	ast, issues := env.Compile(source)
	if issues != nil && issues.Err() != nil {
		return nil, issues.Err()
	}
	if ast.OutputType() != cel.BoolType {
		return nil, errors.New("expression must return bool")
	}
	p, e := env.Program(ast, cel.CostLimit(10000), cel.InterruptCheckFrequency(32))
	if e != nil {
		return nil, e
	}
	return &Expression{program: p}, nil
}
func (e *Expression) Eval(ctx context.Context, data map[string]any) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Millisecond)
	defer cancel()
	v, _, err := e.program.ContextEval(ctx, data)
	if err != nil {
		return false, err
	}
	b, ok := v.Value().(bool)
	if !ok {
		return false, errors.New("expression result is not bool")
	}
	return b, nil
}
func RequestData(r *http.Request, ip string) map[string]any {
	headers := map[string]any{}
	for k, v := range r.Header {
		headers[strings.ToLower(k)] = v
	}
	query := map[string]any{}
	for k, v := range r.URL.Query() {
		query[k] = v
	}
	return map[string]any{"client": map[string]any{"ip": ip}, "request": map[string]any{"host": config.Host(r.Host), "method": r.Method, "path": config.CanonicalPath(r.URL.Path), "raw_path": r.URL.EscapedPath(), "query": query, "raw_query": r.URL.RawQuery, "headers": headers, "user_agent": r.UserAgent(), "protocol": r.Proto, "tls": r.TLS != nil}}
}
