package policy

import (
	"context"
	"strings"
	"testing"
)

func TestExpressionsAndCostBudget(t *testing.T) {
	p, err := CompileExpression(`in_cidr(client.ip, "192.0.2.0/24") && request.method == "GET"`)
	if err != nil {
		t.Fatal(err)
	}
	matched, err := p.Eval(context.Background(), map[string]any{"client": map[string]any{"ip": "192.0.2.1"}, "request": map[string]any{"method": "GET"}})
	if err != nil || !matched {
		t.Fatal(err)
	}
	for _, s := range []string{"request.path + 1", "42", strings.Repeat("(", 100) + "true" + strings.Repeat(")", 100)} {
		if _, err = CompileExpression(s); err == nil {
			t.Fatalf("invalid expression accepted: %s", s)
		}
	}
	p, err = CompileExpression(`request.values.all(x, request.values.all(y, x == y))`)
	if err != nil {
		t.Fatal(err)
	}
	values := make([]string, 300)
	if _, err = p.Eval(context.Background(), map[string]any{"request": map[string]any{"values": values}}); err == nil {
		t.Fatal("unbounded CEL work")
	}
	if Tunable(949110) || Tunable(901001) || !Tunable(942100) {
		t.Fatal("control rule tuning boundary")
	}
}
func FuzzCompileExpression(f *testing.F) {
	f.Add(`request.path.startsWith("/api")`)
	f.Add("true")
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > 4096 {
			return
		}
		_, _ = CompileExpression(s)
	})
}
