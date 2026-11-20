package v2

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestManagedOperationVectors(t *testing.T) {
	var v struct {
		Valid   map[string]any
		Invalid []map[string]any
	}
	raw, err := os.ReadFile("testdata/managed_operation_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	check := func(fields map[string]any, want bool) {
		t.Helper()
		raw, err := json.Marshal(fields)
		if err != nil {
			t.Fatal(err)
		}
		if got := validManagedOperation(string(raw), "smtpreceiver", 100); got != want {
			t.Fatalf("accept=%v fields=%s", got, raw)
		}
	}
	check(v.Valid, true)
	for _, bad := range v.Invalid {
		fields := make(map[string]any)
		for k, val := range v.Valid {
			fields[k] = val
		}
		for k, val := range bad {
			fields[k] = val
		}
		check(fields, false)
	}
	good, _ := json.Marshal(v.Valid)
	if validManagedOperation(strings.Replace(string(good), "{", `{"producer":"smtpreceiver",`, 1), "smtpreceiver", 100) || validManagedOperation(string(good), "smtpreceiver", 110) {
		t.Fatal("duplicate key or expired operation accepted")
	}
}
