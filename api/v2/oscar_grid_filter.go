package v2

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/prometheus/alertmanager/alert"
	model "github.com/prometheus/common/model"
	"golang.org/x/text/cases"
)

type oscarGridRule struct {
	field, operator, value string
	valueSet               map[string]struct{}
	dates                  []time.Time
	duration               time.Duration
	labelNames             map[string]bool
}

type oscarGridModel struct {
	rules []oscarGridRule
	or    bool
}

// Python's Unicode casefold keeps Cherokee in uppercase, while x/text's Fold
// can map the same uppercase rune to its lowercase counterpart. Normalize the
// two Cherokee lowercase ranges back to Python's stable fold form.
type oscarCaseFolder struct{ caser cases.Caser }

func newOscarCaseFolder() *oscarCaseFolder {
	return &oscarCaseFolder{caser: cases.Fold()}
}

func (f *oscarCaseFolder) String(value string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 0xAB70 && r <= 0xABBF:
			return r - 0xAB70 + 0x13A0
		case r >= 0x13F8 && r <= 0x13FD:
			return r - 0x13F8 + 0x13F0
		default:
			return r
		}
	}, f.caser.String(value))
}

func parseOscarGridModel(raw string) (oscarGridModel, error) {
	var result oscarGridModel
	if raw == "" {
		return result, nil
	}
	if len(raw) > 65536 || !utf8.ValidString(raw) {
		return result, fmt.Errorf("invalid grid filter size or encoding")
	}
	if !strings.HasPrefix(strings.TrimSpace(raw), "{") {
		return result, fmt.Errorf("grid filter must be an object")
	}
	var wire struct {
		Items         json.RawMessage `json:"items"`
		LogicOperator string          `json:"logicOperator"`
	}
	if err := json.Unmarshal([]byte(raw), &wire); err != nil {
		return result, fmt.Errorf("invalid grid filter: %w", err)
	}
	if wire.LogicOperator != "" && wire.LogicOperator != "and" && wire.LogicOperator != "or" {
		return result, fmt.Errorf("invalid grid logic operator")
	}
	result.or = wire.LogicOperator == "or"
	if len(wire.Items) == 0 {
		return result, nil
	}
	if string(wire.Items) == "null" {
		return result, fmt.Errorf("items must be a list")
	}
	var items []struct {
		Field    string          `json:"field"`
		Operator string          `json:"operator"`
		Value    json.RawMessage `json:"value"`
	}
	if err := json.Unmarshal(wire.Items, &items); err != nil {
		return result, fmt.Errorf("invalid grid filter items: %w", err)
	}
	if len(items) > 100 {
		return result, fmt.Errorf("too many grid filter items")
	}
	fold := newOscarCaseFolder()
	textFields := map[string]bool{"alertname": true, "summary": true, "severity": true, "alert_status": true, "instance": true, "fingerprint": true, "generatorURL": true}
	dateFields := map[string]bool{"starts_at": true, "ends_at": true, "modified_at": true}
	dateOps := map[string]bool{"before": true, "onOrBefore": true, "after": true, "onOrAfter": true, "between": true, "inTheLast": true}
	dateEqualOps := map[string]bool{"is": true, "equals": true, "=": true, "not": true, "!=": true, "doesNotEqual": true}
	for _, item := range items {
		r := oscarGridRule{field: item.Field, operator: item.Operator}
		isLabel := strings.HasPrefix(r.field, "label:") || strings.HasPrefix(r.field, "label_any:")
		isText := textFields[r.field] || isLabel
		isDate := dateFields[r.field]
		if !isText && !isDate {
			return result, fmt.Errorf("unsupported grid field %q", r.field)
		}
		switch r.operator {
		case "equals", "=", "is", "not", "!=", "doesNotEqual", "contains", "doesNotContain", "startsWith", "endsWith", "isEmpty", "isNotEmpty", "isAnyOf", "before", "onOrBefore", "after", "onOrAfter", "between", "inTheLast":
		default:
			return result, fmt.Errorf("unsupported grid operator %q", r.operator)
		}
		if dateOps[r.operator] && !isDate || isDate && (r.operator == "contains" || r.operator == "doesNotContain" || r.operator == "startsWith" || r.operator == "endsWith" || r.operator == "isAnyOf") {
			return result, fmt.Errorf("invalid operator for grid field %q", r.field)
		}
		if isLabel {
			var parts []string
			if strings.HasPrefix(r.field, "label_any:") {
				parts = strings.Split(strings.TrimPrefix(r.field, "label_any:"), ",")
			} else {
				parts = []string{strings.TrimPrefix(r.field, "label:")}
			}
			r.labelNames = map[string]bool{}
			validNames := 0
			for _, name := range parts {
				name = strings.TrimSpace(name)
				if name == "" {
					continue
				}
				validNames++
				if validNames > 8 {
					return result, fmt.Errorf("too many grid label names")
				}
				if utf8.RuneCountInString(name) > 100 {
					return result, fmt.Errorf("grid label name too long")
				}
				r.labelNames[fold.String(name)] = true
			}
			if len(r.labelNames) == 0 {
				return result, fmt.Errorf("grid label name required")
			}
		}
		if r.operator == "isEmpty" || r.operator == "isNotEmpty" {
			result.rules = append(result.rules, r)
			continue
		}
		if r.operator == "isAnyOf" {
			var values []string
			if err := json.Unmarshal(item.Value, &values); err != nil {
				return result, fmt.Errorf("isAnyOf requires text values")
			}
			r.valueSet = make(map[string]struct{}, len(values))
			for _, v := range values {
				r.valueSet[fold.String(v)] = struct{}{}
			}
			result.rules = append(result.rules, r)
			continue
		}
		if r.operator == "between" {
			var values []string
			if err := json.Unmarshal(item.Value, &values); err != nil || len(values) != 2 {
				return result, fmt.Errorf("between requires two UTC dates")
			}
			for _, v := range values {
				dt, err := time.Parse(time.RFC3339Nano, v)
				if err != nil {
					return result, fmt.Errorf("invalid grid date: %w", err)
				}
				r.dates = append(r.dates, dt.UTC())
			}
			if r.dates[0].After(r.dates[1]) {
				r.dates[0], r.dates[1] = r.dates[1], r.dates[0]
			}
			result.rules = append(result.rules, r)
			continue
		}
		if err := json.Unmarshal(item.Value, &r.value); err != nil {
			return result, fmt.Errorf("grid rule requires string value")
		}
		if isDate {
			if r.operator == "inTheLast" {
				if len(r.value) < 2 || len(r.value) > 5 || r.value[0] < '1' || r.value[0] > '9' {
					return result, fmt.Errorf("invalid relative grid date")
				}
				unit := r.value[len(r.value)-1]
				if unit != 'h' && unit != 'd' {
					return result, fmt.Errorf("invalid relative grid date")
				}
				n := 0
				for _, c := range r.value[:len(r.value)-1] {
					if c < '0' || c > '9' {
						return result, fmt.Errorf("invalid relative grid date")
					}
					n = n*10 + int(c-'0')
				}
				if unit == 'd' {
					r.duration = time.Duration(n) * 24 * time.Hour
				} else {
					r.duration = time.Duration(n) * time.Hour
				}
			} else if dateOps[r.operator] || dateEqualOps[r.operator] {
				dt, err := time.Parse(time.RFC3339Nano, r.value)
				if err != nil {
					return result, fmt.Errorf("invalid grid date: %w", err)
				}
				r.dates = []time.Time{dt.UTC()}
			}
		} else {
			r.value = fold.String(r.value)
		}
		result.rules = append(result.rules, r)
	}
	return result, nil
}

func (m oscarGridModel) matches(a *alert.Alert, status alert.AlertStatus, fingerprint string, now time.Time) bool {
	return m.matchesWithFold(a, status, fingerprint, now, newOscarCaseFolder())
}

func (m oscarGridModel) matchesWithFold(a *alert.Alert, status alert.AlertStatus, fingerprint string, now time.Time, fold *oscarCaseFolder) bool {
	if len(m.rules) == 0 {
		return true
	}
	if m.or {
		for _, rule := range m.rules {
			if rule.matches(a, status, fingerprint, now, fold) {
				return true
			}
		}
		return false
	}
	for _, rule := range m.rules {
		if !rule.matches(a, status, fingerprint, now, fold) {
			return false
		}
	}
	return true
}

func (r oscarGridRule) matches(a *alert.Alert, status alert.AlertStatus, fingerprint string, now time.Time, fold *oscarCaseFolder) bool {
	if r.labelNames != nil {
		for name, value := range a.Labels {
			if r.labelNames[fold.String(string(name))] && r.matchText(fold.String(string(value)), true) {
				return true
			}
		}
		return false
	}
	if r.field == "starts_at" || r.field == "ends_at" || r.field == "modified_at" {
		var actual time.Time
		switch r.field {
		case "starts_at":
			actual = a.StartsAt
		case "ends_at":
			actual = a.EndsAt
		default:
			actual = a.UpdatedAt
		}
		return r.matchDate(actual.UTC().Truncate(time.Millisecond), now)
	}
	var value string
	present := true
	switch r.field {
	case "alertname", "severity", "instance":
		v, ok := a.Labels[model.LabelName(r.field)]
		value, present = string(v), ok
	case "summary":
		v, ok := a.Annotations["summary"]
		value, present = string(v), ok
	case "alert_status":
		value = string(status.State)
	case "fingerprint":
		value = fingerprint
	case "generatorURL":
		value = a.GeneratorURL
	}
	return r.matchText(fold.String(value), present)
}

func (r oscarGridRule) matchText(actual string, present bool) bool {
	switch r.operator {
	case "isEmpty":
		return !present
	case "isNotEmpty":
		return present
	case "equals", "=", "is":
		return present && actual == r.value
	case "not", "!=", "doesNotEqual":
		return !present || actual != r.value
	case "contains":
		return present && strings.Contains(actual, r.value)
	case "doesNotContain":
		return !present || !strings.Contains(actual, r.value)
	case "startsWith":
		return present && strings.HasPrefix(actual, r.value)
	case "endsWith":
		return present && strings.HasSuffix(actual, r.value)
	case "isAnyOf":
		_, found := r.valueSet[actual]
		return present && found
	}
	return false
}

func (r oscarGridRule) matchDate(actual, now time.Time) bool {
	switch r.operator {
	case "isEmpty":
		return false
	case "isNotEmpty":
		return true
	case "inTheLast":
		return !actual.Before(now.Add(-r.duration))
	case "between":
		return !actual.Before(r.dates[0]) && !actual.After(r.dates[1])
	case "before":
		return actual.Before(r.dates[0])
	case "onOrBefore":
		return !actual.After(r.dates[0])
	case "after":
		return actual.After(r.dates[0])
	case "onOrAfter":
		return !actual.Before(r.dates[0])
	case "is", "equals", "=", "not", "!=", "doesNotEqual":
		inside := !actual.Before(r.dates[0]) && actual.Before(r.dates[0].Add(time.Minute))
		if r.operator == "not" || r.operator == "!=" || r.operator == "doesNotEqual" {
			return !inside
		}
		return inside
	}
	return false
}
