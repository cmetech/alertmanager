package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/prometheus/common/model"

	"github.com/prometheus/alertmanager/config/common"
	"github.com/prometheus/alertmanager/matcher/compat"
	"github.com/prometheus/alertmanager/pkg/labels"
)

const (
	// ManagedInhibitionPrefix reserves names for OSCAR-managed rule revisions.
	ManagedInhibitionPrefix = "oscar-inh-"
	// ManagedInhibitionMaxRules bounds one complete managed set.
	ManagedInhibitionMaxRules = 500
	// ManagedInhibitionMaxMatchers bounds each side after scope enforcement.
	ManagedInhibitionMaxMatchers = 20
	// ManagedInhibitionMaxEqual bounds the shared label set.
	ManagedInhibitionMaxEqual = 20
	// ManagedInhibitionMaxBodyBytes bounds the structured managed payload.
	ManagedInhibitionMaxBodyBytes = 1 << 20
)

var managedInhibitionName = regexp.MustCompile(`^oscar-inh-([1-9][0-9]*)-r[1-9][0-9]*$`)

// ManagedInhibitionMatcher is a structured matcher, avoiding matcher-string interpolation.
type ManagedInhibitionMatcher struct {
	Label    string `json:"label"`
	Operator string `json:"operator"`
	Value    string `json:"value"`
}

// ManagedInhibitionRule contains one named revision of an OSCAR rule.
type ManagedInhibitionRule struct {
	Name           string                     `json:"name"`
	SourceMatchers []ManagedInhibitionMatcher `json:"source_matchers"`
	TargetMatchers []ManagedInhibitionMatcher `json:"target_matchers"`
	Equal          []string                   `json:"equal"`
}

// ManagedInhibitionRules is a JSON input boundary that requires matcher values
// without changing the compiler's explicit-empty-string matcher semantics.
type ManagedInhibitionRules []ManagedInhibitionRule

// UnmarshalJSON preserves required-value presence for HTTP and persisted rules.
func (rules *ManagedInhibitionRules) UnmarshalJSON(data []byte) error {
	type matcherInput struct {
		Label    string  `json:"label"`
		Operator string  `json:"operator"`
		Value    *string `json:"value"`
	}
	var input []struct {
		Name           string         `json:"name"`
		SourceMatchers []matcherInput `json:"source_matchers"`
		TargetMatchers []matcherInput `json:"target_matchers"`
		Equal          []string       `json:"equal"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		return err
	}
	if input == nil {
		*rules = nil
		return nil
	}
	convert := func(matchers []matcherInput, field string) ([]ManagedInhibitionMatcher, error) {
		result := make([]ManagedInhibitionMatcher, len(matchers))
		for index, matcher := range matchers {
			if matcher.Value == nil {
				return nil, managedInvalid(fmt.Sprintf("%s.%d.value", field, index), "matcher value must be an explicit string")
			}
			result[index] = ManagedInhibitionMatcher{Label: matcher.Label, Operator: matcher.Operator, Value: *matcher.Value}
		}
		return result, nil
	}
	result := make(ManagedInhibitionRules, len(input))
	for index, rule := range input {
		field := fmt.Sprintf("rules.%d", index)
		source, err := convert(rule.SourceMatchers, field+".source_matchers")
		if err != nil {
			return err
		}
		target, err := convert(rule.TargetMatchers, field+".target_matchers")
		if err != nil {
			return err
		}
		result[index] = ManagedInhibitionRule{Name: rule.Name, SourceMatchers: source, TargetMatchers: target, Equal: rule.Equal}
	}
	*rules = result
	return nil
}

// ManagedInhibitionSet is a complete replacement, including an explicit empty set.
type ManagedInhibitionSet struct {
	Rules []ManagedInhibitionRule `json:"rules"`
}

// CompiledManagedInhibition retains canonical definitions and native matcher objects.
// Digest is semantic content identity, never a concurrency token.
type CompiledManagedInhibition struct {
	Definition ManagedInhibitionSet
	Rules      []common.InhibitRule
	Digest     string
}

// ManagedInhibitionValidationError identifies a structural/native validation failure.
type ManagedInhibitionValidationError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

func (e *ManagedInhibitionValidationError) Error() string {
	return e.Field + ": " + e.Message
}

func managedInvalid(field, message string) error {
	return &ManagedInhibitionValidationError{Field: field, Message: message}
}

func managedMatchers(input []ManagedInhibitionMatcher, equal []string, field string) ([]ManagedInhibitionMatcher, common.Matchers, error) {
	if len(input) == 0 || len(input) > ManagedInhibitionMaxMatchers {
		return nil, nil, managedInvalid(field, "matcher count outside supported limits")
	}
	terms := make(map[ManagedInhibitionMatcher]*labels.Matcher, len(input)+len(equal))
	for index, term := range input {
		itemField := fmt.Sprintf("%s.%d", field, index)
		if !utf8.ValidString(term.Label) || !compat.IsValidLabelName(model.LabelName(term.Label)) {
			return nil, nil, managedInvalid(itemField+".label", "invalid label name")
		}
		if !utf8.ValidString(term.Value) {
			return nil, nil, managedInvalid(itemField+".value", "invalid UTF-8")
		}
		var kind labels.MatchType
		switch term.Operator {
		case "=":
			kind = labels.MatchEqual
		case "!=":
			kind = labels.MatchNotEqual
		case "=~":
			kind = labels.MatchRegexp
		case "!~":
			kind = labels.MatchNotRegexp
		default:
			return nil, nil, managedInvalid(itemField+".operator", "unsupported operator")
		}
		if slices.Contains(equal, term.Label) && kind == labels.MatchEqual && term.Value == "" {
			return nil, nil, managedInvalid(itemField, "shared scope cannot require an empty value")
		}
		matcher, err := labels.NewMatcher(kind, term.Label, term.Value)
		if err != nil {
			return nil, nil, managedInvalid(itemField+".value", err.Error())
		}
		terms[term] = matcher
	}
	for _, label := range equal {
		term := ManagedInhibitionMatcher{Label: label, Operator: "!=", Value: ""}
		matcher, err := labels.NewMatcher(labels.MatchNotEqual, label, "")
		if err != nil {
			return nil, nil, managedInvalid(field, err.Error())
		}
		terms[term] = matcher
	}
	if len(terms) > ManagedInhibitionMaxMatchers {
		return nil, nil, managedInvalid(field, "matcher limit exceeded after enforcing shared scope")
	}
	canonical := make([]ManagedInhibitionMatcher, 0, len(terms))
	for term := range terms {
		canonical = append(canonical, term)
	}
	slices.SortFunc(canonical, func(a, b ManagedInhibitionMatcher) int {
		if order := strings.Compare(a.Label, b.Label); order != 0 {
			return order
		}
		if order := strings.Compare(a.Operator, b.Operator); order != 0 {
			return order
		}
		return strings.Compare(a.Value, b.Value)
	})
	native := make(common.Matchers, 0, len(canonical))
	for _, term := range canonical {
		native = append(native, terms[term])
	}
	return canonical, native, nil
}

// CompileManagedInhibition validates and compiles with the native label/RE2 implementation.
// It has no filesystem, runtime activation or persistence side effects.
func CompileManagedInhibition(input ManagedInhibitionSet) (*CompiledManagedInhibition, error) {
	if len(input.Rules) > ManagedInhibitionMaxRules {
		return nil, managedInvalid("rules", "managed rule limit exceeded")
	}
	encoded, err := json.Marshal(input)
	if err != nil {
		return nil, managedInvalid("rules", "cannot encode managed rules")
	}
	if len(encoded) > ManagedInhibitionMaxBodyBytes {
		return nil, managedInvalid("rules", "managed payload byte limit exceeded")
	}
	result := &CompiledManagedInhibition{Definition: ManagedInhibitionSet{Rules: []ManagedInhibitionRule{}}, Rules: []common.InhibitRule{}}
	seen := make(map[string]struct{}, len(input.Rules))
	byName := make(map[string]common.InhibitRule, len(input.Rules))
	for index, rule := range input.Rules {
		field := fmt.Sprintf("rules.%d", index)
		identity := managedInhibitionName.FindStringSubmatch(rule.Name)
		if len(rule.Name) > 128 || identity == nil {
			return nil, managedInvalid(field+".name", "expected oscar-inh-<id>-r<revision>")
		}
		if _, exists := seen[identity[1]]; exists {
			return nil, managedInvalid(field+".name", "duplicate rule identity")
		}
		seen[identity[1]] = struct{}{}
		if len(rule.Equal) == 0 || len(rule.Equal) > ManagedInhibitionMaxEqual {
			return nil, managedInvalid(field+".equal", "shared label count outside supported limits")
		}
		equal := slices.Clone(rule.Equal)
		for _, name := range equal {
			if !utf8.ValidString(name) || !compat.IsValidLabelName(model.LabelName(name)) {
				return nil, managedInvalid(field+".equal", "invalid shared label name")
			}
		}
		slices.Sort(equal)
		equal = slices.Compact(equal)
		source, nativeSource, err := managedMatchers(rule.SourceMatchers, equal, field+".source_matchers")
		if err != nil {
			return nil, err
		}
		target, nativeTarget, err := managedMatchers(rule.TargetMatchers, equal, field+".target_matchers")
		if err != nil {
			return nil, err
		}
		result.Definition.Rules = append(result.Definition.Rules, ManagedInhibitionRule{
			Name: rule.Name, SourceMatchers: source, TargetMatchers: target, Equal: equal,
		})
		byName[rule.Name] = common.InhibitRule{Name: rule.Name, SourceMatchers: nativeSource, TargetMatchers: nativeTarget, Equal: equal}
	}
	slices.SortFunc(result.Definition.Rules, func(a, b ManagedInhibitionRule) int { return strings.Compare(a.Name, b.Name) })
	for _, rule := range result.Definition.Rules {
		result.Rules = append(result.Rules, byName[rule.Name])
	}
	encoded, err = json.Marshal(result.Definition)
	if err != nil || len(encoded) > ManagedInhibitionMaxBodyBytes {
		return nil, managedInvalid("rules", "compiled payload byte limit exceeded")
	}
	digest := sha256.Sum256(encoded)
	result.Digest = "sha256:" + hex.EncodeToString(digest[:])
	return result, nil
}
