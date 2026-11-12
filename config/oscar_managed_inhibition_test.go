package config

import (
	"strings"
	"testing"

	"github.com/prometheus/common/model"
	"github.com/stretchr/testify/require"

	"github.com/prometheus/alertmanager/pkg/labels"
)

func managedRuleFixture() ManagedInhibitionRule {
	return ManagedInhibitionRule{
		Name:           "oscar-inh-7-r3",
		SourceMatchers: []ManagedInhibitionMatcher{{Label: "alertname", Operator: "=", Value: "SiteDown"}},
		TargetMatchers: []ManagedInhibitionMatcher{{Label: "alertname", Operator: "=~", Value: "DeviceDown|LinkDown"}},
		Equal:          []string{"site"},
	}
}

func TestManagedInhibitionUsesNativeMatchersAndNonemptyScope(t *testing.T) {
	t.Parallel()
	compiled, err := CompileManagedInhibition(ManagedInhibitionSet{Rules: []ManagedInhibitionRule{managedRuleFixture()}})
	require.NoError(t, err)
	require.Len(t, compiled.Rules, 1)
	source := labels.Matchers(compiled.Rules[0].SourceMatchers)
	target := labels.Matchers(compiled.Rules[0].TargetMatchers)
	require.False(t, source.Matches(model.LabelSet{"alertname": "SiteDown"}))
	require.False(t, target.Matches(model.LabelSet{"alertname": "DeviceDown", "site": ""}))
	require.True(t, source.Matches(model.LabelSet{"alertname": "SiteDown", "site": "west"}))
	require.True(t, target.Matches(model.LabelSet{"alertname": "LinkDown", "site": "west"}))
	require.False(t, target.Matches(model.LabelSet{"alertname": "Other", "site": "west"}))
}

func TestManagedInhibitionRejectsInvalidOrUnscopedRules(t *testing.T) {
	t.Parallel()
	for name, mutate := range map[string]func(*ManagedInhibitionRule){
		"external name":      func(r *ManagedInhibitionRule) { r.Name = "external" },
		"zero revision":      func(r *ManagedInhibitionRule) { r.Name = "oscar-inh-7-r0" },
		"missing scope":      func(r *ManagedInhibitionRule) { r.Equal = nil },
		"empty scope":        func(r *ManagedInhibitionRule) { r.Equal = []string{""} },
		"empty matcher side": func(r *ManagedInhibitionRule) { r.SourceMatchers = nil },
		"unknown operator":   func(r *ManagedInhibitionRule) { r.TargetMatchers[0].Operator = "contains" },
		"invalid RE2":        func(r *ManagedInhibitionRule) { r.TargetMatchers[0].Value = "(?=unsupported)" },
		"invalid label":      func(r *ManagedInhibitionRule) { r.TargetMatchers[0].Label = "" },
		"invalid UTF8":       func(r *ManagedInhibitionRule) { r.SourceMatchers[0].Value = string([]byte{0xff}) },
		"empty scope required": func(r *ManagedInhibitionRule) {
			r.SourceMatchers = append(r.SourceMatchers, ManagedInhibitionMatcher{Label: "site", Operator: "=", Value: ""})
		},
	} {
		t.Run(name, func(t *testing.T) {
			rule := managedRuleFixture()
			mutate(&rule)
			_, err := CompileManagedInhibition(ManagedInhibitionSet{Rules: []ManagedInhibitionRule{rule}})
			require.Error(t, err)
		})
	}
}

func TestManagedInhibitionCanonicalDigestDoesNotDependOnOrder(t *testing.T) {
	t.Parallel()
	one := managedRuleFixture()
	one.Equal = []string{"site", "tenant"}
	one.SourceMatchers = append(one.SourceMatchers, ManagedInhibitionMatcher{Label: "kind", Operator: "!=", Value: "test"})
	first, err := CompileManagedInhibition(ManagedInhibitionSet{Rules: []ManagedInhibitionRule{one}})
	require.NoError(t, err)
	one.Equal = []string{"tenant", "site", "site"}
	one.SourceMatchers[0], one.SourceMatchers[1] = one.SourceMatchers[1], one.SourceMatchers[0]
	one.SourceMatchers = append(one.SourceMatchers, ManagedInhibitionMatcher{Label: "site", Operator: "!=", Value: ""})
	second, err := CompileManagedInhibition(ManagedInhibitionSet{Rules: []ManagedInhibitionRule{one}})
	require.NoError(t, err)
	require.Equal(t, first.Digest, second.Digest)
	one.TargetMatchers[0].Value = "AnotherChild"
	changed, err := CompileManagedInhibition(ManagedInhibitionSet{Rules: []ManagedInhibitionRule{one}})
	require.NoError(t, err)
	require.NotEqual(t, first.Digest, changed.Digest)
}

func TestManagedInhibitionRejectsDuplicateIdentityAndAggregateLimits(t *testing.T) {
	t.Parallel()
	one, two := managedRuleFixture(), managedRuleFixture()
	two.Name = "oscar-inh-7-r4"
	_, err := CompileManagedInhibition(ManagedInhibitionSet{Rules: []ManagedInhibitionRule{one, two}})
	require.Error(t, err)
	_, err = CompileManagedInhibition(ManagedInhibitionSet{Rules: make([]ManagedInhibitionRule, ManagedInhibitionMaxRules+1)})
	require.Error(t, err)
	one.TargetMatchers[0].Value = strings.Repeat("x", ManagedInhibitionMaxBodyBytes)
	_, err = CompileManagedInhibition(ManagedInhibitionSet{Rules: []ManagedInhibitionRule{one}})
	require.Error(t, err)
}

func TestManagedInhibitionEmptySetIsExplicitAndStable(t *testing.T) {
	t.Parallel()
	nilSet, err := CompileManagedInhibition(ManagedInhibitionSet{})
	require.NoError(t, err)
	emptySet, err := CompileManagedInhibition(ManagedInhibitionSet{Rules: []ManagedInhibitionRule{}})
	require.NoError(t, err)
	require.NotNil(t, nilSet.Definition.Rules)
	require.Equal(t, nilSet.Digest, emptySet.Digest)
}
