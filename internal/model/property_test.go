package model

import "testing"

// Organizations define custom property names in whatever case they like, and
// nobody remembers which. An exact-match lookup silently reports every
// repository as having no value, which looks like missing data rather than a
// bug.
func TestPropertyValueIsCaseInsensitive(t *testing.T) {
	properties := map[string]string{"Project": "WUPH", "BU": "IT"}

	for _, name := range []string{"Project", "project", "PROJECT", "pRoJeCt"} {
		value, ok := PropertyValue(properties, name)
		if !ok || value != "WUPH" {
			t.Errorf("PropertyValue(%q) = %q, %v; want WUPH", name, value, ok)
		}
	}

	if _, ok := PropertyValue(properties, "Missing"); ok {
		t.Error("an absent property must report itself as absent")
	}
	if _, ok := PropertyValue(nil, "Project"); ok {
		t.Error("a nil property map must report itself as absent")
	}
}

// Output should show the organization's own spelling, not the user's.
func TestPropertyKeyReturnsCanonicalCasing(t *testing.T) {
	properties := map[string]string{"Project": "WUPH"}

	if got := PropertyKey(properties, "PROJECT"); got != "Project" {
		t.Errorf("PropertyKey = %q, want Project", got)
	}
	if got := PropertyKey(properties, "Unknown"); got != "Unknown" {
		t.Errorf("an unknown property should be echoed back, got %q", got)
	}
}

func TestBuildSummaryGroupsCaseInsensitivelyWithCanonicalLabel(t *testing.T) {
	repos := []Repo{
		{Name: "a", Status: Status{Overall: SeverityHealthy}, Properties: map[string]string{"Project": "WUPH"}},
		{Name: "b", Status: Status{Overall: SeverityFailing}, Properties: map[string]string{"Project": "WUPH"}},
		{Name: "c", Status: Status{Overall: SeverityHealthy}, Properties: map[string]string{"Project": "Internal"}},
		{Name: "d", Status: Status{Overall: SeverityHealthy}, Properties: map[string]string{}},
	}

	// The user typed the property in the wrong case.
	summary := BuildSummary(repos, "PROJECT")

	if len(summary.Groups) != 3 {
		t.Fatalf("got %d groups, want WUPH, Internal and (not set): %+v", len(summary.Groups), summary.Groups)
	}

	byValue := map[string]GroupSummary{}
	for _, group := range summary.Groups {
		byValue[group.Value] = group
		if group.Property != "Project" {
			t.Errorf("group label = %q, want the organization's spelling Project", group.Property)
		}
	}

	if byValue["WUPH"].Repositories != 2 {
		t.Errorf("WUPH group = %d repositories, want 2", byValue["WUPH"].Repositories)
	}
	if byValue["WUPH"].NeedsAttention != 1 {
		t.Errorf("WUPH group = %d needing attention, want 1", byValue["WUPH"].NeedsAttention)
	}
	if byValue["Internal"].Repositories != 1 {
		t.Errorf("Internal group = %d repositories, want 1", byValue["Internal"].Repositories)
	}
	if byValue["(not set)"].Repositories != 1 {
		t.Errorf("(not set) group = %d repositories, want 1", byValue["(not set)"].Repositories)
	}
}

// Every repository landing in "(not set)" is what a case mismatch looks like,
// so it is worth asserting that correct casing never produces it.
func TestBuildSummaryDoesNotSilentlyGroupEverythingAsNotSet(t *testing.T) {
	repos := []Repo{
		{Name: "a", Properties: map[string]string{"Project": "WUPH"}},
		{Name: "b", Properties: map[string]string{"Project": "INFINITY"}},
	}

	summary := BuildSummary(repos, "Project")
	for _, group := range summary.Groups {
		if group.Value == "(not set)" {
			t.Fatalf("repositories with property values must not be grouped as (not set): %+v", summary.Groups)
		}
	}
}
