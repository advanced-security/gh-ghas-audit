package collector

import (
	"testing"
	"time"
)

// scenarioWithProperties builds an organization whose custom properties use
// mixed-case names and multi-select values, matching what the API actually
// returns.
func propertyClient(t *testing.T) *fakeClient {
	t.Helper()

	client := buildClient(t,
		scenario{
			name: "wuphf-com", languages: []string{"Go"},
			defaultSetup: defaultSetup{State: "configured", Languages: []string{"go"}},
			workflows:    codeqlWorkflows(),
			runs:         map[string]any{"": runList("success", time.Hour)},
			jobs:         jobsFor(map[string]string{"go": "success"}),
			databases:    databasesFor([]string{"go"}, time.Hour),
		},
		scenario{
			name: "infinity", languages: []string{"Go"},
			defaultSetup: defaultSetup{State: "configured", Languages: []string{"go"}},
			workflows:    codeqlWorkflows(),
			runs:         map[string]any{"": runList("success", time.Hour)},
			jobs:         jobsFor(map[string]string{"go": "success"}),
			databases:    databasesFor([]string{"go"}, time.Hour),
		},
	)

	// Mixed-case name, multi-select values, exactly as the properties API
	// returns them.
	client.set("orgs/"+testOrg+"/properties/values?", []propertyValues{
		{
			RepositoryName: "wuphf-com",
			Properties: []struct {
				PropertyName string `json:"property_name"`
				Value        any    `json:"value"`
			}{
				{PropertyName: "Project", Value: []any{"WUPH"}},
				{PropertyName: "BU", Value: []any{"Corporate"}},
			},
		},
		{
			RepositoryName: "infinity",
			Properties: []struct {
				PropertyName string `json:"property_name"`
				Value        any    `json:"value"`
			}{
				{PropertyName: "Project", Value: []any{"INFINITY", "Internal"}},
				{PropertyName: "BU", Value: []any{"IT"}},
			},
		},
	})

	return client
}

// The user's own spelling of a property must not decide whether it matches.
func TestPropertyFilterIsCaseInsensitive(t *testing.T) {
	for _, filter := range []string{"Project=WUPH", "project=wuph", "PROJECT=WUPH"} {
		report := collect(t, propertyClient(t), Options{
			PropertyFilters: map[string][]string{
				splitFilterName(filter): {splitFilterValue(filter)},
			},
		})

		if len(report.Repositories) != 1 {
			t.Fatalf("%s selected %d repositories, want 1", filter, len(report.Repositories))
		}
		if report.Repositories[0].Name != "wuphf-com" {
			t.Errorf("%s selected %q, want wuphf-com", filter, report.Repositories[0].Name)
		}
	}
}

// A multi-select property holds several values, so a filter must match any one
// of them rather than the joined string.
func TestPropertyFilterMatchesOneValueOfAMultiSelect(t *testing.T) {
	report := collect(t, propertyClient(t), Options{
		PropertyFilters: map[string][]string{"Project": {"Internal"}},
	})

	if len(report.Repositories) != 1 || report.Repositories[0].Name != "infinity" {
		t.Fatalf("expected the repository whose Project includes Internal, got %d: %+v",
			len(report.Repositories), report.Repositories)
	}
}

// Recording the property under the user's casing would make output columns
// disagree with the organization's settings.
func TestCollectedPropertiesKeepTheOrganizationSpelling(t *testing.T) {
	report := collect(t, propertyClient(t), Options{Properties: []string{"project"}})

	repo := findRepo(t, report, "wuphf-com")
	if _, ok := repo.Properties["Project"]; !ok {
		t.Fatalf("properties should be stored as Project, got %v", repo.Properties)
	}
	if repo.Properties["Project"] != "WUPH" {
		t.Errorf("Project = %q, want WUPH", repo.Properties["Project"])
	}
	if _, ok := repo.Properties["BU"]; ok {
		t.Error("only the requested properties should be recorded")
	}
}

func TestGroupingUsesPropertyValuesRegardlessOfCasing(t *testing.T) {
	report := collect(t, propertyClient(t), Options{GroupByProperty: "PROJECT"})

	for _, group := range report.Summary.Groups {
		if group.Value == "(not set)" {
			t.Fatalf("a case mismatch must not group everything as (not set): %+v", report.Summary.Groups)
		}
		if group.Property != "Project" {
			t.Errorf("group label = %q, want Project", group.Property)
		}
	}
	if len(report.Summary.Groups) != 2 {
		t.Errorf("got %d groups, want 2", len(report.Summary.Groups))
	}
}

func TestPropertyMatchesHandlesMultiSelectAndGlobs(t *testing.T) {
	cases := []struct {
		value    string
		patterns []string
		want     bool
	}{
		{"WUPH", []string{"WUPH"}, true},
		{"WUPH", []string{"wuph"}, true},
		{"INFINITY, Internal", []string{"Internal"}, true},
		{"INFINITY, Internal", []string{"internal"}, true},
		{"INFINITY, Internal", []string{"WUPH"}, false},
		{"WUPH", []string{"WU*"}, true},
		{"", []string{"WUPH"}, false},
	}

	for _, test := range cases {
		if got := propertyMatches(test.value, test.patterns); got != test.want {
			t.Errorf("propertyMatches(%q, %v) = %v, want %v", test.value, test.patterns, got, test.want)
		}
	}
}

func splitFilterName(filter string) string {
	for index := 0; index < len(filter); index++ {
		if filter[index] == '=' {
			return filter[:index]
		}
	}
	return filter
}

func splitFilterValue(filter string) string {
	for index := 0; index < len(filter); index++ {
		if filter[index] == '=' {
			return filter[index+1:]
		}
	}
	return ""
}
