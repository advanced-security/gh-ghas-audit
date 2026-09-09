package model

import (
	"reflect"
	"testing"
)

func TestNormalizeLanguageCollapsesAliases(t *testing.T) {
	// The default setup API returns overlapping legacy names alongside the
	// canonical one; all three must collapse to a single language so a
	// repository is not reported as having three JavaScript languages.
	for _, alias := range []string{"javascript", "TypeScript", "javascript-typescript"} {
		got, ok := NormalizeLanguage(alias)
		if !ok || got != LangJavaScriptTypeScript {
			t.Errorf("NormalizeLanguage(%q) = %q, %v; want %q", alias, got, ok, LangJavaScriptTypeScript)
		}
	}

	for _, alias := range []string{"Java", "kotlin", "java-kotlin"} {
		got, ok := NormalizeLanguage(alias)
		if !ok || got != LangJavaKotlin {
			t.Errorf("NormalizeLanguage(%q) = %q, %v; want %q", alias, got, ok, LangJavaKotlin)
		}
	}

	for _, alias := range []string{"C", "C++", "cpp", "c-cpp"} {
		got, ok := NormalizeLanguage(alias)
		if !ok || got != LangCCpp {
			t.Errorf("NormalizeLanguage(%q) = %q, %v; want %q", alias, got, ok, LangCCpp)
		}
	}
}

func TestNormalizeLanguagesDeduplicatesAndSorts(t *testing.T) {
	got := NormalizeLanguages([]string{
		"JavaScript", "TypeScript", "javascript-typescript",
		"Java", "Kotlin",
		"HTML", "CSS", "Dockerfile", "Shell",
		"Python",
	})

	want := []Language{LangJavaKotlin, LangJavaScriptTypeScript, LangPython}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("NormalizeLanguages = %v, want %v", got, want)
	}
}

func TestNormalizeLanguagesDropsUnsupported(t *testing.T) {
	got := NormalizeLanguages([]string{"HTML", "CSS", "Makefile", "Dockerfile"})
	if len(got) != 0 {
		t.Fatalf("unsupported languages must be dropped, got %v", got)
	}
}

func TestIsDetectable(t *testing.T) {
	// Actions cannot be observed from repository source, so it must never be
	// reported as an unconfigured coverage gap.
	if IsDetectable(LangActions) {
		t.Error("actions must not be treated as detectable from source")
	}
	if !IsDetectable(LangGo) {
		t.Error("go must be detectable from source")
	}
}

func TestLanguageSetSortedIsStable(t *testing.T) {
	set := LanguageSet{}
	set.Get(LangPython).Configured = true
	set.Get(LangActions).Configured = true
	set.Get(LangJavaKotlin).Detected = true

	first := set.Sorted()
	want := []Language{LangActions, LangJavaKotlin, LangPython}
	for index, state := range first {
		if state.Language != want[index] {
			t.Fatalf("position %d = %q, want %q", index, state.Language, want[index])
		}
	}

	for attempt := 0; attempt < 5; attempt++ {
		repeat := set.Sorted()
		if !reflect.DeepEqual(repeat, first) {
			t.Fatal("language ordering must be stable across calls")
		}
	}
}

func TestJoinLanguages(t *testing.T) {
	if got := JoinLanguages(nil); got != "" {
		t.Errorf("JoinLanguages(nil) = %q, want empty", got)
	}
	got := JoinLanguages([]Language{LangGo, LangPython})
	if got != "go, python" {
		t.Errorf("JoinLanguages = %q, want \"go, python\"", got)
	}
}
