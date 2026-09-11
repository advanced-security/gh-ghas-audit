package model

import (
	"encoding/json"
	"sort"
	"strings"
)

// Language is a canonical CodeQL language identifier, matching the values used
// by the code scanning default setup API (for example "javascript-typescript").
type Language string

// Canonical CodeQL languages supported by default setup.
const (
	LangActions              Language = "actions"
	LangCCpp                 Language = "c-cpp"
	LangCSharp               Language = "csharp"
	LangGo                   Language = "go"
	LangJavaKotlin           Language = "java-kotlin"
	LangJavaScriptTypeScript Language = "javascript-typescript"
	LangPython               Language = "python"
	LangRuby                 Language = "ruby"
	LangRust                 Language = "rust"
	LangSwift                Language = "swift"
)

// languageAliases maps every name we might receive - from the repository
// languages API (Linguist names), from the default setup API, and from Actions
// job names - onto a canonical CodeQL language.
//
// The default setup API returns overlapping legacy values such as "javascript"
// and "typescript" alongside "javascript-typescript"; collapsing them here is
// what stops a single repository being reported as having several distinct
// JavaScript languages.
var languageAliases = map[string]Language{
	"actions":               LangActions,
	"github actions":        LangActions,
	"c":                     LangCCpp,
	"c++":                   LangCCpp,
	"cpp":                   LangCCpp,
	"c-cpp":                 LangCCpp,
	"c#":                    LangCSharp,
	"csharp":                LangCSharp,
	"go":                    LangGo,
	"golang":                LangGo,
	"java":                  LangJavaKotlin,
	"kotlin":                LangJavaKotlin,
	"java-kotlin":           LangJavaKotlin,
	"javascript":            LangJavaScriptTypeScript,
	"typescript":            LangJavaScriptTypeScript,
	"javascript-typescript": LangJavaScriptTypeScript,
	"python":                LangPython,
	"ruby":                  LangRuby,
	"rust":                  LangRust,
	"swift":                 LangSwift,
}

// languageOrder gives a stable, human-friendly ordering for output.
var languageOrder = []Language{
	LangActions,
	LangCCpp,
	LangCSharp,
	LangGo,
	LangJavaKotlin,
	LangJavaScriptTypeScript,
	LangPython,
	LangRuby,
	LangRust,
	LangSwift,
}

// undetectableLanguages cannot be discovered from the repository languages
// API, because they are not source languages Linguist reports. They are
// therefore excluded from "supported language is not configured" gap analysis
// to avoid reporting a gap that cannot be verified.
var undetectableLanguages = map[Language]bool{
	LangActions: true,
}

// NormalizeLanguage maps an arbitrary language name onto a canonical CodeQL
// language. The second return value is false for languages CodeQL cannot
// analyze, which the caller should ignore rather than report as a gap.
func NormalizeLanguage(name string) (Language, bool) {
	lang, ok := languageAliases[normalizeToken(name)]
	return lang, ok
}

// NormalizeLanguages converts a list of arbitrary language names into a sorted,
// de-duplicated list of canonical CodeQL languages, dropping unsupported ones.
func NormalizeLanguages(names []string) []Language {
	seen := make(map[Language]bool, len(names))
	for _, name := range names {
		if lang, ok := NormalizeLanguage(name); ok {
			seen[lang] = true
		}
	}
	return sortLanguages(seen)
}

// IsDetectable reports whether a language can be discovered from repository
// source analysis. Languages such as "actions" cannot be.
func IsDetectable(lang Language) bool {
	return !undetectableLanguages[lang]
}

// RuntimeEvaluation distinguishes measured language evidence from uncollected
// or incomplete runtime evidence.
type RuntimeEvaluation string

const (
	RuntimeNotEvaluated RuntimeEvaluation = "not-evaluated"
	RuntimeEvaluated    RuntimeEvaluation = "evaluated"
	RuntimeIncomplete   RuntimeEvaluation = "incomplete"
)

// LanguageState describes what is happening to a single language in a
// repository. Analyzing coverage per language is what distinguishes a truly
// healthy repository from one whose workflow is green while a language is
// quietly skipped.
type LanguageState struct {
	Language Language `json:"language"`
	// RuntimeEvaluation applies to Analyzed and Succeeded.
	RuntimeEvaluation RuntimeEvaluation `json:"runtime_evaluation,omitempty"`
	// Detected means the language was found in the repository source.
	Detected bool `json:"detected"`
	// Configured means default setup lists the language for analysis.
	Configured bool `json:"configured"`
	// Analyzed means an analysis job for the language ran in the latest run.
	Analyzed bool `json:"analyzed"`
	// Succeeded means the analysis job for the language completed successfully.
	Succeeded bool `json:"succeeded"`
	// Deselected means the language was analyzed in the latest run but is no
	// longer part of the configuration. GitHub clears a language from default
	// setup when its analysis fails, so the language will not run again until
	// someone re-enables it.
	Deselected bool `json:"deselected,omitempty"`
	// JobConclusion is the raw Actions conclusion for the language job.
	JobConclusion string `json:"job_conclusion,omitempty"`
	// JobURL links directly to the per-language job for evidence.
	JobURL string `json:"job_url,omitempty"`
	// DatabaseUpdatedAt is when CodeQL last uploaded a database for the
	// language, which is durable proof that extraction succeeded.
	DatabaseUpdatedAt *Timestamp `json:"database_updated_at,omitempty"`
	// AnalysisCreatedAt is when the language last produced a code scanning
	// analysis on the default branch.
	AnalysisCreatedAt *Timestamp `json:"analysis_created_at,omitempty"`
	// AnalysisError is the failure reason GitHub recorded against the most
	// recent analysis for the language. This is the authoritative, log-free
	// explanation of why a language is not producing results.
	AnalysisError string `json:"analysis_error,omitempty"`
	// ResultsCount is the number of alerts in the most recent analysis for
	// the language. Zero results on a language that should produce them is a
	// weak signal on its own, so it is reported rather than judged.
	ResultsCount *int `json:"results_count,omitempty"`
}

// MarshalJSON preserves booleans internally while emitting null for runtime
// values that were deliberately not evaluated.
func (state LanguageState) MarshalJSON() ([]byte, error) {
	type plain LanguageState
	value := struct {
		plain
		Analyzed  *bool `json:"analyzed"`
		Succeeded *bool `json:"succeeded"`
	}{plain: plain(state)}
	if state.RuntimeEvaluation != RuntimeNotEvaluated {
		value.Analyzed = &state.Analyzed
		value.Succeeded = &state.Succeeded
	}
	return json.Marshal(value)
}

// LanguageSet is a helper for assembling per-language state.
type LanguageSet map[Language]*LanguageState

// Get returns the state for a language, creating it if required.
func (s LanguageSet) Get(lang Language) *LanguageState {
	if state, ok := s[lang]; ok {
		return state
	}
	state := &LanguageState{Language: lang}
	s[lang] = state
	return state
}

// Sorted returns the language states in stable presentation order.
func (s LanguageSet) Sorted() []LanguageState {
	keys := make(map[Language]bool, len(s))
	for lang := range s {
		keys[lang] = true
	}
	ordered := sortLanguages(keys)
	states := make([]LanguageState, 0, len(ordered))
	for _, lang := range ordered {
		states = append(states, *s[lang])
	}
	return states
}

// SortLanguageSet returns languages in canonical presentation order.
func SortLanguageSet(set map[Language]bool) []Language {
	return sortLanguages(set)
}

// sortLanguages returns languages in canonical order, with any unrecognized
// entries appended alphabetically so output stays deterministic.
func sortLanguages(set map[Language]bool) []Language {
	result := make([]Language, 0, len(set))
	for _, lang := range languageOrder {
		if set[lang] {
			result = append(result, lang)
		}
	}
	var extra []Language
	for lang := range set {
		if !isKnownLanguage(lang) {
			extra = append(extra, lang)
		}
	}
	sort.Slice(extra, func(i, j int) bool { return extra[i] < extra[j] })
	return append(result, extra...)
}

func isKnownLanguage(lang Language) bool {
	for _, known := range languageOrder {
		if known == lang {
			return true
		}
	}
	return false
}

// normalizeToken lower-cases and trims a token, and converts underscores to
// hyphens so that "not_configured" and "not-configured" behave identically.
func normalizeToken(value string) string {
	return strings.ReplaceAll(strings.ToLower(strings.TrimSpace(value)), "_", "-")
}

// JoinLanguages renders languages as a stable comma-separated string for
// table and CSV output.
func JoinLanguages(langs []Language) string {
	if len(langs) == 0 {
		return ""
	}
	parts := make([]string, 0, len(langs))
	for _, lang := range langs {
		parts = append(parts, string(lang))
	}
	return strings.Join(parts, ", ")
}
