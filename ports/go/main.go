// Go port of the depgraph core surface — single static binary, zero deps.
//
// Mirrors the Python reference: parse a pip requirements.txt, run a
// Levenshtein typosquat check, and match pinned versions against a small
// embedded OSV-style advisory set. Same JSON output shape.
//
// Run:   go run . requirements.txt        (or pipe on stdin)
// Test:  go test ./...                     (see main_test.go)
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
)

var Popular = []string{
	"requests", "urllib3", "numpy", "pandas", "flask", "django", "pillow",
	"lxml", "cryptography", "colorama", "python-dateutil", "setuptools",
}

type Advisory struct {
	ID, Alias, Pkg, Sev, Introduced, Fixed string
}

var Advisories = []Advisory{
	{"GHSA-j8r2-6x86-q33q", "CVE-2023-32681", "requests", "MEDIUM", "2.3.0", "2.31.0"},
	{"GHSA-9wx4-h78v-vm56", "CVE-2021-33503", "urllib3", "HIGH", "0", "1.26.5"},
	{"GHSA-h5c8-rqwp-cp95", "CVE-2022-22817", "pillow", "CRITICAL", "0", "9.0.0"},
	{"GHSA-8q59-q68h-6hv4", "CVE-2022-2309", "lxml", "MEDIUM", "0", "4.9.1"},
}

var sevPenalty = map[string]float64{"LOW": 1.0, "MEDIUM": 2.5, "HIGH": 4.0, "CRITICAL": 6.5}
var verRe = regexp.MustCompile(`\d+`)

func ParseVersion(v string) []int {
	v = strings.TrimLeft(v, "vV=")
	if i := strings.IndexAny(v, "+ -"); i >= 0 {
		v = v[:i]
	}
	parts := verRe.FindAllString(v, -1)
	out := []int{}
	for i, p := range parts {
		if i >= 4 {
			break
		}
		n, _ := strconv.Atoi(p)
		out = append(out, n)
	}
	if len(out) == 0 {
		return []int{0}
	}
	return out
}

func VersionCompare(a, b string) int {
	ta, tb := ParseVersion(a), ParseVersion(b)
	n := len(ta)
	if len(tb) > n {
		n = len(tb)
	}
	for i := 0; i < n; i++ {
		x, y := 0, 0
		if i < len(ta) {
			x = ta[i]
		}
		if i < len(tb) {
			y = tb[i]
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

func InRange(version string, a Advisory) bool {
	if VersionCompare(version, a.Introduced) < 0 {
		return false
	}
	if a.Fixed != "" && VersionCompare(version, a.Fixed) >= 0 {
		return false
	}
	return true
}

func Levenshtein(a, b string) int {
	if a == b {
		return 0
	}
	la, lb := len(a), len(b)
	if la == 0 {
		return lb
	}
	if lb == 0 {
		return la
	}
	prev := make([]int, lb+1)
	for j := 0; j <= lb; j++ {
		prev[j] = j
	}
	for i := 1; i <= la; i++ {
		cur := make([]int, lb+1)
		cur[0] = i
		for j := 1; j <= lb; j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			cur[j] = min3(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev = cur
	}
	return prev[lb]
}

func min3(a, b, c int) int {
	m := a
	if b < m {
		m = b
	}
	if c < m {
		m = c
	}
	return m
}

func TyposquatMatch(name string) (string, bool) {
	ln := strings.ToLower(name)
	for _, p := range Popular {
		if p == ln {
			return "", false
		}
	}
	best, bestD := "", 99
	for _, cand := range Popular {
		if abs(len(cand)-len(ln)) > 2 {
			continue
		}
		if d := Levenshtein(ln, cand); d < bestD {
			bestD, best = d, cand
		}
	}
	if bestD == 1 {
		return best, true
	}
	return "", false
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

type Dep struct {
	Name    string    `json:"name"`
	Version string    `json:"version"`
	Score   float64   `json:"score"`
	Grade   string    `json:"grade"`
	Finding []Finding `json:"findings"`
}

type Finding struct {
	Kind     string `json:"kind"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
}

var pipRe = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(==|~=|>=|<=|>|<|!=)?\s*([A-Za-z0-9][\w.*+!-]*)?`)

func ParseRequirements(text string) []Dep {
	var deps []Dep
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(strings.SplitN(raw, "#", 2)[0])
		if line == "" || hasSkipPrefix(line) {
			continue
		}
		m := pipRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		ver := ""
		if (m[2] == "==" || m[2] == "~=") && m[3] != "" {
			ver = m[3]
		}
		deps = append(deps, Dep{Name: m[1], Version: ver})
	}
	return deps
}

func hasSkipPrefix(line string) bool {
	for _, p := range []string{"-", ".", "/", "git+", "http"} {
		if strings.HasPrefix(line, p) {
			return true
		}
	}
	return false
}

func ScoreToGrade(s float64) string {
	switch {
	case s >= 9:
		return "A"
	case s >= 7.5:
		return "B"
	case s >= 6:
		return "C"
	case s >= 4:
		return "D"
	default:
		return "F"
	}
}

func ScoreDep(d Dep) Dep {
	var fs []Finding
	penalty := 0.0
	for _, a := range Advisories {
		if a.Pkg == strings.ToLower(d.Name) && d.Version != "" && InRange(d.Version, a) {
			fs = append(fs, Finding{"vuln", a.Sev, fmt.Sprintf("%s (%s) affects %s %s", a.ID, a.Alias, d.Name, d.Version)})
			penalty += sevPenalty[a.Sev]
		}
	}
	if closest, ok := TyposquatMatch(d.Name); ok {
		fs = append(fs, Finding{"typosquat", "CRITICAL", fmt.Sprintf("'%s' is 1 edit from popular '%s'", d.Name, closest)})
		penalty += 5.0
	}
	if d.Version == "" {
		fs = append(fs, Finding{"unpinned", "MEDIUM", fmt.Sprintf("'%s' is not pinned", d.Name)})
		penalty += 1.5
	}
	score := 10.0 - penalty
	if score < 0 {
		score = 0
	}
	d.Score = score
	d.Grade = ScoreToGrade(score)
	d.Finding = fs
	return d
}

func Audit(text string) map[string]any {
	deps := ParseRequirements(text)
	total := 0.0
	vulns := 0
	for i := range deps {
		deps[i] = ScoreDep(deps[i])
		total += deps[i].Score
		for _, f := range deps[i].Finding {
			if f.Kind == "vuln" {
				vulns++
			}
		}
	}
	proj := 10.0
	if len(deps) > 0 {
		proj = total / float64(len(deps))
	}
	return map[string]any{
		"tool": "depgraph", "version": "2.1.0",
		"dependency_count": len(deps), "vuln_count": vulns,
		"project_score": proj, "project_grade": ScoreToGrade(proj),
		"dependencies": deps,
	}
}

func main() {
	var text string
	if len(os.Args) > 1 {
		b, err := os.ReadFile(os.Args[1])
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(2)
		}
		text = string(b)
	} else {
		b, _ := io.ReadAll(os.Stdin)
		text = string(b)
	}
	out, _ := json.MarshalIndent(Audit(text), "", "  ")
	fmt.Println(string(out))
}
