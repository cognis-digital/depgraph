package main

import "testing"

func TestParseVersion(t *testing.T) {
	got := ParseVersion("2.31.0")
	want := []int{2, 31, 0}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("ParseVersion(2.31.0)=%v", got)
		}
	}
	if v := ParseVersion("v1.2.3-beta"); v[0] != 1 || v[1] != 2 || v[2] != 3 {
		t.Fatalf("ParseVersion(v1.2.3-beta)=%v", v)
	}
}

func TestVersionCompare(t *testing.T) {
	if VersionCompare("1.2.3", "1.2.10") != -1 {
		t.Fatal("1.2.3 < 1.2.10")
	}
	if VersionCompare("2.0", "2.0.0") != 0 {
		t.Fatal("2.0 == 2.0.0")
	}
	if VersionCompare("9.0.0", "8.4.0") != 1 {
		t.Fatal("9.0.0 > 8.4.0")
	}
}

func TestLevenshtein(t *testing.T) {
	if Levenshtein("colorama", "colourama") != 1 {
		t.Fatal("colorama/colourama distance 1")
	}
	if Levenshtein("same", "same") != 0 {
		t.Fatal("identical distance 0")
	}
}

func TestTyposquat(t *testing.T) {
	if c, ok := TyposquatMatch("reqests"); !ok || c != "requests" {
		t.Fatalf("reqests -> %q,%v", c, ok)
	}
	if _, ok := TyposquatMatch("requests"); ok {
		t.Fatal("popular name must not flag")
	}
}

func TestInRange(t *testing.T) {
	a := Advisories[0] // requests
	if !InRange("2.28.0", a) {
		t.Fatal("2.28.0 vulnerable")
	}
	if InRange("2.31.0", a) {
		t.Fatal("2.31.0 fixed")
	}
}

func TestScorePillowF(t *testing.T) {
	deps := ParseRequirements("pillow==8.4.0\n")
	d := ScoreDep(deps[0])
	if d.Grade != "F" {
		t.Fatalf("pillow 8.4.0 grade=%s", d.Grade)
	}
}

func TestAuditShape(t *testing.T) {
	out := Audit("requests==2.28.0\nnumpy\n")
	if out["tool"] != "depgraph" {
		t.Fatal("tool field")
	}
	if out["vuln_count"].(int) != 1 {
		t.Fatalf("vuln_count=%v", out["vuln_count"])
	}
}

func TestCleanPackageA(t *testing.T) {
	deps := ParseRequirements("cryptography==42.0.0\n")
	d := ScoreDep(deps[0])
	if d.Grade != "A" || len(d.Finding) != 0 {
		t.Fatalf("cryptography grade=%s findings=%d", d.Grade, len(d.Finding))
	}
}
