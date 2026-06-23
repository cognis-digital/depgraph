#!/usr/bin/env sh
# POSIX shell port of the depgraph core surface — offline, no deps beyond awk.
#
# Mirrors the Python reference for the pip path: parse requirements.txt, flag
# typosquats (edit distance 1 to a popular name), match pinned versions against
# an embedded OSV-style advisory set, and emit a compact report.
#
# Run:   sh depgraph.sh requirements.txt
# Test:  sh test.sh
set -eu

# Embedded advisory table: pkg|introduced|fixed|sev|id|alias
ADVISORIES='requests|2.3.0|2.31.0|MEDIUM|GHSA-j8r2-6x86-q33q|CVE-2023-32681
urllib3|0|1.26.5|HIGH|GHSA-9wx4-h78v-vm56|CVE-2021-33503
pillow|0|9.0.0|CRITICAL|GHSA-h5c8-rqwp-cp95|CVE-2022-22817
lxml|0|4.9.1|MEDIUM|GHSA-8q59-q68h-6hv4|CVE-2022-2309'

POPULAR='requests urllib3 numpy pandas flask django pillow lxml cryptography colorama python-dateutil setuptools'

audit() {
  manifest="$1"
  awk -v advisories="$ADVISORIES" -v popular="$POPULAR" '
    function vnorm(v,   t) { gsub(/^[vV=]+/, "", v); split(v, a, /[+ -]/); return a[1]; }
    # return -1/0/1 comparing dotted numeric versions
    function vcmp(x, y,   ax, ay, n, i, xi, yi) {
      n = split(vnorm(x), ax, /[^0-9]+/); m = split(vnorm(y), ay, /[^0-9]+/);
      if (m > n) n = m;
      for (i = 1; i <= n; i++) { xi = ax[i]+0; yi = ay[i]+0;
        if (xi < yi) return -1; if (xi > yi) return 1; }
      return 0;
    }
    function in_range(v, intro, fixed) {
      if (vcmp(v, intro) < 0) return 0;
      if (fixed != "" && vcmp(v, fixed) >= 0) return 0;
      return 1;
    }
    function lev(a, b,   la, lb, i, j, cost, d, prev, cur) {
      la = length(a); lb = length(b);
      if (a == b) return 0; if (la == 0) return lb; if (lb == 0) return la;
      for (j = 0; j <= lb; j++) prev[j] = j;
      for (i = 1; i <= la; i++) {
        cur[0] = i;
        for (j = 1; j <= lb; j++) {
          cost = (substr(a, i, 1) == substr(b, j, 1)) ? 0 : 1;
          d = prev[j] + 1; if (cur[j-1] + 1 < d) d = cur[j-1] + 1;
          if (prev[j-1] + cost < d) d = prev[j-1] + cost;
          cur[j] = d;
        }
        for (j = 0; j <= lb; j++) prev[j] = cur[j];
      }
      return prev[lb];
    }
    function typosquat(name,   p, np, k, best, bestd, d) {
      np = split(popular, p, " "); best = ""; bestd = 99;
      for (k = 1; k <= np; k++) {
        if (tolower(name) == p[k]) return "";
        d = lev(tolower(name), p[k]);
        if (d < bestd) { bestd = d; best = p[k]; }
      }
      return (bestd == 1) ? best : "";
    }
    function grade(s) {
      if (s >= 9) return "A"; if (s >= 7.5) return "B"; if (s >= 6) return "C";
      if (s >= 4) return "D"; return "F";
    }
    BEGIN {
      na = split(advisories, ad, "\n");
      deps = 0; vulns = 0; total = 0;
    }
    {
      line = $0; sub(/#.*/, "", line); gsub(/^[ \t]+|[ \t]+$/, "", line);
      if (line == "") next;
      if (line ~ /^[-.\/]/ || line ~ /^git\+/ || line ~ /^http/) next;
      name = line; sub(/[ \t]*(==|~=|>=|<=|>|<|!=).*/, "", name);
      gsub(/[ \t]/, "", name);
      if (name == "") next;
      ver = "";
      if (line ~ /(==|~=)/) { ver = line; sub(/.*(==|~=)[ \t]*/, "", ver);
        sub(/[ \t;].*/, "", ver); }
      deps++;
      penalty = 0; nf = 0; worst = "NONE"; msg = "";
      for (k = 1; k <= na; k++) {
        split(ad[k], f, "|");
        if (f[1] == tolower(name) && ver != "" && in_range(ver, f[2], f[3])) {
          pen = (f[4]=="LOW")?1.0:(f[4]=="MEDIUM")?2.5:(f[4]=="HIGH")?4.0:6.5;
          penalty += pen; vulns++; nf++; worst = f[4];
          msg = msg "    - [" f[4] "] " f[5] " (" f[6] ") affects " name " " ver "\n";
        }
      }
      sq = typosquat(name);
      if (sq != "") { penalty += 5.0; nf++; worst = "CRITICAL";
        msg = msg "    - [CRITICAL] typosquat: " name " ~ " sq "\n"; }
      if (ver == "") { penalty += 1.5; nf++;
        msg = msg "    - [MEDIUM] unpinned: " name "\n"; }
      score = 10 - penalty; if (score < 0) score = 0;
      total += score;
      printf "%-5s %-20s %-10s %5.1f  %s\n", grade(score), name, (ver==""?"-":ver), score, worst;
      if (msg != "") printf "%s", msg;
    }
    END {
      proj = (deps > 0) ? total / deps : 10;
      printf "project: %s  score=%.2f  deps=%d  vulns=%d\n", grade(proj), proj, deps, vulns;
    }
  ' "$manifest"
}

if [ "$#" -ge 1 ]; then
  audit "$1"
else
  tmp="$(mktemp)"; cat > "$tmp"; audit "$tmp"; rm -f "$tmp"
fi
