package model

import (
	"fmt"
	"os"
	"strings"
)

// LoadCases reads fixtures/cases.tsv (id, target, mount, unescape 0|1).
func LoadCases(file string) ([]Case, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	var out []Case
	for n, line := range strings.Split(string(data), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) != 4 || (f[3] != "0" && f[3] != "1") {
			return nil, fmt.Errorf("%s:%d: bad row", file, n+1)
		}
		out = append(out, Case{ID: f[0], Target: f[1], Mount: f[2], Unescape: f[3] == "1"})
	}
	return out, nil
}

// SweepTokens build the fixed sweep: "/" + t1 + t2 + t3 + "secret.txt".
var SweepTokens = []string{"", "/", ".", "..", "%2e%2e", "%2F", "%61dmin", "admin", "x", "%252e%252e"}

// Sweep enumerates every target for every mount and unescape setting, in a
// fixed order.
func Sweep() []Case {
	var out []Case
	seen := map[string]bool{}
	var targets []string
	for _, a := range SweepTokens {
		for _, b := range SweepTokens {
			for _, c := range SweepTokens {
				t := "/" + a + b + c + "secret.txt"
				if !seen[t] {
					seen[t] = true
					targets = append(targets, t)
				}
			}
		}
	}
	for _, m := range []string{MountGlobal, MountGlobalExact, MountRoute} {
		for _, un := range []bool{false, true} {
			for _, t := range targets {
				out = append(out, Case{ID: "s" + itoa(len(out)+1), Target: t, Mount: m, Unescape: un})
			}
		}
	}
	return out
}

// SweepCSV renders the sweep with pre and post labels.
func SweepCSV() string {
	var b strings.Builder
	b.WriteString("id,target,mount,unescape,pre_label,pre_served,post_label,post_served\n")
	for _, c := range Sweep() {
		pre, post := Run(c, Pre), Run(c, Post)
		un := "0"
		if c.Unescape {
			un = "1"
		}
		b.WriteString(strings.Join([]string{c.ID, c.Target, c.Mount, un, pre.Label, pre.Served, post.Label, post.Served}, ",") + "\n")
	}
	return b.String()
}
