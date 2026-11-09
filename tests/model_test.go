// Tests for the Echo Static model. "diff:N" is a line of
// CVE-2026-118650_echo_b838391e2ead.diff (v4), "v5diff:N" of
// CVE-2026-118650_echo_fc410094b2f3.diff (v5); see SOURCES.md.
package tests

import (
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/federiconbaez/cortex9-echo-static-encoded-segment-bypass-model/src/model"
)

func cases(t *testing.T) map[string]model.Case {
	t.Helper()
	cs, err := model.LoadCases("../fixtures/cases.tsv")
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]model.Case{}
	for _, c := range cs {
		m[c.ID] = c
	}
	return m
}

func run(t *testing.T, id, v string) model.Outcome {
	t.Helper()
	c, ok := cases(t)[id]
	if !ok {
		t.Fatalf("fixture %s missing", id)
	}
	return model.Run(c, v)
}

func TestFixturesMatchIndependentDerivation(t *testing.T) {
	data, err := os.ReadFile("../fixtures/expected.tsv")
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	cs, err := model.LoadCases("../fixtures/cases.tsv")
	if err != nil {
		t.Fatal(err)
	}
	got := []string{model.Header}
	for _, c := range cs {
		got = append(got, model.Run(c, model.Pre).Row(), model.Run(c, model.Post).Row())
	}
	if len(got) != len(want) {
		t.Fatalf("rows: got %d want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("row %d:\n got %s\nwant %s", i, got[i], want[i])
		}
	}
}

// Post-fix statuses of the diff's own tests: TestStatic_resolvesRoutedPath
// (diff:1314-1323) and TestStatic_routeLevelGuard (diff:1367-1375).
func TestDiffTestStatuses(t *testing.T) {
	want := map[string]int{
		"g01_encoded_slash": 404, "g02_encoded_slash_lower": 404, "g03_encoded_letter": 404,
		"g04_encoded_dot_segment": 404, "g05_encoded_slashes_and_dots": 404, "g06_parent_dot_segment": 404,
		"g07_current_dot_segment": 404, "g08_empty_segment": 404, "g09_canonical_escape": 200, "g10_plain_public": 200,
		"r01_guarded": 403, "r02_guarded_repeated_prefix": 403, "r03_encoded_slash": 404, "r04_encoded_letter": 404,
		"r05_parent_dot_segment": 404, "r06_empty_segment": 404, "r07_encoded_dots_unescape": 404,
		"r08_encoded_dot_slash_unescape": 404, "r09_public": 200,
	}
	for id, st := range want {
		o := run(t, id, model.Post)
		if o.Status != st {
			t.Errorf("%s: status %d, diff expects %d", id, o.Status, st)
		}
		if o.Served == "admin/secret.txt" {
			t.Errorf("%s: serves SECRET (diff:1346, diff:1401 assert NotContains)", id)
		}
	}
}

// GHSA-375p-5qhx-8wq4: global mount, %2F-encoded path; pre resolves from the
// decoded URL.Path (diff:1216), post from RawPath (diff:1221-1224).
func TestEncodedSlashDifferential(t *testing.T) {
	for _, id := range []string{"g01_encoded_slash", "g02_encoded_slash_lower", "g03_encoded_letter", "x02_poc_encoded_slash"} {
		pre, post := run(t, id, model.Pre), run(t, id, model.Post)
		if pre.Label != model.LabelMismatch || pre.Served != "admin/secret.txt" {
			t.Errorf("%s pre: %+v", id, pre)
		}
		if post.Label != model.LabelNotFound || post.Lookup == "admin/secret.txt" {
			t.Errorf("%s post: %+v", id, post)
		}
	}
}

// GHSA-3pmx-cf9f-34xr (same commit, different advisory): dot and empty
// segments (diff:1225-1230, 1238, 1246-1252).
func TestDotSegmentsRelatedAdvisory(t *testing.T) {
	for _, id := range []string{"g06_parent_dot_segment", "g07_current_dot_segment", "g08_empty_segment", "r05_parent_dot_segment", "r06_empty_segment", "r07_encoded_dots_unescape", "r08_encoded_dot_slash_unescape", "a01_double_encoded_dots_unescape"} {
		if pre := run(t, id, model.Pre); !model.ServesAdmin(pre) {
			t.Errorf("%s pre: %s", id, pre.Label)
		}
		if post := run(t, id, model.Post); post.Lookup != "!unclean" || post.Status != 404 {
			t.Errorf("%s post: %+v", id, post)
		}
	}
}

// Documented, not fixed: with EnablePathUnescaping encoded slashes are still
// decoded (diff:44 CHANGELOG, diff:1184-1185 docstring).
func TestUnescapingResidualIsDocumented(t *testing.T) {
	for _, id := range []string{"a02_encoded_slash_unescape_route", "a04_unescape_encoded_slash_global"} {
		if post := run(t, id, model.Post); post.Label != model.LabelMismatch {
			t.Errorf("%s post: %s", id, post.Label)
		}
	}
}

// Global Static runs before route and group middleware (diff:1206-1208,
// v5diff:1299-1301): in the GHSA PoC layout the literal path is served in
// the model too. The NVD text calls the source inconsistent on this point.
func TestOrderBypassInPoCLayout(t *testing.T) {
	for _, v := range []string{model.Pre, model.Post} {
		if o := run(t, "x01_poc_literal", v); o.Label != model.LabelOrderBypass {
			t.Errorf("%s: %+v", v, o)
		}
	}
	if o := run(t, "g11_literal_guarded", model.Post); o.Label != model.LabelDenied {
		t.Errorf("wildcard group literal: %+v", o)
	}
}

func TestNegativesUnchanged(t *testing.T) {
	for _, id := range []string{"g09_canonical_escape", "g10_plain_public", "g11_literal_guarded", "r01_guarded", "r02_guarded_repeated_prefix", "r03_encoded_slash", "r04_encoded_letter", "r09_public", "c04_public_admin_subdir", "a03_bad_escape_unescape"} {
		pre, post := run(t, id, model.Pre), run(t, id, model.Post)
		if pre.Label != post.Label || pre.Status != post.Status || pre.Served != post.Served {
			t.Errorf("%s changed: %+v -> %+v", id, pre, post)
		}
	}
}

func decodedHasDotOrEmpty(target string) bool {
	p, err := url.PathUnescape(target)
	if err != nil {
		return false
	}
	p = strings.Trim(p, "/")
	for _, s := range strings.Split(p, "/") {
		if s == "" || s == "." || s == ".." {
			return p != ""
		}
	}
	return false
}

func TestSweepInvariants(t *testing.T) {
	cs := model.Sweep()
	if len(cs) != 4704 {
		t.Fatalf("sweep size %d", len(cs))
	}
	var preMismatch, postResidual int
	for _, c := range cs {
		pre, post := model.Run(c, model.Pre), model.Run(c, model.Post)
		if pre.Label == model.LabelMismatch {
			preMismatch++
		}
		if post.Label == model.LabelMismatch {
			postResidual++
			if !c.Unescape {
				t.Errorf("%s %s: post mismatch without EnablePathUnescaping", c.Target, c.Mount)
			}
			if decodedHasDotOrEmpty(c.Target) || !strings.Contains(c.Target, "%") {
				t.Errorf("%s %s: post mismatch with a dot/empty segment or without encoding", c.Target, c.Mount)
			}
		}
		if post.Status == 200 && strings.HasPrefix(post.Served, "admin/") && post.Label != model.LabelOrderBypass {
			if post.Label != model.LabelMismatch {
				t.Errorf("%s: admin file with label %s", c.Target, post.Label)
			}
		}
		if model.ServesAdmin(post) && !model.ServesAdmin(pre) {
			t.Errorf("%s %s: post serves admin where pre did not", c.Target, c.Mount)
		}
		if pre.Label == model.LabelDenied && post.Label != model.LabelDenied {
			t.Errorf("%s %s: guard result changed", c.Target, c.Mount)
		}
	}
	if preMismatch == 0 || postResidual == 0 {
		t.Errorf("expected both classes: pre %d, post residual %d", preMismatch, postResidual)
	}
}

func TestAdversarialInputs(t *testing.T) {
	bad := []model.Case{
		{Target: "", Mount: model.MountGlobal},
		{Target: "admin/secret.txt", Mount: model.MountGlobal},
		{Target: "/" + strings.Repeat("a", 600), Mount: model.MountGlobal},
		{Target: "/admin\x00/secret.txt", Mount: model.MountGlobal},
		{Target: "/admin\\secret.txt", Mount: model.MountGlobal},
		{Target: "/admin/secr\u00e9t.txt", Mount: model.MountGlobal},
		{Target: "/admin%2", Mount: model.MountGlobal},
		{Target: "/admin#x", Mount: model.MountGlobal},
		{Target: "/admin/secret.txt", Mount: ""},
	}
	for _, c := range bad {
		for _, v := range []string{model.Pre, model.Post} {
			if o := model.Run(c, v); o.Label != model.LabelBadInput {
				t.Errorf("%q %q %s: %s", c.Target, c.Mount, v, o.Label)
			}
		}
	}
	if o := model.Run(model.Case{Target: "/x/file.txt", Mount: model.MountGlobal}, "v6"); o.Label != model.LabelBadInput {
		t.Errorf("unknown version: %s", o.Label)
	}
	// Deep traversal never escapes the static root: path.Clean on a rooted path.
	o := model.Run(model.Case{Target: "/x/../../../../admin/secret.txt", Mount: model.MountGlobal}, model.Pre)
	if o.Lookup != "admin/secret.txt" {
		t.Errorf("rooted clean: %+v", o)
	}
}

func TestResultsMatchCommittedSweep(t *testing.T) {
	data, err := os.ReadFile("../results/sweep.csv")
	if err != nil {
		t.Fatal(err)
	}
	a, b := model.SweepCSV(), model.SweepCSV()
	if a != b {
		t.Fatal("SweepCSV is not deterministic")
	}
	if a != string(data) {
		t.Fatal("results/sweep.csv differs from the model; run scripts/build.sh results")
	}
}

// PRACTICE.md levels.
func TestPracticeLevels(t *testing.T) {
	c := func(target, mount string, un bool) model.Case {
		return model.Case{Target: target, Mount: mount, Unescape: un}
	}
	if o := model.Run(c("/public/index.html", model.MountGlobal, false), model.Pre); o.Label != model.LabelServed {
		t.Errorf("level 1: %+v", o)
	}
	if o := model.Run(c("/admin%2Fsecret.txt", model.MountGlobal, false), model.Pre); o.RouterPath != "/admin%2Fsecret.txt" || o.Route != "none" {
		t.Errorf("level 2: %+v", o)
	}
	if o := model.Run(c("/admin%2Fsecret.txt", model.MountGlobal, false), model.Pre); o.Label != model.LabelMismatch {
		t.Errorf("level 3: %+v", o)
	}
	if o := model.Run(c("/admin%2Fsecret.txt", model.MountGlobal, false), model.Post); o.Status != 404 {
		t.Errorf("level 4: %+v", o)
	}
	if o := model.Run(c("/admin%2Fsecret.txt", model.MountRoute, false), model.Pre); o.Status != 404 {
		t.Errorf("level 5: %+v", o)
	}
	if o := model.Run(c("/public/../admin/secret.txt", model.MountGlobal, false), model.Post); o.Lookup != "!unclean" {
		t.Errorf("level 6: %+v", o)
	}
	if o := model.Run(c("/admin%2Fsecret.txt", model.MountRoute, true), model.Post); o.Label != model.LabelMismatch {
		t.Errorf("level 7: %+v", o)
	}
	if o := model.Run(c("/admin/secret.txt", model.MountGlobalExact, false), model.Post); o.Label != model.LabelOrderBypass {
		t.Errorf("level 8: %+v", o)
	}
}
