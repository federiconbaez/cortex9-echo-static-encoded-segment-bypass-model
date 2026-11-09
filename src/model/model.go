// Package model is an offline model of how Echo's middleware.Static picks the
// file for a request, before and after the fix for CVE-2026-118650
// (GHSA-375p-5qhx-8wq4) in labstack/echo b838391 (v4.16.0) and fc41009
// (v5.4.0).
//
// "diff:N" is line N of CVE-2026-118650_echo_b838391e2ead.diff (v4);
// "v5diff:N" is line N of CVE-2026-118650_echo_fc410094b2f3.diff (v5). See
// SOURCES.md. No Echo code is imported or run; Go standard library only.
package model

import (
	"net/url"
	"path"
	"strings"
)

// Versions.
const (
	Pre  = "pre"  // before b838391 / fc41009
	Post = "post" // b838391 / fc41009
)

// Mounts: how the application wires Static and the /admin guard.
const (
	// MountGlobal: e.Use(Static) and an /admin group guard with GET "/*"
	// (diff:1328-1337).
	MountGlobal = "global"
	// MountGlobalExact: e.Use(Static) and an /admin group guard with GET
	// "/secret.txt" (the GHSA PoC layout).
	MountGlobalExact = "global-exact"
	// MountRoute: Static as route middleware on GET "/*" and the /admin
	// group guard with GET "/*" (diff:1380-1392).
	MountRoute = "route"
)

// Labels.
const (
	LabelServed      = "SERVED"        // a file outside admin/ is served
	LabelMismatch    = "MISMATCH"      // a file under admin/ is served for a router form outside /admin
	LabelOrderBypass = "ORDER_BYPASS"  // a file under admin/ is served although the router matched the guarded route
	LabelDenied      = "DENIED_403"    // the /admin guard answers
	LabelNotFound    = "NOT_FOUND_404" // no file and no other handler
	LabelError       = "ERROR_500"     // unescaping the path failed
	LabelBadInput    = "BAD_INPUT"
	maxInput         = 512
	targetChars      = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~/%"
)

// Files is the static root of the model, the union of the diff's test
// filesystems (diff:1301-1306, diff:1355-1359).
var Files = map[string]string{
	"admin/secret.txt":       "SECRET",
	"public/index.html":      "public",
	"hello world.txt":        "hello",
	"public/admin/other.txt": "other",
	"x/file.txt":             "x",
}

// Case is one request with one application layout.
type Case struct {
	ID       string
	Target   string // request-target as sent (origin-form, no query)
	Mount    string
	Unescape bool // StaticConfig.EnablePathUnescaping
}

// Outcome is what the model observes.
type Outcome struct {
	ID, Version, Label    string
	Status                int
	RouterPath, Route     string
	Param, Lookup, Served string
	PathSeen, RawPathSeen string
}

// hasDotOrEmptySegment is copied in behaviour from diff:1264-1276
// (v5diff:1357-1369).
func hasDotOrEmptySegment(p string) bool {
	p = strings.TrimPrefix(p, "/")
	p = strings.TrimSuffix(p, "/")
	if p == "" {
		return false
	}
	for _, segment := range strings.Split(p, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return true
		}
	}
	return false
}

// hasUncleanPath: diff:1281-1286 (v5diff:1374-1379).
func hasUncleanPath(p, raw string) bool {
	if raw != "" {
		return hasDotOrEmptySegment(raw)
	}
	return hasDotOrEmptySegment(p)
}

// routerPath is the form the router matches by default: the escaped path
// when it differs from the default encoding (diff:1218-1219, diff:1278-1279).
func routerPath(p, raw string) string {
	if raw != "" {
		return raw
	}
	return p
}

// route models the router lookup for a mount (reconstructed, not in the
// diff). It returns the route pattern (c.Path()), the wildcard param and
// whether the route is behind the /admin guard.
func route(mount, rp string) (pattern, param string, guarded bool) {
	switch mount {
	case MountGlobal:
		if strings.HasPrefix(rp, "/admin/") {
			return "/admin/*", rp[len("/admin/"):], true
		}
		return "none", "", false
	case MountGlobalExact:
		if rp == "/admin/secret.txt" {
			return "/admin/secret.txt", "", true
		}
		return "none", "", false
	default: // MountRoute
		if strings.HasPrefix(rp, "/admin/") {
			return "/admin/*", rp[len("/admin/"):], true
		}
		return "/*", strings.TrimPrefix(rp, "/"), false
	}
}

// lookup is the Static middleware's choice of file name for one version.
// ok=false means unescaping failed (ERROR_500).
func lookup(version string, u *url.URL, pattern, param string, unescape bool) (name string, unclean, ok bool) {
	var p string
	if version == Pre {
		p = u.Path // diff:1216 (v5diff:1309), removed by the fix
		if strings.HasSuffix(pattern, "*") {
			p = param // diff:1228-1229
		}
		if unescape { // diff:1232 (removed form)
			var err error
			if p, err = url.PathUnescape(p); err != nil { // diff:1234-1236
				return "", false, false
			}
		}
	} else {
		p = u.Path // diff:1221
		if u.RawPath != "" {
			p = u.RawPath // diff:1222-1224
		}
		unclean = hasUncleanPath(u.Path, u.RawPath) // diff:1227
		if strings.HasSuffix(pattern, "*") {
			p = param                                    // diff:1229
			unclean = unclean || hasDotOrEmptySegment(p) // diff:1230
		}
		if !unclean && unescape { // diff:1233
			var err error
			if p, err = url.PathUnescape(p); err != nil { // diff:1234-1236
				return "", false, false
			}
			unclean = hasDotOrEmptySegment(p) // diff:1238
		}
	}
	// Reconstructed (between hunks, after the comment at diff:1240-1241): path.Clean on a rooted
	// path, then the leading slash is dropped for the filesystem.
	name = strings.TrimPrefix(path.Clean("/"+p), "/")
	return name, unclean, true
}

func valid(c Case) (*url.URL, bool) {
	if c.Mount != MountGlobal && c.Mount != MountGlobalExact && c.Mount != MountRoute {
		return nil, false
	}
	if c.Target == "" || len(c.Target) > maxInput || c.Target[0] != '/' {
		return nil, false
	}
	for i := 0; i < len(c.Target); i++ {
		if !strings.ContainsRune(targetChars, rune(c.Target[i])) {
			return nil, false
		}
	}
	u, err := url.ParseRequestURI(c.Target)
	if err != nil {
		return nil, false
	}
	return u, true
}

// Run evaluates one case for one version.
func Run(c Case, version string) Outcome {
	o := Outcome{ID: c.ID, Version: version, Route: "-", RouterPath: "-", Param: "-", Lookup: "-", Served: "-", PathSeen: "-", RawPathSeen: "-"}
	u, ok := valid(c)
	if !ok || (version != Pre && version != Post) {
		o.Label = LabelBadInput
		return o
	}
	o.PathSeen, o.RawPathSeen = u.Path, u.RawPath
	o.RouterPath = routerPath(u.Path, u.RawPath)
	pattern, param, guarded := route(c.Mount, o.RouterPath)
	o.Route = pattern
	if strings.HasSuffix(pattern, "*") {
		o.Param = param
	}
	// Route mount: Static is middleware of "/*" only; the guarded route
	// answers 403 without Static (diff:1382-1392).
	if c.Mount == MountRoute && guarded {
		o.Label, o.Status = LabelDenied, 403
		return o
	}
	// Global mounts: Static runs before route and group middleware
	// (diff:1206-1208, v5diff:1299-1301).
	name, unclean, ok := lookup(version, u, pattern, param, c.Unescape)
	if !ok {
		o.Label, o.Status = LabelError, 500
		return o
	}
	o.Lookup = name
	if unclean {
		o.Lookup = "!unclean" // diff:1248-1249: handled like a missing file
	} else if _, found := Files[name]; found {
		o.Served, o.Status = name, 200
		switch {
		case !strings.HasPrefix(name, "admin/"):
			o.Label = LabelServed
		case guarded:
			o.Label = LabelOrderBypass
		default:
			o.Label = LabelMismatch
		}
		return o
	}
	if guarded {
		o.Label, o.Status = LabelDenied, 403
	} else {
		o.Label, o.Status = LabelNotFound, 404
	}
	return o
}

// Header is the TSV header shared with fixtures/expected.tsv.
const Header = "id\tversion\tlabel\tstatus\trouter_path\troute\tparam\tlookup\tserved"

// Row renders an outcome; empty strings are written as "”".
func (o Outcome) Row() string {
	f := func(s string) string {
		if s == "" {
			return "''"
		}
		return s
	}
	st := "-"
	if o.Status != 0 {
		st = itoa(o.Status)
	}
	return strings.Join([]string{o.ID, o.Version, o.Label, st, f(o.RouterPath), o.Route, f(o.Param), f(o.Lookup), o.Served}, "\t")
}

func itoa(n int) string {
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if i == len(b) {
		return "0"
	}
	return string(b[i:])
}

// ServesAdmin reports whether the outcome serves a file under admin/.
func ServesAdmin(o Outcome) bool { return o.Label == LabelMismatch || o.Label == LabelOrderBypass }
