#!/usr/bin/env python3
"""Independent derivation of fixtures/expected.tsv (and, with "sweep", of
results/sweep.csv).

Written from the saved fix diffs of labstack/echo (b838391, v4: middleware/
static.go diff:1212-1286; fc41009, v5: v5diff:1305-1379), the GHSA/NVD text
and the documented behaviour of Go's net/url (parsing of Path and RawPath,
PathUnescape) and path.Clean. It does not import, call or read the Go model:
URL parsing, segment checks, router lookup and labels are re-implemented
here in plain Python.
"""
import sys
from pathlib import Path

HEX = "0123456789abcdefABCDEF"
TARGET_CHARS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~/%")
FILES = {"admin/secret.txt", "public/index.html", "hello world.txt", "public/admin/other.txt", "x/file.txt"}
MOUNTS = ("global", "global-exact", "route")


class BadEscape(Exception):
    pass


def unescape(s):
    out, i, b = bytearray(), 0, s.encode()
    while i < len(b):
        if b[i] == 0x25:
            if i + 2 >= len(b) or chr(b[i + 1]) not in HEX or chr(b[i + 2]) not in HEX:
                raise BadEscape(s)
            out.append(int(b[i + 1:i + 3], 16))
            i += 3
        else:
            out.append(b[i])
            i += 1
    return out.decode("latin-1")


def escape(p):
    keep = lambda ch: ch.isascii() and (ch.isalnum() or ch in "-_.~$&+,/:;=@")
    return "".join(ch if keep(ch) else "%%%02X" % ord(ch) for ch in p)


def parse(target):
    """(Path, RawPath) as Go url.ParseRequestURI sets them."""
    p = unescape(target)
    return p, ("" if escape(p) == target else target)


def clean_rooted(p):
    stack = []
    for seg in p.split("/"):
        if seg in ("", "."):
            continue
        if seg == "..":
            if stack:
                stack.pop()
            continue
        stack.append(seg)
    return "/" + "/".join(stack)


def dot_or_empty(p):
    if p.startswith("/"):
        p = p[1:]
    if p.endswith("/"):
        p = p[:-1]
    return p != "" and any(s in ("", ".", "..") for s in p.split("/"))


def lookup_route(mount, rp):
    if mount in ("global", "route") and rp.startswith("/admin/"):
        return "/admin/*", rp[7:], True
    if mount == "global-exact" and rp == "/admin/secret.txt":
        return "/admin/secret.txt", None, True
    if mount == "route":
        return "/*", rp[1:] if rp.startswith("/") else rp, False
    return "none", None, False


def derive(target, mount, unesc, version):
    row = dict(label="BAD_INPUT", status="-", rp="-", route="-", param="-", lookup="-", served="-")
    if mount not in MOUNTS or not target or len(target) > 512 or target[0] != "/" or set(target) - TARGET_CHARS:
        return row
    try:
        path, raw = parse(target)
    except BadEscape:
        return row
    rp = raw if raw else path
    pattern, param, guarded = lookup_route(mount, rp)
    row.update(rp=rp, route=pattern, param=param if pattern.endswith("*") else "-")
    if mount == "route" and guarded:
        row.update(label="DENIED_403", status="403")
        return row
    wildcard = pattern.endswith("*")
    unclean = False
    if version == "pre":
        p = param if wildcard else path
        if unesc:
            try:
                p = unescape(p)
            except BadEscape:
                row.update(label="ERROR_500", status="500")
                return row
    else:
        p = raw if raw else path
        unclean = dot_or_empty(raw if raw else path)
        if wildcard:
            p = param
            unclean = unclean or dot_or_empty(p)
        if not unclean and unesc:
            try:
                p = unescape(p)
            except BadEscape:
                row.update(label="ERROR_500", status="500")
                return row
            unclean = dot_or_empty(p)
    name = clean_rooted("/" + p)[1:]
    row["lookup"] = "!unclean" if unclean else name
    if not unclean and name in FILES:
        lab = "SERVED" if not name.startswith("admin/") else ("ORDER_BYPASS" if guarded else "MISMATCH")
        row.update(label=lab, status="200", served=name)
        return row
    row.update(label="DENIED_403" if guarded else "NOT_FOUND_404", status="403" if guarded else "404")
    return row


TOKENS = ["", "/", ".", "..", "%2e%2e", "%2F", "%61dmin", "admin", "x", "%252e%252e"]


def sweep():
    targets = []
    for a in TOKENS:
        for b in TOKENS:
            for c in TOKENS:
                t = "/" + a + b + c + "secret.txt"
                if t not in targets:
                    targets.append(t)
    out = ["id,target,mount,unescape,pre_label,pre_served,post_label,post_served"]
    n = 0
    for m in MOUNTS:
        for un in (False, True):
            for t in targets:
                n += 1
                pre, post = derive(t, m, un, "pre"), derive(t, m, un, "post")
                out.append(",".join(["s%d" % n, t, m, "1" if un else "0", pre["label"], pre["served"], post["label"], post["served"]]))
    sys.stdout.write("\n".join(out) + "\n")


def main():
    if sys.argv[1:] == ["sweep"]:
        sweep()
        return
    root = Path(__file__).resolve().parent.parent
    out = ["id\tversion\tlabel\tstatus\trouter_path\troute\tparam\tlookup\tserved"]
    f = lambda s: "''" if s == "" else s
    for line in (root / "fixtures" / "cases.tsv").read_text().splitlines():
        if not line or line.startswith("#"):
            continue
        cid, target, mount, un = line.split("\t")
        for version in ("pre", "post"):
            r = derive(target, mount, un == "1", version)
            out.append("\t".join([cid, version, r["label"], r["status"], f(r["rp"]), r["route"],
                                  f(r["param"]), f(r["lookup"]), r["served"]]))
    sys.stdout.write("\n".join(out) + "\n")


if __name__ == "__main__":
    main()
