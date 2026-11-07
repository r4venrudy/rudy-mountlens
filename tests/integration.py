"""Independent parent graph, stack, and snapshot comparison oracle."""
from collections import Counter, defaultdict
import copy
import json
from pathlib import Path
import random
import subprocess
import sys
from tempfile import TemporaryDirectory

binary = Path(sys.argv[1]).resolve()
examples = Path(sys.argv[2]).resolve()
checks = 0
keys = ("readOnly", "nosuid", "nodev", "noexec")


def check(value, detail):
    global checks
    checks += 1
    if not value:
        raise AssertionError(detail)


def invoke(*args, status=0):
    completed = subprocess.run([binary, *args], capture_output=True, text=True,
                               encoding="ascii", timeout=30)
    check(completed.returncode == status, (args, completed.returncode, completed.stderr[:300]))
    if status == 2:
        check(not completed.stdout and completed.stderr.startswith("mountlens:"), completed)
        return None
    check(not completed.stderr, completed.stderr)
    return json.loads(completed.stdout)


def policy(row):
    return {"readOnly": row["ro"] or row["super_ro"],
            "nosuid": row["nosuid"], "nodev": row["nodev"], "noexec": row["noexec"]}


def model(rows):
    ids = {row["id"]: row for row in rows}
    parents = {row["id"]: ids.get(row["parent"]) if row["parent"] != row["id"] else None for row in rows}
    shadowed = {row["parent"] for row in rows
                if parents[row["id"]] and parents[row["id"]]["target"] == row["target"]}
    groups = defaultdict(list)
    peers = Counter(row["shared"] for row in rows if row["shared"])
    for row in rows:
        groups[row["target"]].append(row)
    return parents, shadowed, groups, peers


def check_inspect(rows, report):
    parents, shadowed, groups, peers = model(rows)
    by_id = {row["id"]: row for row in report["mounts"]}
    check(list(by_id) == sorted(row["id"] for row in rows), "stable mount ordering")
    for row in rows:
        actual = by_id[row["id"]]
        parent = parents[row["id"]]
        depth, cursor = 0, parent
        while cursor is not None:
            depth += 1
            cursor = parents[cursor["id"]]
        check(actual["depth"] == depth and actual["parentId"] == row["parent"], actual)
        check(actual["parentTarget"] == (parent["target"] if parent else None), actual)
        check(actual["parentRelation"] == ("attached" if parent else
              "self-root" if row["id"] == row["parent"] else "outside-snapshot"), actual)
        check(actual["target"] == row["target"] and actual["root"] == row["root"], actual)
        check(actual["shadowedAtTarget"] == (row["id"] in shadowed), actual)
        check(actual["restrictions"] == policy(row), actual)
        check(actual["propagation"]["sharedPeersInSnapshot"] == peers[row["shared"]], actual)
    expected_counts = dict(mounts=len(rows), targets=len(groups),
        externalParents=sum(parents[r["id"]] is None and r["id"] != r["parent"] for r in rows),
        directStacks=sum(len(group) > 1 and sum(r["id"] not in shadowed for r in group) == 1
                         for group in groups.values()),
        ambiguousTargets=sum(sum(r["id"] not in shadowed for r in group) != 1 for group in groups.values()))
    check(report["counts"] == expected_counts, (report["counts"], expected_counts))


def expected_compare(before, after):
    prior = model(before)
    later = model(after)
    counts = dict(unchanged=0, added=0, removed=0, changed=0, ambiguous=0, relaxed=0)
    expected = {}
    for target in sorted(prior[2].keys() | later[2].keys()):
        old, new = [m[2].get(target, []) for m in (prior, later)]
        a = [r for r in old if r["id"] not in prior[1]]
        b = [r for r in new if r["id"] not in later[1]]
        lost = dict.fromkeys(keys, False)
        gained = dict.fromkeys(keys, False)
        attachment = backing = propagation = False
        if len(a) > 1 or len(b) > 1:
            state = "ambiguous"
        elif not a:
            state = "added"
        elif not b:
            state = "removed"
        else:
            x, y = a[0], b[0]
            pa, pb = prior[0][x["id"]], later[0][y["id"]]
            attachment = ((pa and pa["target"], x["id"] == x["parent"]) !=
                          (pb and pb["target"], y["id"] == y["parent"]))
            backing = any(x[k] != y[k] for k in ("root", "source", "device", "filesystem"))
            propagation = ((bool(x["shared"]), bool(x["master"]), bool(x["from"]), x["unbindable"],
                            prior[3][x["shared"]]) !=
                           (bool(y["shared"]), bool(y["master"]), bool(y["from"]), y["unbindable"],
                            later[3][y["shared"]]))
            old_policy, new_policy = policy(x), policy(y)
            lost = {key: old_policy[key] and not new_policy[key] for key in keys}
            gained = {key: new_policy[key] and not old_policy[key] for key in keys}
            state = "changed" if (len(old) != len(new) or any(lost.values()) or any(gained.values())
                                  or attachment or backing or propagation) else "unchanged"
            counts["relaxed"] += any(lost.values())
        counts[state] += 1
        if state != "unchanged":
            expected[target] = (state, len(old), len(new), len(a), len(b), attachment,
                                backing, propagation, lost, gained)
    return counts, expected


def check_compare(before, after, report):
    counts, expected = expected_compare(before, after)
    check(report["counts"] == counts, (report["counts"], counts))
    check([r["target"] for r in report["changes"]] == list(expected), "ordered changed targets")
    for row in report["changes"]:
        actual = tuple(row[key] for key in ("status", "beforeLayers", "afterLayers",
            "beforeCandidates", "afterCandidates", "attachmentChanged", "backingChanged",
            "propagationChanged", "lost", "gained"))
        check(actual == expected[row["target"]], (row, expected[row["target"]]))


def escape_token(text):
    for char, code in (("\\", "\\134"), (" ", "\\040"), ("\t", "\\011"), ("\n", "\\012")):
        text = text.replace(char, code)
    return text


def row_text(row):
    opts = ["ro" if row["ro"] else "rw"] + [k for k in keys[1:] if row[k]]
    optional = [f"{name}:{row[key]}" for name, key in (
        ("shared", "shared"), ("master", "master"), ("propagate_from", "from")) if row[key]]
    if row["unbindable"]:
        optional.append("unbindable")
    optional.append("future-tag:example")
    return " ".join(map(str, [row["id"], row["parent"], row["device"], escape_token(row["root"]),
        escape_token(row["target"]), ",".join(opts), *optional, "-", row["filesystem"],
        escape_token(row["source"]), "ro,size=1" if row["super_ro"] else "rw,size=1"]))


def make_row(identity, parent, target):
    return dict(id=identity, parent=parent, target=target, root="/", filesystem="tmpfs", source="tmpfs",
                device="0:45", shared=0, master=0, **{"from":0}, unbindable=False,
                ro=False, super_ro=False, nosuid=False, nodev=False, noexec=False)


fixed_a, fixed_b = examples / "before.mountinfo", examples / "after.mountinfo"
fixed = invoke("compare", fixed_a, fixed_b, "--fail-on-relaxation", status=1)
check(fixed["counts"]["relaxed"] == 1 and fixed["counts"]["ambiguous"] == 1, fixed)
srv = next(r for r in fixed["changes"] if r["target"] == "/srv")
check(srv["beforeLayers"] == 2 and srv["before"]["id"] == 21, srv)
check(srv["lost"] == {"readOnly":True, "nosuid":False, "nodev":True, "noexec":False}, srv)
check(invoke("compare", fixed_a, fixed_a, "--fail-on-relaxation", status=3)["counts"]["ambiguous"] == 1,
      "ambiguous target prevents a passing gate")
check(invoke("inspect", fixed_a)["counts"]["externalParents"] == 1, "outside root parent")

with TemporaryDirectory() as scratch:
    left, right = Path(scratch) / "left.mountinfo", Path(scratch) / "right.mountinfo"
    rng = random.Random(20261107)
    for trial in range(16):
        rows = [make_row(1, 1 if trial % 2 else 99000, "/")]
        for n in range(2, 98):
            parent = rng.choice(rows)
            target = parent["target"] if n % 7 == 0 else f"/target {n % 80:02}"
            row = make_row(n, parent["id"], target)
            row.update({key: bool(rng.randrange(2)) for key in ("ro", "super_ro", "nosuid", "nodev", "noexec")})
            row["shared"] = rng.choice((0, 0, 11, 13))
            row["master"] = rng.choice((0, 12))
            row["from"] = 13 if row["master"] and n % 4 == 0 else 0
            row["unbindable"] = not row["shared"] and not row["master"] and n % 5 == 0
            row["source"] = "mock\tvolume\n" if n % 11 == 0 else "tmpfs"
            rows.append(row)
        later = copy.deepcopy(rows)
        for row in later:
            row["id"] += 1000
            row["parent"] += 1000
            if row["id"] % 7 == 0:
                row["nodev"] = not row["nodev"]
                row["super_ro"] = not row["super_ro"]
            if row["id"] % 11 == 0:
                row["root"] = "/changed"
            if row["id"] % 13 == 0 and row["id"] != 1001:
                row["parent"] = 1001
            row["shared"] += 100 if row["shared"] else 0
            row["master"] += 100 if row["master"] else 0
        later = [r for r in later if r["target"] != "/target 03"]
        later.append(make_row(5000, 1001, "/new"))
        for path, model_rows in ((left, rows), (right, later)):
            lines = [row_text(r) for r in model_rows]
            rng.shuffle(lines)
            path.write_bytes(("\r\n" if trial % 2 else "\n").join(lines).encode("ascii"))
            check_inspect(model_rows, invoke("inspect", path))
        result = invoke("compare", left, right)
        check_compare(rows, later, result)

    valid = b"1 1 8:1 / / rw - ext4 /dev/root rw"
    invalid = [
        b"", b"\n", valid + b"\n" + valid,
        b"1 2 0:0 / /a rw - tmpfs none rw\n2 1 0:0 / /b rw - tmpfs none rw",
        b"1 1 0:0 / /a rw - tmpfs none rw",
        b"4294967296 1 0:0 / / rw - tmpfs none rw",
        valid.replace(b"/ / rw", b"/ /a/../b rw"),
        valid.replace(b"/ / rw", b"/ /invalid\\041 rw"),
        valid.replace(b"/ / rw", b"/ /invalid\t rw"),
        valid.replace(b"/ / rw", b"/ /invalid\0 rw"),
        valid.replace(b"/ / rw", b"/ / ro,rw"),
        valid.replace(b" - ext4", b" shared:5 shared:6 - ext4"),
        valid.replace(b" - ext4", b" shared:0 - ext4"),
        valid.replace(b" - ext4", b" shared:5 unbindable - ext4"),
        valid.replace(b" - ext4", b" ext4"),
        valid + b" " + b"a" * 65537,
    ]
    for data in invalid:
        left.write_bytes(data)
        invoke("inspect", left, status=2)
    left.write_bytes(valid + b"\n2 1 0:0 / /bytes\xff\\134quote\" rw - tmpfs none rw\n")
    report = invoke("inspect", left)
    check(report["mounts"][1]["target"].encode("latin-1") == b'/bytes\xff\\quote"', "reversible path bytes")
    chain = [row_text(make_row(1, 1, "/"))]
    chain += [row_text(make_row(n, n-1, "/stack")) for n in range(2, 12001)]
    left.write_text("\n".join(chain), encoding="ascii")
    deep = invoke("inspect", left)
    check(deep["mounts"][-1]["depth"] == 11999 and deep["counts"]["directStacks"] == 1, "deep stack")
print(f"{checks} independent conditions across 16 generated snapshot pairs, malformed input, and a 12,000-record stack")
