#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""compose-up.py: `docker compose ... up`, and every service whose start-read
inputs changed is recreated (OPS-165).

    scripts/compose-up.py <compose global args...> up <up args...> [services]

WHY. `docker compose up` recreates a service only when its OWN definition
changed. A long-running service reads its config and key files once, at
start; when a one-shot rewrites one of them, or an update changes a
checked-in config it mounts, the definition is the same and the service keeps
what it read days ago. Measured on a live core 2026-10-09: innsegl-credentials
generated new object-store keys, innsegl-s3-identities rewrote identities.json,
innsegl-s3 (up four days) kept the old keys, innsegl-object-init was refused,
and the update stopped with the core down.

WHAT THIS DOES, in three steps.

  1. The one-shots that write a volume a long-running service reads run first
     (`up -d` of those one-shots, then waited for), with every running
     service's label held at its current value so nothing else moves.
  2. Every long-running service's start-read inputs are hashed: each volume
     it mounts read-only (unless a long-running service writes that volume:
     that is live state, not an input), and each read-only bind mount from
     inside this repository. The hash goes into the service's
     `dev.innsegl.inputs` label through INNSEGL_INPUTS_<SERVICE>, which the
     compose file names.
  3. The `up` asked for runs with those values. A changed label is a changed
     definition, so compose recreates exactly the services whose inputs
     changed, and no others.

`list` prints each long-running service's inputs and the variable it needs,
without touching a container:

    scripts/compose-up.py <compose global args...> list
"""

import hashlib
import io
import json
import os
import re
import subprocess
import sys
import tarfile

LABEL = "dev.innsegl.inputs"
# Up flags that take a value; every other flag is a switch.
VALUE_FLAGS = {"--scale", "-t", "--timeout", "--wait-timeout", "--pull",
               "--exit-code-from", "--attach", "--no-attach", "--attach-dependencies"}
REPO = os.path.realpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))


def say(msg):
    print("compose-up: " + msg, file=sys.stderr, flush=True)


def fail(msg, code=1):
    say("FAIL: " + msg)
    sys.exit(code)


def var_for(service):
    return "INNSEGL_INPUTS_" + re.sub(r"[^A-Z0-9]", "_", service.upper())


def long_running(svc):
    r = svc.get("restart") or ""
    return r in ("always", "unless-stopped") or r.startswith("on-failure")


def one_shot(svc):
    return (svc.get("restart") or "no") == "no"


def inputs(cfg, cfg_all):
    """{service: [(kind, ident, target)]} for every long-running service.
    What counts as live state is decided over every profile (cfg_all), so a
    service's inputs do not depend on which profiles are on."""
    services = cfg.get("services") or {}
    vols = cfg.get("volumes") or {}
    live_written = set()
    for s in (cfg_all.get("services") or {}).values():
        if long_running(s):
            for m in s.get("volumes") or []:
                if m.get("type") == "volume" and not m.get("read_only"):
                    live_written.add(m.get("source"))
    out = {}
    for name, s in services.items():
        if not long_running(s):
            continue
        found = []
        for m in s.get("volumes") or []:
            if not m.get("read_only"):
                continue
            src, tgt = m.get("source") or "", m.get("target") or ""
            if m.get("type") == "volume" and src and src not in live_written:
                real = (vols.get(src) or {}).get("name") or src
                found.append(("volume", real, tgt))
            elif m.get("type") == "bind":
                path = os.path.realpath(src)
                if path == REPO or path.startswith(REPO + os.sep):
                    found.append(("bind", path, tgt))
        out[name] = sorted(found)
    return out


def writers(cfg, ins, closure):
    """The one-shots in closure that write a volume some service reads."""
    services = cfg.get("services") or {}
    vols = cfg.get("volumes") or {}
    read = {ident for lst in ins.values() for kind, ident, _ in lst if kind == "volume"}
    out = []
    for name in sorted(closure):
        s = services.get(name) or {}
        if not one_shot(s):
            continue
        for m in s.get("volumes") or []:
            if m.get("type") == "volume" and not m.get("read_only"):
                real = (vols.get(m.get("source")) or {}).get("name") or m.get("source")
                if real in read:
                    out.append(name)
                    break
    return out


def closure_of(cfg, named, no_deps):
    services = cfg.get("services") or {}
    if not named:
        return set(services)
    seen, todo = set(), list(named)
    while todo:
        n = todo.pop()
        if n in seen or n not in services:
            continue
        seen.add(n)
        if not no_deps:
            todo.extend((services[n].get("depends_on") or {}).keys())
    return seen


def docker(*args, check=True, capture=True, env=None):
    p = subprocess.run(["docker", *args], capture_output=capture, env=env)
    if check and p.returncode != 0:
        err = p.stderr.decode(errors="replace").strip() if capture else ""
        fail("docker %s: exit %d %s" % (" ".join(args[:3]), p.returncode, err))
    return p


def hash_tar(data):
    """sha256 over the files of a `docker cp` tar: names (first component
    stripped) and contents, never times or owners."""
    h = hashlib.sha256()
    with tarfile.open(fileobj=io.BytesIO(data)) as tf:
        members = sorted(tf.getmembers(), key=lambda m: m.name)
        for m in members:
            rel = m.name.split("/", 1)[1] if "/" in m.name else ""
            base = os.path.basename(m.name)
            if ".tmp." in base or base.endswith(".partial"):
                continue
            if m.isfile():
                h.update(b"f\0" + rel.encode() + b"\0")
                h.update(hashlib.sha256(tf.extractfile(m).read()).digest())
            elif m.issym():
                h.update(b"l\0" + rel.encode() + b"\0" + m.linkname.encode() + b"\0")
    return h.hexdigest()


def hash_path(path):
    h = hashlib.sha256()
    if os.path.isfile(path):
        with open(path, "rb") as f:
            h.update(hashlib.sha256(f.read()).digest())
        return h.hexdigest()
    for root, dirs, files in os.walk(path):
        dirs[:] = sorted(d for d in dirs if d != "__pycache__")
        for fn in sorted(files):
            p = os.path.join(root, fn)
            rel = os.path.relpath(p, path)
            if os.path.islink(p):
                h.update(b"l\0" + rel.encode() + b"\0" + os.readlink(p).encode() + b"\0")
            else:
                with open(p, "rb") as f:
                    h.update(b"f\0" + rel.encode() + b"\0" + hashlib.sha256(f.read()).digest())
    return h.hexdigest()


def hash_volume(name, cache):
    """The volume's content, read through a container that already mounts it.
    No container of our own: the one-shot that wrote it, or its reader, is
    there to read it through."""
    if name in cache:
        return cache[name]
    if docker("volume", "inspect", name, check=False).returncode != 0:
        # Compose is about to create it empty: the same value an empty
        # volume reads as, so the next run does not see a change.
        cache[name] = hashlib.sha256().hexdigest()
        return cache[name]
    ids = docker("ps", "-a", "--filter", "volume=" + name, "--format", "{{.ID}}").stdout.decode().split()
    value = "unread"
    for cid in ids:
        mounts = json.loads(docker("inspect", "-f", "{{json .Mounts}}", cid).stdout or b"[]")
        dest = next((m["Destination"] for m in mounts
                     if m.get("Type") == "volume" and m.get("Name") == name), None)
        if not dest:
            continue
        p = docker("cp", cid + ":" + dest + "/.", "-", check=False)
        if p.returncode == 0:
            value = hash_tar(p.stdout)
            break
    cache[name] = value
    return value


def compose_config(gargs):
    p = subprocess.run(["docker", "compose", *gargs, "config", "--format", "json"],
                       capture_output=True)
    if p.returncode != 0:
        fail("docker compose config: " + p.stderr.decode(errors="replace").strip())
    return json.loads(p.stdout)


def current_labels(cfg):
    project = cfg.get("name") or ""
    p = docker("ps", "-a", "--filter", "label=com.docker.compose.project=" + project,
               "--format", '{{.Label "com.docker.compose.service"}}\t{{.Label "' + LABEL + '"}}')
    out = {}
    for line in p.stdout.decode().splitlines():
        svc, _, val = line.partition("\t")
        out[svc] = val
    return out


def main(argv):
    if "up" in argv:
        i = argv.index("up")
        mode = "up"
    elif "list" in argv:
        i = argv.index("list")
        mode = "list"
    else:
        fail("usage: compose-up.py <compose args...> up|list [args...]", 2)
    gargs, uargs = argv[:i], argv[i + 1:]

    cfg = compose_config(gargs)
    cfg_all = compose_config(["--profile", "*", *gargs])
    ins = {s: v for s, v in inputs(cfg, cfg_all).items() if v}

    if mode == "list":
        for svc in sorted(ins):
            print("%s %s" % (svc, var_for(svc)))
            for kind, ident, tgt in ins[svc]:
                print("  %s %s -> %s" % (kind, os.path.relpath(ident, REPO) if kind == "bind" else ident, tgt))
        return 0

    named, skip = [], False
    for a in uargs:
        if skip:
            skip = False
            continue
        if a.startswith("-"):
            if a in VALUE_FLAGS:
                skip = True
            continue
        named.append(a)
    no_deps = "--no-deps" in uargs
    closure = closure_of(cfg, named, no_deps)

    env = dict(os.environ)
    held = current_labels(cfg)
    # Step 1: the writers first, everything else held where it is.
    w = writers(cfg, ins, closure)
    if w:
        e1 = dict(env)
        for svc in ins:
            e1[var_for(svc)] = held.get(svc, "")
        extra = [f for f in ("--no-build", "--no-deps") if f in uargs]
        say("rendering first: " + " ".join(w))
        p = subprocess.run(["docker", "compose", *gargs, "up", "-d", *extra, *w], env=e1)
        if p.returncode != 0:
            fail("bringing up %s exited %d" % (" ".join(w), p.returncode), p.returncode)
        project = cfg.get("name") or ""
        for svc in w:
            ids = docker("ps", "-a", "-q", "--filter", "label=com.docker.compose.project=" + project,
                         "--filter", "label=com.docker.compose.service=" + svc).stdout.decode().split()
            if not ids:
                fail("%s did not start" % svc)
            rc = docker("wait", ids[0]).stdout.decode().strip()
            if rc != "0":
                subprocess.run(["docker", "logs", "--tail", "30", ids[0]])
                fail("%s exited %s" % (svc, rc))

    # Step 2: hash what each service reads at start.
    cache = {}
    for svc, lst in sorted(ins.items()):
        h = hashlib.sha256()
        for kind, ident, tgt in lst:
            v = hash_volume(ident, cache) if kind == "volume" else hash_path(ident)
            h.update(("%s\0%s\0%s\n" % (kind, tgt, v)).encode())
        value = h.hexdigest()[:24]
        env[var_for(svc)] = value
        before = held.get(svc)
        if before is not None and before != value and svc in closure:
            say("%s: its start-read inputs changed; it is recreated" % svc)

    # Step 3: the up that was asked for.
    os.execvpe("docker", ["docker", "compose", *gargs, "up", *uargs], env)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
