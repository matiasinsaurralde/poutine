# poutine — vulnerability discovery (from-source analysis)

Threat model: victim clones an attacker-controlled repo and runs `poutine`
(typically `cd repo && poutine analyze_local .`). Every file in the repo —
including `.poutine.yml`, workflow YAML, and git-tracked symlinks — is
attacker-controlled. No interaction beyond running the scan.

Key structural fact: poutine contains **no `os/exec`**, go-git v6 has **no exec
transport**, and `opa/capabilities.json` strips all network/host builtins and
rejects non-empty `allow_net`. A true "run an arbitrary command" RCE is
therefore **not** reachable. The achievable impacts are process crash (two
independent ways), OOM DoS, and arbitrary file read/exfiltration.

## Finding 1 — CONFIRMED: process crash via `uses: "."` (unrecovered panic)
- Sink: `models/purl.go:136` `subPath := uses[2:]`. Guards reject `len==0` and
  `".."` but not the length-1 string `"."`, so `uses[2:]` → slice-out-of-range.
- Reach: `opa/rego/poutine/inventory/github_actions.rego:10` calls
  `purl.parse_github_actions(step.uses, …)` for every step, no validation.
  OPA does not recover Go-builtin panics → whole process dies.
- PoC: `.github/workflows/x.yml` with a step `- uses: "."`.
- Verified end-to-end with the real binary (`analyze_local` → `panic: runtime
  error: slice bounds out of range [2:1]`, exit 2). Double-confirmed by agent D.
- In `analyze_org`, one poisoned repo crashes the whole batch run.

## Finding 1b — CONFIRMED: process crash via empty `.gitlab-ci.yml` job key
- Sink: `models/gitlab.go:185` `Hidden: key[0] == '.'` inside
  `(*GitlabciConfig).UnmarshalYAML`. An empty top-level mapping key `""` is not
  in `invalidJobNames` and not `"default"`, so it reaches `key[0]` on a
  zero-length string → `index out of range [0] with length 0`.
- yaml.v3 re-panics runtime errors (only recovers its own `yamlError`), so the
  panic escapes `yaml.Unmarshal`; no `recover()` on the scan path → process dies.
- PoC: repo-root `.gitlab-ci.yml` containing:  `"":\n  script: echo pwned`
- Verified end-to-end with the real binary (`panic: index out of range [0]…
  gitlab.go:185`). Confirmed by agent B; reproduced independently.

## Finding 2 — CONFIRMED: arbitrary attacker Rego compiled & evaluated
- Chain: attacker `.poutine.yml` `include[].path` → `opa/opa.go:114-131`
  copies verbatim into `LoadPaths` → `opa/opa.go:203-206`
  `loader…Filtered(LoadPaths)` compiles every `*.rego` from the repo into the
  same compiler → `findings.rego:54-58` evaluates `rules[id].results[_]`, so an
  attacker `package rules.<x>` body runs at eval time.
- Paths are not contained (absolute paths and `../` traversal both load).
- PoC: `.poutine.yml` with `include: [{path: ["badrules"]}]` + `badrules/evil.rego`
  defining `package rules.evil`. Verified: injected `"rule_id":"evil-injected"`
  appeared in JSON output. Double-confirmed by agent A.

## Finding 3 — CONFIRMED: OOM DoS via injected Rego (`net.cidr_expand`)
- `capabilities.json` still allows `net.cidr_expand`, `numbers.range`, unbounded
  comprehensions; `opa/opa.go:238-264 Eval` has no time/memory bound.
- PoC rule body `count(net.cidr_expand("10.0.0.0/8"))` → ~2 GB RSS (agent A);
  `/1` or `/0` → tens of GB → OOM-kill.
- Independently verified callable: injected `net.cidr_expand("10.0.0.0/24")`
  rule fired (`"rule_id":"cidr"`).

## Finding 4 — CONFIRMED: arbitrary out-of-repo file read via git symlink
- A git-tracked symlink (mode 120000) at a CI-config path (e.g.
  `.github/workflows/leak.yml -> /home/victim/.kube/config`) is followed:
  `scanner/inventory_scanner.go:35` `filepath.Walk` (Lstat) sees it as a file,
  not skipped; `parsers.go:91` `os.ReadFile(filePath)` follows the symlink.
- Exfiltration: if the target parses as CI YAML, its content surfaces in the
  SARIF/JSON report (agent C reproduced with findings echoing out-of-repo
  content). A parse error echoes the first offending line to stderr (agent A/C;
  I reproduced `/etc/passwd` `root:x:0:0:...` via a symlinked `.rego`).
- No symlink guard anywhere in `scanner/`.
- Two independent symlink sinks: the `.rego` loader (Finding 2 path) and the
  filesystem scanner (this one).

## Ruled out (multiple independent agents)
- RCE / arbitrary command execution: no reachable `os/exec`; go-git v6 exec only
  in tests; capabilities strip exec-adjacent builtins.
- SSRF / network exfil from Rego: `http.send`/`net.lookup_ip_addr` absent →
  compile-time `undefined function`; `allow_net` forced empty.
- go-git `.git/config` RCE (`core.sshCommand`/hooks/`ext::`): PlainOpen is
  read-only, honors none of these.
- Malformed git objects on local path: errors swallowed, no panic.
- Docker/semver/packageurl parsing & ReDoS: no panics (semver's dangerous arg
  comes from bundled advisory data, not attacker YAML; RE2 has no backtracking).
