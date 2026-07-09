# Sentinel

The ubiquitous language for Sentinel — the agent-auditable security layer for npm. This is a glossary, not a spec: it defines what terms *mean*, not how anything is implemented. Architecture lives in [ARCHITECTURE.md](./ARCHITECTURE.md); decisions in [docs/adr/](./docs/adr/).

## Language

### Sandbox capability model

**Capability**:
A single permission a package's install-time code may exercise — a `filesystem` target, `network`, `process`, or `env` name. The unit the sandbox reasons about.

**Approval**:
An operator's decision to allow a specific `Capability` for a specific package version. Recorded against the immutable integrity hash; an agent may *request* one but only a human *grants* it.

**Grant**:
A positive allow the sandbox profile emits for an approved `Capability` — the sandbox opens exactly that resource. The inverse of a deny.
_Avoid_: permission, allow-rule.

**Deny-by-default**:
The sandbox posture where a resource class (filesystem writes, home-directory reads) is closed unless a `Grant` or a baseline allow opens it. The opposite of the older allow-default-plus-deny-list posture.

**Carve-out**:
A deny punched *back* into an otherwise-allowed region — e.g. `/etc` is read-allowed for the runtime, but `/etc/passwd` is carved out. Distinct from a blanket deny, which closes a whole region.

**Sensitive path**:
A credential or persistence filesystem location Sentinel treats as dangerous (SSH keys, cloud creds, shell rc files, autostart). The shared source of truth for both code-level detection and sandbox `Carve-out`s.
_Avoid_: secret path, protected path.

**Read-allow list**:
The fixed set of paths a sandboxed script may still read *inside* `$HOME` once home-directory reads are `Deny-by-default` — the node install prefix, the `Project root`, and the node build caches. Everything else under `$HOME` is denied; system paths outside `$HOME` are unaffected.
_Avoid_: read floor (the write-side term is `write floor`; reads use an allow *list*, not a floor, since there's no baseline every script needs beyond the node runtime and its own project).

**Node install prefix**:
The directory the running node runtime is installed under (one level above its `bin/`) — derived from `process.execPath`. Read-allowed so a node runtime installed *under* `$HOME` (nvm/fnm/volta) can still load its own standard library.

### Install topology

**Install directory**:
The directory a lifecycle script runs *in* — the package's own extracted/build tree (the sandbox's `cwd`). Where build output lands.
_Avoid_: package dir (ambiguous — could mean this or the Project root), working directory.

**Project root**:
The ancestor directory whose `node_modules` a lifecycle script's `require()` resolves against — distinct from the Install directory, which sits *inside* it. A script needs read access to the whole Project root, not just its own Install directory.
_Avoid_: workspace, package dir.

**Sandbox backend**:
The platform enforcement engine selected by `createSandbox()` — Seatbelt on macOS, bubblewrap on Linux — sharing one approved-capability model and fail-closed contract.
