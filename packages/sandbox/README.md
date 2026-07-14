# @git-agentic/sentinel-sandbox

The Sentinel capability sandbox: turns an approved capability set into
enforced install-time least-privilege. `createSandbox()` selects **Seatbelt**
on macOS and **bubblewrap** on Linux — deny-by-default writes and `$HOME`
reads, scrubbed environment, all-or-nothing network, and exec containment —
with a fail-closed contract on any other platform.

> **Alpha.** This is a pre-1.0 alpha preview. APIs may change
> without notice. Not production-ready.

```bash
npm install @git-agentic/sentinel-sandbox@alpha
```

## Platform behavior in this alpha

- **macOS (Seatbelt):** full enforcement, including the exec floor and the
  sensitive-executable carve-out. No native compilation involved.
- **Linux (bubblewrap):** filesystem/network/env containment and the
  exfil-tool exec carve-out are always enforced. The **exec floor** is
  enforced via a Landlock helper that this package ships **as source only**
  (`native/landlock-exec.c`) — no prebuilt binary, and deliberately **no
  install-time compilation** (Sentinel does not run lifecycle scripts, by
  posture). Without the compiled helper the exec floor is **advisory**, and
  the sandbox prints a one-time notice saying so.

To opt in to Landlock exec-floor enforcement on Linux, compile the helper
explicitly (requires `cc`):

```bash
node node_modules/@git-agentic/sentinel-sandbox/scripts/build-native.mjs
```

The helper is verified with an ABI probe before use; any failure falls back
to the advisory floor — containment of filesystem, network, and environment
is unaffected either way. See the
[Sentinel repository](https://github.com/git-agentic/pkg-registry) for the
full documentation and threat model.

## License

Apache-2.0
