# Go-public checklist (operator)

Pre-flight is done on the `oss-launch-prep` branch: LICENSE, SECURITY.md,
CODE_OF_CONDUCT.md, CONTRIBUTING.md, threat model, CodeQL workflow, issue
templates, README status/badges, repo description/homepage/topics, and a
clean full-history secrets scan (gitleaks + pattern grep). What remains
needs the repo to be PUBLIC, so it's yours, in order:

1. **Merge** `oss-launch-prep` into `main` and push.
2. **Flip visibility**: repo Settings → General → Danger Zone → Change
   visibility → Public. (Everything in git history becomes visible; the
   secrets scan covering all commits was a merge precondition.)
3. **Enable private vulnerability reporting** (public-only):
   `gh api -X PUT repos/git-agentic/pkg-registry/private-vulnerability-reporting`
   — SECURITY.md's reporting instructions depend on this.
4. **Enable secret scanning + push protection** (public-only): Settings →
   Code security → enable both.
5. **Confirm CodeQL ran**: Actions → `codeql` workflow green on main;
   Security → Code scanning shows results.
6. **Confirm the badges render** on the README (ci + codeql + license) and
   the license is detected on the repo sidebar as Apache-2.0.
7. **Verify the GitHub Action is consumable**: in a scratch public repo, add
   a workflow step `uses: git-agentic/pkg-registry@main` pointing at the
   root `action.yml`; confirm it resolves and runs observe-only
   (`fail-on: none`).
8. **Spot-check rendering**: README, SECURITY.md, CONTRIBUTING.md,
   sentinel-threat-model.md, and one issue template (open the new-issue
   chooser — blank issues should be disabled, security contact link shown).
9. **Link the repo from https://git-agentic.com/sentinel.**
10. Optional: create a `v0.1.0` tag/release once you're happy — not part of
    this launch.
