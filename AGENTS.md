# webkit-driftstack — repository context (agent policy)

This file is mirrored across the three Driftstack repositories
(`driftstack-api`, `driftstack`, `webkit-driftstack`). Edits to
this file should be applied identically to all three. The
canonical source of truth is `driftstack-api/AGENTS.md` §
"Founder anonymity policy", "Git identity policy", "Commit
attribution policy", and "Customer-facing copy policy"; this
file mirrors those four sections only.

This repository is a fork of Apple's WebKit; it is **publicly
visible**. Commit history is on the public internet. The
attribution policy below is therefore particularly load-bearing:
nothing personal, nothing AI-tooling, nothing that breaks
founder anonymity or product framing belongs in commit
metadata or the message body.

The deeper project context for this specific repository (build
environment, modified-file surfaces, modification process)
lives elsewhere in this repo. This file contains only the
cross-repo agent attribution and presentation policies.

## ⚠️ Founder anonymity policy

Driftstack does not attribute work to a specific named person on customer-facing surfaces. All public-facing copy refers to "Driftstack" as the entity, never to a personal founder name.

- **DO NOT** include personal founder name on `/about`, `/security`, `/docs`, marketing site, customer dashboard, admin panel, FAQ, or any public-facing surface.
- **DO NOT** include personal founder bio paragraphs ("Driftstack is built by [name]" framing).
- **DO** use "Driftstack" / "the Driftstack team" / "we" framing for company voice.
- **DO** use generic role descriptions where founder context is needed (e.g. "founded in 2026 in the Netherlands").

Internal documentation, `docs/decisions.md`, V-log entries, and engineering scaffolding can reference founder context for engineering accuracy. Customer-facing surfaces stay anonymous.

This applies to commit history as well: commit author and committer fields use the Driftstack-branded identity (per the next section), not a personal name. Particularly load-bearing here because this repo is public.

## ⚠️ Git identity policy

All commits in this repo use the Driftstack-branded git identity, not a personal name + email.

```
git config --local user.name "Driftstack"
git config --local user.email "dev@driftstack.dev"
```

The local config above is set per-clone; verify with `git config --local user.name` after cloning. Existing commits with the prior personal identity (or with an AI-tooling email such as `noreply@anthropic.com`) are rewritten via a force-push attribution-cleanup runbook in `docs/founder-actions/` — driftstack-api uses `v207-force-push-attribution-cleanup.md`; this repo will use a parallel runbook surfaced as a separate V-NNN founder-action document.

If `git config --local --get user.name` does not return `Driftstack` after cloning, set it before the next commit. Never push commits with a personal name as author. **Particularly load-bearing here because this repo is public; every commit's author shows up on github.com/driftstackdev/webkit-driftstack to anyone browsing the repo.**

## ⚠️ Commit attribution policy

Commits are attributed to the Driftstack identity (per the git identity policy above), not to AI development tooling.

- **DO NOT** include `Co-Authored-By: Claude <noreply@anthropic.com>` (or any other AI-tool name) trailer on commits.
- **DO NOT** include `🤖 Generated with [Claude Code]` (or any equivalent) footer on commits.
- **DO NOT** reference Anthropic / Claude / AI tooling in commit messages, including in body text.
- Commit message body documents engineering work; tooling is not part of commit metadata.

This is a presentation choice, not capability disclosure. Driftstack engineering uses whatever tools are most effective; commit history reflects the work, not the tooling.

Applies to every commit going forward without exception. If a tool's default appends an attribution trailer, override the default. When using `git commit -m "$(cat <<'EOF' ... EOF)"` heredoc, the message ends with a normal blank line — never a `Co-Authored-By:` trailer.

**Particularly load-bearing here because this repo is public**; commit-message bodies are visible to anyone browsing the GitHub repo, and AI-tooling references in public commit history are exactly the kind of presentation breakage the policy exists to prevent.

## ⚠️ Customer-facing copy policy

Marketing site, customer dashboard, admin panel, FAQ, docs, and any public-facing surfaces:

- **DO NOT** reference AI / AI-assisted development / AI tooling on customer-facing copy.
- **DO NOT** mention Claude / Anthropic / OpenAI / specific AI tools.
- **DO NOT** use "AI-powered" or "AI-built" framing.
- **DO NOT** include personal founder name (per the Founder anonymity policy above).
- Driftstack is the product; the development tooling that produced it is not customer-facing information.

Internal documentation (architecture docs, planning docs, `docs/decisions.md`) can reference tooling for engineering accuracy. Customer-facing surfaces stay product-focused.

The Anthropic API used as a BYO bundled LLM (per driftstack-api's sub-processor list) is product surface, not development-tooling reference — that's allowed when documenting customer-facing capability.

Documentation surfaces in **this** repo (e.g. `MODIFICATIONS.md`, fork-build runbooks) are **internal engineering**, not customer-facing — references to tooling here are fine when they help future engineers understand fork mechanics. The boundary is: anything that goes onto driftstack.dev / customer dashboard / signup flow / admin panel is customer-facing; anything else in this repo is internal.
