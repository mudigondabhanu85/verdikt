# Architecture & Product Overview

Full technical reference documentation and a presentation deck for Verdikt,
generated directly from the codebase (not hand-summarized) — every fact,
including the reference appendices, was verified against the actual source
at the time of writing.

## Contents

- **`Verdikt_Architecture_Document.md` / `.html` / `.docx`** — the same
  document in three formats. Covers the system architecture, the 31-node
  multi-agent scanning engine, the Confirmed-Only Findings pipeline, the
  pluggable AI provider layer, vulnerability coverage, VGS integration
  (three modes), enterprise hardening, deployment (Docker + manual +
  standalone browser extension), and testing discipline — plus full
  reference appendices (every data model, API route, check ID, config
  setting, migration, and RBAC resource), a Frequently Asked Questions
  section, and an honest "spec vs. reality" delta against
  `docs/BUILD_SPEC.md`. The `.html` version renders its diagrams live via
  Mermaid; the `.docx` version embeds them as images.
- **`Verdikt_Presentation.pptx`** — a 22-slide deck covering the same
  material at presentation depth, including a tech-stack ("app info")
  slide, a "by the numbers" slide, an honest spec-vs-reality slide, and a
  closing FAQ slide.
- **`diagrams/*.mmd`** — the 6 architecture diagrams as Mermaid source:
  system architecture, data model (ER diagram), the verified 31-node scan
  DAG, the Confirmed-Only Findings pipeline, AI provider resolution order,
  and deployment topology. Miro has a native Mermaid-import feature, so
  these can be dropped directly into a board and remain editable — there's
  no separate literal "Miro file format" to export to instead.
- **`diagrams/*.png`** — the same 6 diagrams pre-rendered at high
  resolution, used to embed them in the `.docx` and `.pptx`.

## Regenerating

The diagrams were rendered with `@mermaid-js/mermaid-cli` via
`npx -y @mermaid-js/mermaid-cli -i <file>.mmd -o <file>.png -b white -s 3`.
The `.html`/`.docx`/`.pptx` were generated from the Markdown source with
small one-off Python scripts (`markdown` + hand-rolled Markdown→DOCX via
`python-docx`, and `python-pptx` for the deck) — not checked into the repo,
since they're throwaway build tooling rather than part of the application.
