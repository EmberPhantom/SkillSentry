# Work Checklists — Index

> Task-level breakdown of [11-team-and-workload.md](../11-team-and-workload.md). Each developer's work packages are elaborated into **multiple checklists** with concrete tasks, dependencies, and acceptance criteria.

## 📋 The Checklist Files

| Developer | Role | File | Checklists |
|:---|:---|:---|:---|
| **Dev 1** | Backend + AI Integration | [dev1-backend-ai.md](dev1-backend-ai.md) | CL-D1-0 … CL-D1-8 (9) |
| **Dev 2** | Backend — Skill Analysis | [dev2-skill-analysis.md](dev2-skill-analysis.md) | CL-D2-0 … CL-D2-8 (9) |
| **Dev 3** | Frontend | [dev3-frontend.md](dev3-frontend.md) | CL-D3-0 … CL-D3-8 (9) |

## 🗓️ Milestone → Checklist Matrix

| Milestone | Dev 1 | Dev 2 | Dev 3 |
|:---|:---|:---|:---|
| **M0** · Contracts & Scaffold | CL-D1-0, CL-D1-1 | CL-D2-0, CL-D2-1 (parser part) | CL-D3-0, CL-D3-1 |
| **M1** · Sandbox Base + Deterministic Analysis | CL-D1-2, CL-D1-3 | CL-D2-1, CL-D2-2, CL-D2-3, CL-D2-4 | CL-D3-2, CL-D3-3 (start) |
| **M2** · Deception, Vision, Live Pipeline | CL-D1-4, CL-D1-6 (start) | CL-D2-5, CL-D2-6 | CL-D3-3, CL-D3-4, CL-D3-5 |
| **M3** · Verdict, Reports, E2E | CL-D1-5, CL-D1-6 (finish) | CL-D2-6 (finish), CL-D2-7 | CL-D3-6, CL-D3-7 (start) |
| **M4** · Hardening & Rehearsal | CL-D1-7 | CL-D2-7 (finish) | CL-D3-7 (finish), CL-D3-8 |
| **M5** · Stabilization | CL-D1-8 | CL-D2-8 | CL-D3-8 (post-demo polish) |

## 🔗 Cross-Developer Dependency Quick Reference

| Artifact | Producer | Consumers | Checklist |
|:---|:---|:---|:---|
| Frozen contracts + shared constants (I1) | Dev 1 | everyone | CL-D1-1 |
| Mock server (`demo_mode`) | Dev 1 | Dev 3 (all UI work), Dev 2 (demo payloads later) | CL-D1-1 |
| Model client + `MockGemma` (I2) | Dev 1 | Dev 2 semantic/vision | CL-D1-3 |
| `StageResult` structs (I3) | Dev 2 | Dev 1 orchestrator/fusion | CL-D2-2/3/5 |
| `declared_intent` normalized keywords | Dev 2 | Dev 1 context honeypots | CL-D2-3 ↔ CL-D1-4 |
| Cache store interface | Dev 2 | Dev 1 Stage 0 + verdict writes | CL-D2-4 ↔ CL-D1-5 |
| Canned demo payloads from fixtures (I4) | Dev 2 | Dev 1 `demo_mode` → Dev 3 | CL-D2-6 |
| Real WS + report endpoints (I5) | Dev 1 | Dev 3 live console / exports | CL-D1-6 → CL-D3-4/6 |

## ✅ How to Use

1. **One checklist = one issue/PR bundle.** Copy the checklist into your tracker; check items off as you go.
2. **"Done means" = acceptance criteria.** A checklist is not done until its *Done means* line is verifiably true (test, demo, or measurement — not opinion).
3. **Dependencies are hard.** Don't start a checklist whose *Depends on* artifacts don't exist yet — build against the specified mock instead.
4. **Spec links are normative.** Where a task cites a doc section (e.g., *docs/03 §3.2*), that section is the requirement — deviations need a PR touching the doc.
5. **Update on change.** If scope shifts, edit the checklist in the same PR — these files are the team's source of truth for who-does-what-next.
