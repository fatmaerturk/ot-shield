# HMGCC Co-Creation Proposal
## Smart Personal Assistant for Security Researchers

*Submitted by OTShield  |  Research-First. Offline-Ready. Evidence-Driven.*

---

| | | | |
|---|---|---|---|
| **Organisation** | Safetech Global Limited (trading as OTShield) | **Reg. No.** | 15233187 |
| **Primary contact** | Fatma Erturk, Project Lead  |  fatma.erturk@otshield.io  |  07453 641903 | **Address** | 7 Bell Yard, London, WC2A 2JR |
| **Web / LinkedIn** | https://otshield.io/  |  @ot-shield  |  @the-ot-hacker-mindset | **Funding** | **£60,000** all-inclusive  |  12 weeks  |  TRL 6 |

---

## 1. Scope & alignment with the challenge

Security researchers spend more time **finding, indexing and interpreting** technical data than acting on it; interpretation of complex artefacts is the most time-intensive stage in HMGCC's recent projects. Across complex hardware / software systems, ICS, embedded firmware, additive manufacturing controllers, SCADA and any domain HMGCC's tear-down workflows touch (ICS is the worked example, not the limit), this bottleneck delays vulnerability discovery and increases mission risk, especially when the target is heterogeneous, fragmented and operated in air-gapped facilities.

**Our proposal:** extend the existing OTShield platform, an offline, evidence-driven, copilot-ready security platform with deep ICS pedigree, into a TRL 6 research-assistant capability applicable to any complex hardware / software tear-down, that meets every essential HMGCC requirement and addresses all four desirable requirements.

**Why us:** we are not building a better search tool. We are building a *cognitive layer for vulnerability research* that does what RAG cannot, bridging documentation with real network behaviour through OTShield's live PCAP analysis, decoys and asset inventory. The Research Mode that HMGCC's funding extends is operational at TRL 3 to 4 today; the supporting SOC-side decoy fabric, validated against real attackers on Safetech Global's internet-exposed deployment, sits at TRL 5 and feeds the research tool through signed update bundles. The 12-week project takes the Research Mode capability to TRL 6 with HMGCC-supplied test data, with the today-vs-Phase-1 delta laid out explicitly in Section 2.

**Dual-use by design, HMGCC will not be a sole customer.** OTShield is a commercial ICS security product targeting critical infrastructure operators, defence supply chain and ICS vendor red teams; we are pre-revenue with an active commercial pipeline and three published price tiers. Safetech Global, **incorporated October 2023**, and our product OTShield hold **12 industry awards to date** and have been confirmed by UK Enterprise Awards as **Most Innovative OT Security Company 2026** (under embargo, public announcement July 2026; see Annex C). The same platform is taken to multiple buyers, so HMGCC inherits a commercially supported tool, not a one-off bespoke build, and the Phase 1 royalty-free licence to HMGCC remains in place regardless of how the commercial pipeline converts.

### OTShield today: live capabilities (the dual-use evidence)

| Live capability | What it does today, and why it matters for the challenge |
|---|---|
| **Research Mode** | Bundle-based research workspaces (Library, Summary, Inventory, Ports & Services, Threads, Findings, Vulns) on a Java + Spring Boot backend with offline Ollama LLM (Llama 3.2 1B today) and an in-memory vector store. Foundation for the HMGCC challenge. |
| **SOC Mode + Decoy layer** | Realistic protocol-aware decoys for Modbus, S7Comm, EtherNet/IP, OPC UA, DNP3 and more, deployed today on an internet-exposed decoy fabric operated by Safetech Global and capturing real attacker behaviour against ICS protocols. |
| **PCAP, asset inventory + MITRE ATT&CK for ICS** | Purdue-aware packet processing with dedicated dissectors for SCADA communication protocols; auto-discovered PLCs / RTUs / HMIs with risk scoring; attacker TTPs mapped across the full ATT&CK for ICS kill chain (initial access through impact); IOC export in JSON / CSV / plain formats with SIEM / TAXII / MISP push interfaces (production-grade push hardened in Phase 2). Lets the assistant validate documentation against on-wire behaviour. |
| **Live ICS threat-intelligence platform** | Internet-exposed decoy fabric operated by Safetech Global, capturing real ICS attacks. In the first days of live operation alone we recorded **157 unique attackers from 20 countries executing 12,968 attacks**, ranging from script-kiddie scans to advanced actors targeting ICS-specific protocol weaknesses. This feed is packaged as signed update bundles for the air-gapped Phase 1 tool (Sec. 3 & 8). *Full breakdown in Annex B.* |
| **Commercial maturity & regulatory alignment** | Pre-revenue but commercially defined: three published price tiers (Starter / Growth / Advanced) with an active customer pipeline; aligned with **NIS2**, **IEC 62443** and the **UK NCSC Cyber Assessment Framework (CAF)**; coexists with Dragos / Claroty (does not replace them); deployable on Cisco hardware or as software. *Full partner-channel evidence in Annex E.* |

**Mapping to the three challenge objectives:** **(i) Index structured + unstructured technical data:** Bundles ingest PDFs and plain-text formats (markdown, text, CSV) today via Apache PDFBox + chunker + embeddings; multi-modal ingest (OCR, handwriting, schematic / image understanding) is added in Phase 1 Sprint 1. **(ii) Generate clear technical summaries:** a local LLM via Ollama (Llama 3.2 1B today, upgraded to Gemma 4 26B MoE / 31B Dense in Phase 1) produces per-bundle Summary, Inventory and Ports & Services views, all reproducible and offline. **(iii) Conversational, source-cited Q&A that adapts to the researcher:** Threads tab with persistent copilot conversations, inline citations and HIGH/MEDIUM/LOW confidence labels with a "needs more sources" flag (Phase 1 upgrades these to a calibrated 0 to 1 conformal score), promote-to-Findings workflow and adaptive user profile.

---

## 2. System approach & innovation

The tool is a locally-hosted web application running entirely on the researcher's laptop (browser UI served from localhost; backend, local LLM, embeddings and indices on the same machine; no internet calls). The backend is **Java 21 + Spring Boot** wrapping a five-stage pipeline: **(1) Ingest** → **(2) Index & extract** → **(3) Retrieve** → **(4) Reason & verify** → **(5) Answer & ledger**.

### Today's stack vs. Phase 1 upgrade (Research Mode: TRL 3 to 4 → TRL 6)

| Layer | Today (operational, in production code) | Phase 1 upgrade |
|---|---|---|
| **LLM serving (3-tier)** | Ollama at localhost:11434, **Llama 3.2 1B Instruct Q4_K_M** (2K context, top-K=4, min relevance 0.18) | **Tier 1 / Edge laptop (4 to 8 GB VRAM, primary deployment):** Gemma 4 9B Q4_K_M for 4 GB-class laptops, Gemma 4 13B Q4_K_M for 8 GB-class laptops; Llama 3.2 1B retained as CPU-only / ablation fallback. **Tier 2 / HMGCC OpenAI-style endpoint (optional scale-up):** any open-weights model of HMGCC's choice (e.g. Llama 3.3 70B, Qwen 2.5 72B, Gemma 4 27B). Used by the L2 verifier for higher-accuracy cross-checking and by an automatic escalation path when edge confidence falls below threshold. Air-gap preserved (HMGCC-hosted infrastructure). **Tier 3 / OTShield dev workstation (RTX 5090 32 GB, internal only):** Gemma 4 26B MoE / 31B Dense Q5_K_M for benchmark-driven model selection, conformal calibration and ablation studies; not part of the deliverable. |
| **Embeddings** | **nomic-embed-text** via Ollama (768-dim, English-centric) | **BGE-M3** added (BAAI, MIT, 100+ languages, 8K input, dense + sparse + multi-vector); nomic kept for English-only fast path |
| **Vector store** | **InMemoryVectorStore** (ConcurrentHashMap, brute-force cosine, < 500 chunks, < 1 ms search) | **ChromaDB** (Apache 2.0, embedded, persistent, hybrid sparse + dense); existing in-memory store kept as a fast in-process cache |
| **Retrieval** | Single-modal (vector cosine only) | **Hybrid retrieval**: dense (BGE-M3 + nomic) + sparse (BM25 over Chroma) + ICS-protocol-aware filters over structured Inventory/Ports/Services tables; cross-lingual expansion at query time |
| **Verifier (L2)** | None. Answers returned with retrieved-chunk citations only. | **New IP.** Independent agentic verifier on **LangGraph** (MIT). Three parallel checks per claim: (i) corpus re-query, (ii) trusted-source cross-check, (iii) on-wire cross-check against OTShield PCAP / decoy data (unique to us). Adversarial validation by Jon Medvenics with **PyRIT**. Per-claim decision log labels every output as **known**, **inferred** or **uncertain** for human-readable audit. |
| **Confidence (L3)** | HIGH / MEDIUM / LOW label + binary 'needs more sources' flag emitted by the assistant on every answer; cosine relevance per retrieved chunk (not user-facing as a calibrated 0 to 1 confidence yet) | **New IP.** Calibrated 0 to 1 per claim using **conformal prediction** (primary) + Platt scaling / isotonic regression (baselines). 'Needs more sources' flag below threshold (default 0.6, HMGCC-tuneable). |
| **Multi-modal ingest (L1)** | PDF text + plain-text fallback (markdown, text, CSV). | Full HMGCC format coverage: Word (.docx), Excel (.xlsx), PowerPoint (.pptx) via Apache POI; JPEG / PNG / BMP / TIFF, schematics, draw.io outputs (.drawio XML), hand-drawn and scanned material via Tesseract 5 + PaddleOCR + **TrOCR** (handwriting) + **LayoutLMv3** + Gemma 4 vision; Markdown / Obsidian and OneNote (.one) note-taking imports; structured database exports (CSV / SQL dumps / XML); protocol-aware extractors for Modbus, S7Comm, EtherNet/IP, OPC UA, DNP3, IEC 60870-5-104. |
| **Multilingual** | Offline output translation in production for **EN, TR, DE, FR, ES** via the local Ollama chat model with a domain-tuned translation prompt that preserves citations, CVE ids, port numbers, IPs and ICS acronyms; LRU-cached per session. | **NLLB-200 distilled-600M** upgrades the chat-model translator and prioritises HMGCC's stated languages (**DE, JA, FR, ZH**); bilingual technical-term dictionary curated with HMGCC; **cross-lingual retrieval** (EN query, non-EN source) over BGE-M3. |
| **Adaptive profile (L4)** | Threads + Findings persistence. | **New IP.** Cross-bundle long-term memory schema; learns researcher terminology and preferred output format; proactive surfacing of related findings. |

**Innovation, beyond off-the-shelf RAG.** Some applicants will ship a conventional document-Q&A system. We address all four limitations HMGCC raised in Q34 / Q35: (i) **structured representation alongside Q&A**, the LLM extractor produces a **component knowledge graph** (SBOM-style hierarchies, firmware memory maps, communication-interface graphs, attack-surface relationships) in parallel with the vector embeddings, so the assistant supports both "show me what you found" (graph view) and "what does this device do" (Q&A view); (ii) **on-wire cross-check**, verifier validates documented protocol behaviour against real PCAP traffic and decoy interactions from OTShield's platform (no other applicant has this); (iii) **multilingual + cultural-bias awareness** with four-layer bias mitigation, ingestion-time tagging and cross-lingual retrieval (see desirable c); (iv) **robust offline updates**, twofold signed-bundle pipeline with cryptographic integrity verification (see desirable d). Calibrated confidence using **conformal prediction** sits across all four.

**IP position.** *Existing (no charge to HMGCC):* Java + Spring Boot Research / SOC platform, Ollama integration, in-memory vector store, deep-extract pipeline, protocol-aware extractors, PCAP / decoy / asset platform, live threat-intel feed. *New IP generated in Phase 1:* agentic verifier with on-wire cross-check, calibrated ICS confidence model, multilingual / cross-lingual layer, long-term memory schema, hybrid retrieval over ChromaDB. All new IP owned by OTShield; Authority granted a non-exclusive royalty-free licence per HMGCC Co-Creation Terms and Conditions (T&Cs). *Full module-by-module specs in Annex A.*

---

## 3. Deliverables

The 12-week MVP is a locally-hosted web application that runs entirely on the researcher's laptop with no internet dependency: the backend, local LLM, embeddings, indices and UI all run on the same machine and the researcher accesses the tool through their browser at localhost. The deliverable is shipped with documentation, a reproducible test corpus and a verification report.

| HMGCC essential requirement (8/8) | OTShield delivery in Phase 1 | Status |
|---|---|---|
| Understand system architecture (interfaces, data, protocols) | Inventory + Ports & Services + Network Topology; LLM-driven inventory deep-extractor today, plus dedicated dissectors for SCADA communication protocols. Phase 1 extends with additional protocol-specific document extractors. **Architectural-insight extraction**: high-level component design including firmware modules (bootloader, kernel, drivers, OTA updater), communication interfaces (UART, I2C, SPI, ethernet, Wi-Fi), trusted / untrusted execution domains, external dependencies (libs, 3rd-party SDKs) and attack-surface enumeration (ports, exposed APIs, file-system mounts) generated by the LLM extractor against ingested datasheets and schematics, persisted as a **queryable component knowledge graph** for both Q&A and graph-view access. | **Met** |
| Validate responses, prevent hallucinations | L2 verifier agent with **user-selectable mode**: (a) **automated self-check** with mandatory pre-publication validation gate, or (b) **source-listing mode** where the assistant lists cited sources for human review without auto-blocking. On-wire cross-check + decision log apply in both modes. **Failure-mode mitigations**: the assistant explicitly recognises "No information" / "Not enough information" rather than fabricating an answer; prompts the user to continue, expand sources or refine the query before producing a low-confidence response; and supports **interrupting an in-flight reasoning step** when the user sees the tool going the wrong way or the prompt was lacking. | **Met** |
| Characterise multimedia inputs (manuals, schematics, datasheets, images, code, handwriting) | Today: PDF, markdown, text, CSV. Phase 1 Sprint 1 covers the full HMGCC test-data list: Word (.docx), Excel (.xlsx), PowerPoint (.pptx), JPEG / PNG / BMP / TIFF, schematics, draw.io (.drawio XML), hand-drawn and scanned material via Apache POI + Tesseract 5 + PaddleOCR + TrOCR + LayoutLMv3 + Gemma 4 vision. **Baseline:** high-confidence text and label extraction. **Bonus:** spatial awareness on schematic diagrams (component connectivity, handwritten annotation linked to its target element); reported with explicit confidence levels rather than asserted as full visual grounding. | **Met** |
| Verify by listing sources, cross-check against high-confidence data | Citations on every answer; trusted-source registry; evidence ledger with audit trail; per-claim decision log labels each output as **known**, **inferred** or **uncertain** for human-readable audit. | **Met** |
| Confidence score + flag when more sources needed | Today: HIGH / MEDIUM / LOW confidence label and a binary 'needs more sources' flag emitted on every answer. Phase 1 upgrades to a calibrated 0 to 1 score per claim using conformal prediction. **When the system cannot confidently resolve a query, three behaviours combine**: (a) **explicitly defer** ("not enough information to answer with confidence"); (b) **suggest further avenues of investigation** (Cultural-Gap checklist, e.g. "add Dutch advisories"); (c) **highlight gaps in available data** (coverage label, e.g. "Coverage: English 90% / Dutch 0%"). | **Met** |
| Operate on a laptop with no internet | Fully air-gapped; local Ollama LLM, local embeddings, local watch-folder ingest. 100 % offline by design. | **Met** |
| Easy, intelligent chat-style query | Threads tab: copilot with citations, follow-up, and **multiple plausible hypotheses with supporting evidence** when ambiguity or contradiction is detected, rather than a single 'collapsed' answer. Default: surface the top hypothesis with cited evidence; if confidence is split or contradictory sources exist, present alternatives side-by-side with their respective evidence. | **Met** |
| Persistent memory across weeks of conversation | Bundles + Threads + Findings persist locally; long-term memory schema added in Sprint 2. | **Met** |

**Desirable requirements (4/4 addressed):** **(a) Adaptive user profile** delivered in Phase 1 (L4, Sprint 2). **(b) Translate / index non-English data**: offline output translation across **5 languages** (EN, TR, DE, FR, ES) is already in production via the local Ollama chat model with a domain-tuned translation prompt. Phase 1 extends this: Sprint 1 language detection + dedicated NLLB-200 NMT model packaged for air-gapped install, prioritising **German, Japanese, French and Chinese** per HMGCC guidance; Sprint 2 bilingual technical-term dictionary curated with HMGCC + cross-lingual retrieval (EN query, non-EN source); Sprint 3 hardening + extension path. **(c) Cultural-bias mitigation (four-layer + policy modes):** (1) ingestion-time lang/origin tagging with modal-banner alert; (2) corpus-level audit with follow-up checklist; (3) retrieval-time coverage label (e.g. 'English 90% / Dutch 0%') + Cultural-Gap tab; (4) proactive UI prompt invoking the offline MT engine (already in production for EN/TR/DE/FR/ES, NLLB-200 in Phase 1) to surface alternative-cultural sources inline. User-selectable **PROACTIVE / SUGGESTIVE / OFF** policy. Aligned with NCSC RTAU bias-mitigation guidance. Full UI/UX flow in Annex A.12. **(d) Offline update mechanism (twofold):** (i) **software / algorithm updates** (runtime, UI, model weights, model loading logics) and (ii) **data repository updates** (corpus, CVE feeds, vendor bulletins, threat-intel signatures from OTShield's live decoy fabric, see Sec. 1) both delivered as **signed tar.zst bundles** with **cosign** (sigstore) signatures, transferred via removable media or watch-folder; integrity and authenticity verified before install; the laptop never connects to the internet but stays current.

**Out of Phase 1 scope:** binary firmware reverse engineering and source-code static analysis, per HMGCC Q14 / Q21. The assistant works from *documentation about* hardware / software systems (datasheets, schematics, manuals, vendor bulletins), not from compiled binaries or source. Hardware-in-the-loop firmware extraction (JTAG / SWD) is a Phase 2 candidate (see Sec. 8).

### Concrete week-12 deliverables & success metrics

- Locally-hosted web app packaged for offline install on **Windows 11 and Ubuntu (latest)** laptops; signed binaries; browser UI from localhost; zero internet calls. **Two delivery modes**: (a) **physical laptop pre-installed** by Safetech Global at handover, or (b) **vSphere-compatible image** uploaded to HMGCC's existing vSphere infrastructure for both initial install and subsequent signed update bundles. Modular components are integratable into HMGCC's existing air-gapped agent platforms.
- Reference test corpus (HMGCC-supplied) + reproducible benchmark report against these **quantitative success criteria** (full methodology in Annex A.8):
  - **Hallucination rate ≤ 5 %** (verifier-flagged / contradicted claims, 200-claim adjudicated sample); **Confidence calibration ECE ≤ 0.10** (10-bin, conformal); **Retrieval precision@5 ≥ 0.80** on ICS-protocol queries.
  - Stretch (tracked through Phase 2): **Cross-lingual recall@10 ≥ 0.65** (HMGCC priority languages); **latency ≤ 30 s** Tier 1 edge laptop (4 to 8 GB VRAM) / **≤ 8 s** Tier 2 HMGCC endpoint (verifier escalation); **OCR + handwriting accuracy ≥ 0.92**; **"needs more sources" precision ≥ 0.85**.
  - **Researcher saved-time assessment (qualitative)**: at the three sprint-review demos (Wk 4, 8, 12), HMGCC security researchers compare time-to-first-finding using the assistant against their current tooling on a representative tear-down task; net positive saved-time on at least 2 of 3 sessions is a Phase 1 outcome target.
  - **The first three quantitative criteria are the minimum acceptance criteria for week-12 sign-off; the rest are stretch goals. The qualitative saved-time assessment aligns with HMGCC's stated evaluation method.**
- Technical documentation (requirement-discovery log, architectural design decisions, threat model, data-handling plan, test methodology and results, operator guide, IP register, signed CycloneDX SBOM with pinned versions); code handover (Git repository archive, README, build instructions, dependency manifest, sample queries) to a standard suitable for review and ongoing maintenance by HMGCC engineers; TRL 6 evidence pack (benchmark harness, raw measurements, calibration plots, adjudication log, signed-off methodology); Phase 2 roadmap with costings (Sec. 8).
- Phase 2 roadmap with rough costings (see Sec. 8).

---

## 4. Co-creation model: how we will work with HMGCC

Co-creation is central to this challenge and to how we will deliver. We treat HMGCC not as a customer receiving test data, but as an embedded partner shaping the product across all 12 weeks. The engagement model below is open to refinement during the kick-off call.

| Engagement | Cadence | Purpose & co-created output |
|---|---|---|
| **Kick-off on-site at HMGCC Milton Keynes** | Wk 1, 1 to 2 days | Architecture & threat-model walkthrough; align on trusted-source taxonomy, confidence thresholds, acceptance criteria. Output: signed-off Phase 1 plan. |
| **Weekly delivery sync** | 30 min, weekly | HMGCC delivery manager + OTShield tech lead. Risks, blockers, scope trade-offs decided jointly. |
| **Sprint Planning + Sprint Review ceremonies + bi-weekly iteration demos** | Start of each sprint (Wk 1, 5, 9) for Planning + end of each sprint (Wk 4, 8, 12) for Review, plus optional iteration demos at Wk 2, 6, 10. HMGCC SME input minimum at Planning and Review, ad hoc during sprints where practicable. | HMGCC security researchers run the latest build against real tear-down tasks at every sprint review; findings feed the next sprint backlog, so UX, prompts and calibration are shaped by real users. |
| **Mid-project on-site review at HMGCC Milton Keynes** | Wk 6, 1 day | Deep-dive on verifier output, bias flags, multilingual coverage; re-prioritise Sprint 2 / Sprint 3 backlog if needed. |
| **Joint risk & scope board** | Continuous | Shared register; any scope trade-off (e.g. multilingual depth vs. hardening) is a joint decision, no unilateral cuts. |
| **Joint go/no-go gates** | End of Sprint 1 (Wk 4) and Sprint 2 (Wk 8) | Formal review against the Section 3 acceptance criteria. If a minimum metric is missed by > 20 %, scope is renegotiated jointly through the risk & scope board, not silently descoped. Stretch metrics tracked but not gate-blocking. |

**Where we would value HMGCC's input:** (1) researcher workflow & pain points beyond the Alicia use case (current tooling, what fails, what is irreplaceable); (2) the trusted-source register that should rank highest in the confidence model; (3) security & data-handling constraints (OFFICIAL handling, BPSS, audit/log requirements); (4) priority ICS product families & languages for early validation.

---

## 5. Timescale: 12-week agile sprint plan (3 x 4-week sprints)

Following HMGCC's stated standard cadence ("majority of our 12-week projects are typically 3 x 4-week sprints"), the project runs as three 4-week sprints with formal sprint review demos at end of weeks 4, 8 and 12, plus optional bi-weekly iteration demos at weeks 2, 6 and 10 to keep the user-test feedback loop tight.

| Sprint & weeks | Outcomes | Demo / co-creation moment |
|---|---|---|
| **Sprint 1: Foundation + Multi-modal & multilingual ingest** (Wk 1 to 4, bi-weekly iteration demo at Wk 2) | Kick-off on-site at HMGCC Milton Keynes; baseline workbench installed in target environment; threat model + architecture sign-off; benchmark harness defined; OCR + handwriting + schematic extraction; full HMGCC format coverage (Word / Excel / PowerPoint / draw.io); offline language detection + translation models packaged for HMGCC priority languages (DE, JA, FR, ZH). | On-site kick-off (signed Phase 1 plan); **Sprint 1 review demo** at end of Wk 4 with **HMGCC researcher pool**: schematic + non-EN datasheet, Inventory populated. |
| **Sprint 2: Verifier + Adaptive UX & cross-lingual retrieval** (Wk 5 to 8, bi-weekly iteration demo at Wk 6) | Agentic verification + contradiction detection + on-wire cross-check; calibrated confidence; bilingual ICS-term dictionary curated with HMGCC; long-term memory schema; researcher-profile + proactive surfacing; cross-lingual retrieval (EN query, non-EN source); persistent multi-week threads validated. | **Mid-project on-site review at HMGCC Milton Keynes (Wk 6)**; hallucination demo; **Sprint 2 review demo** at end of Wk 8: 3-week 'Alicia' walkthrough with HMGCC researcher pool. |
| **Sprint 3: Hardening, bias layer + Handover** (Wk 9 to 12, bi-weekly iteration demo at Wk 10) | Bias-flag layer; independent security review; Tier 1 edge-laptop performance tuning; TRL 6 in-environment test plan executed; final benchmarks; documentation, operator guide, IP register, signed CycloneDX SBOM, code handover; Phase 2 roadmap with costings. | TRL 6 test report + signed binaries (Wk 10); **Final on-site demonstration session at HMGCC Milton Keynes (Wk 12)**; code & documentation handover to HMGCC engineering team. |

---

## 6. Budget: £60,000 (all-inclusive ceiling), justified

The £60,000 figure is the all-in ceiling and includes all time, materials, hardware, software licensing, overheads and indirect expenses; all proposed costs are within the maximum £60,000 budget. **Safetech Global Limited is not currently UK VAT registered, so no VAT applies to this contract.** All software components in the Phase 1 stack are open-source (Apache 2.0 / MIT); no commercial software licence fees are incurred. Daily rates are blended UK-market rates for security R&D specialists.

| Cost line | Day rate (£) | Days | Subtotal (£) | Sprints | % Total |
|---|---:|---:|---:|---|---:|
| **Technical Lead / Architect & Project Delivery (Fatma, founder rate, full-time)** | 240 | 60 | **14,400** | S1 to S3 | 24.0 % |
| Senior Cybersecurity & AI Verification Engineer (Jon, 0.5 FTE across all 12 weeks, verifier focus in Sprint 2) | 600 | 30 | **18,000** | S1 to S3 | 30.0 % |
| Cybersecurity Advisor (Alan, 1 day / week) | 800 | 12 | **9,600** | S1 to S3 | 16.0 % |
| **Labour subtotal** | | **102** | **42,000** | | **70.0 %** |
| OTShield dev / eval workstation (1x RTX 5090 32 GB GDDR7) for Tier 3 internal benchmarking, model selection & calibration; not part of HMGCC deliverable | n/a | n/a | **5,500** | S1 to S3 | 9.2 % |
| Air-gapped test laptop (Windows 11 + Ubuntu latest dual-boot) | n/a | n/a | **2,000** | S1 to S3 | 3.3 % |
| Local LLM tooling, Gemma 4 deployment, signed-installer toolchain | n/a | n/a | **900** | S1 to S3 | 1.5 % |
| Independent security review (external) | n/a | n/a | **2,500** | S3 | 4.2 % |
| Project management & overheads (delivery role combined with Tech Lead) | n/a | n/a | **800** | S1 to S3 | 1.3 % |
| Travel & on-site engagement at HMGCC Milton Keynes (kick-off + mid-project + final demo / handover) | n/a | n/a | **1,300** | S1 to S3 | 2.2 % |
| Reproducible test corpus + benchmark infrastructure (TRL 6 evidence pack) | n/a | n/a | **5,000** | S1 to S3 | 8.3 % |
| **TOTAL (all-inclusive)** | | | **£60,000** | | **100 %** |

### Value-for-money rationale

- **Founder full-time at a deep discount.** Fatma, as Founder & CEO, commits full-time to the project for all 12 weeks (60 person-days) at a heavily reduced founder rate of £240/day, against her standard commercial rate of £750+. This is a real cash discount of approximately £30,000 to the project, and a genuine commitment of founder time to HMGCC's delivery rather than to other commercial activity.
- **Pre-existing IP at no charge.** Safetech Global brings substantial pre-existing OTShield IP into the project at no charge (Workbench, deep-extract pipeline, offline LLM stack, PCAP / decoy / asset platform, live threat-intel feed). HMGCC pays only for the new capability built on top.
- **Senior commercial rate for the high-risk workstream.** Jon Medvenics (ChCSP, ex-MoD / NHS Digital / Parliamentary Digital Service) is engaged at his commercial rate, ensuring the verifier-agent and AI red-team workstream is led by a chartered specialist rather than a junior.
- **Independent senior assurance.** Alan Jenkins (CISM, PRINCE2, CISMP, ex-RAF Squadron Leader, former Babcock CISO) provides 1 day per week of independent assurance over architecture, threat model, data-handling and HMGCC engagement, at standard senior advisory rate.
- **Right-sized hardware + realistic 70 / 30 labour-non-labour split.** The RTX 5090 funds Tier 3 internal benchmarking and calibration only (not the deliverable). The Phase 1 deployment target is a 4 to 8 GB VRAM laptop (Tier 1) plus optional escalation to HMGCC's hosted OpenAI-style endpoint (Tier 2); no cloud dependency, no closed-source model lock-in. Non-labour also funds external security review, on-site engagement and TRL 6 evidence pack.
- **Independent external security review at £2,500** ensures HMGCC receives a third-party-validated build, not a self-certified one.
- **On-site engagement budgeted, not assumed.** Travel and on-site costs for the Section 4 co-creation moments (kick-off + mid-project review at HMGCC) are explicitly funded.
- **TRL 6 evidence pack funded.** £5,000 is allocated to building a reproducible test corpus and benchmark infrastructure, not just running tests on it. This is what makes the deliverable defensible at TRL 6.
- **Labour is 70 % of the budget**, with the remainder targeted at hardware, tooling, external assurance and on-site engagement, a more realistic split for a TRL 6 project than a labour-only line item.

---

## 7. Team

OTShield is a research-first ICS security company. The proposed delivery team combines deep ICS / OT security expertise with senior ML / AI verification and chartered cyber-security advisory. ICS / OT subject-matter authority for the Alicia use case is shared across the named team, not delegated to a separate role: **Fatma** brings 8+ years hands-on OT / ICS protocol expertise plus NATO Locked Shields 2019 SCADA Blue Team experience; **Jon** brings prior engineering audits for SCADA systems and deep classified-network exposure; **Alan** brings former Babcock CISO and UK Defence Intelligence School pedigree. *Full CVs and the organisational profile are in Annex C, outside the 6-page limit.*

| Role | Person | Relevant expertise |
|---|---|---|
| **Technical Lead / Architect & Project Delivery** | Fatma Erturk (Project Lead; Founder & CEO, OTShield) | Founder & lead architect of OTShield, also accountable for Phase 1 delivery and HMGCC interface. 14+ years software engineering across SCADA, smart-city security and large-scale Java microservices; **Vodafone Scrum Master Award (2023 to 2024)**; 8+ years hands-on OT/ICS protocol expertise (Modbus, IEC 104, DNP3, S7); SCADA Blue Team member at **NATO Locked Shields 2019**; Best SCADA/ICS/OT Security Training Provider 2024; Winmark Deep Tech Award finalist 2025; Turkish Presidency of Defence Industries Woman Entrepreneur Award. |
| **Senior Cybersecurity & AI Verification Engineer** | Jon Medvenics (ChCSP, OSCP, GXPN, GREM) | Founder of Heretek Ltd; UK Chartered Cyber Security Professional. Government delivery: **Ministry of Defence** (classified-network SOC + protective monitoring), **Ministry of Justice** (Red Team Operator), **NHS Digital** (Principal Security Analyst, COVID-19 incident response), **Parliamentary Digital Service** (Security Operations Manager). Specialist in **AI / LLM red-teaming and verification**, including bespoke uses of Microsoft's PyRIT and weaponising agentic AI chatbots. Conference speaker (B-sides, DEF CON 4420, BEAcon, CRESTcon). |
| **Cybersecurity Advisor** | Alan Jenkins (CISM, PRINCE2, CISMP) | 35+ years across cyber and enterprise security, including 20+ years as a senior RAF Police officer (Squadron Leader) and a graduate of the UK Defence Intelligence & Security School and Carnegie-Mellon SEI's Computer Emergency Response programme. Former CISO at Babcock International (UK defence prime), T-Systems UK and CSC UK, and former IBM Security Associate Partner. Long-standing CISO-in-Residence at CyLon and current Advisor & Mentor at Safetech Global. On this project: independent assurance over architecture, threat model, data-handling and HMGCC engagement. |

---

## 8. Exploitation, Phase 2 & risk

### Dual-use exploitation: HMGCC is one customer in a wider market

OTShield is a commercial dual-use product. We are pre-revenue but commercially defined: an active pipeline against three published price tiers, an internet-exposed decoy fabric validating the platform against real attackers today, and a roadmap aligned to multiple customer segments. The capability HMGCC funds in Phase 1 is directly reusable across the segments below, so HMGCC inherits a tool whose maintenance and improvement is driven by Safetech Global's wider commercial activity, not a bespoke build that bit-rots after the project.

- **UK national security & defence (beyond HMGCC):** other government departments running ICS tear-downs and supply-chain assurance, including MOD, NCSC, NPSA and defence primes' security functions.
- **Critical infrastructure operators (largest commercial segment):** energy, water, transport, pharma. Active commercial pipeline against three published price tiers: Starter (£20k/yr, up to 50 assets), Growth (£50k/yr, up to 500 assets) and Advanced (£75k/yr, unlimited, full-scale CNI). NIS2-, IEC 62443- and NCSC CAF-aligned; coexists with Dragos / Claroty rather than replacing them. *Full partner-channel evidence in Annex E.*
- **ICS vendor red teams & product security:** Siemens, Rockwell, Schneider-class vendors run internal tear-down programmes today on ad-hoc tooling; OTShield is a structured replacement.
- **International allies:** Five Eyes & NATO partner governments doing equivalent ICS assurance work. Safetech Global has already been selected for the **Portuguese Air Force InnCyber programme** and is actively participating in Germany's **Hubgrade Cyber programme**, in addition to UK accelerators (CyLon, Digital Catapult Cyber 101, Cyber Runway).
- **Phase 2 vision, subject entirely to HMGCC's discretion based on Phase 1 outcomes (no commitment for Phase 2):** if HMGCC chooses to proceed, an indicative scope of approx. £250 to £400 k over 6 to 9 months would deliver (i) **signed offline-update pipeline**: production-grade rollout of the air-gap-safe bundle mechanism designed in Phase 1, fed by OTShield's internet-exposed decoy fabric threat-intel feed; (ii) **multi-researcher collaborative workspaces**: shared Findings ledger across HMGCC team members with role-based access and reviewer hand-off; (iii) **hardware-in-the-loop firmware extraction**: bench-side integration with chip programmers and JTAG / SWD probes for tear-down workflows; (iv) **HMGCC tooling pipeline integration**: REST / gRPC API + SIEM-style export for existing HMGCC analyst infrastructure. **The Phase 1 deliverable is fully self-sufficient under the royalty-free licence; Phase 2 is not a precondition for HMGCC to retain and use the Phase 1 output.**

### Risk register (top 6)

| Risk | Lhood | Impact | Mitigation |
|---|:-:|:-:|---|
| Tier 3 dev-workstation procurement slip (RTX 5090) | Low | Low | RTX 5090 funds internal benchmarking and Tier 3 calibration *only*; the HMGCC deliverable is the Tier 1 edge laptop binary plus the optional Tier 2 HMGCC-endpoint integration, neither of which depend on the dev workstation. Used RTX 5090 / RTX 4090 24 GB are equivalent fallbacks; cloud-GPU dev environment available as a temporary backstop. Project schedule is unaffected by procurement variance. |
| Local LLM accuracy on technical ICS jargon insufficient | Med | High | Domain-tuned prompts + verifier agent + protocol-aware extractors already operational; benchmark-driven model selection in Sprint 1; AI red-team validation by Jon Medvenics using PyRIT-class methodology. |
| Hallucination / over-confident answers | Med | High | Mandatory verifier pass + on-wire cross-check + calibrated confidence + 'needs more sources' flag; pre-publication gate. |
| Tier 1 edge-laptop performance (4 to 8 GB VRAM) | Med | Med | Tier 1 primary models (Gemma 4 9B Q4_K_M for 4 GB, 13B Q4_K_M for 8 GB) sized explicitly for HMGCC's 4 to 8 GB VRAM envisaged laptop. Llama 3.2 1B retained as CPU-only fallback for VRAM-constrained or CPU-only edge cases. Tier 2 HMGCC endpoint absorbs higher-accuracy verifier passes when edge confidence falls below threshold. Latency target ≤ 30 s Tier 1 / ≤ 8 s Tier 2 (see Annex A.8). |
| HMGCC test data delivery slip | Low | Med | HMGCC will deliver representative test documents incrementally during the first 4 weeks. OTShield's internal ICS test corpus is used as fallback in Sprint 1 to keep schedule on track until HMGCC data arrives. |
| Phase 2 funding not secured before Phase 1 ends | Med | Low | Safetech Global's commercial roadmap and active customer pipeline sustain the codebase even if Phase 2 grant slips; Phase 2 features are then prioritised by the order in which the pipeline converts. The Phase 1 deliverable remains usable to HMGCC under the royalty-free licence whether or not Phase 2 proceeds. |

### Live demo (recorded walkthrough)

A recorded end-to-end walkthrough of the OTShield platform is available on YouTube and shows everything the main proposal claims as *operational today*: SOC Mode and the live decoy fabric attacker map with the 157-attacker / 20-country / 12,968-attack figures, and Research Mode (Bundles, Library, Summary, Inventory, Threads with citations and HIGH / MEDIUM / LOW confidence labels). Reviewer can verify every "today" claim in this proposal against the demo before reading the annexes.

**Demo video:** [https://www.youtube.com/watch?v=Jseq8cPICdc](https://www.youtube.com/watch?v=Jseq8cPICdc)

> *We are not building a better search tool. We are delivering a TRL 6 cognitive layer for ICS vulnerability research: purpose-built, offline-native, evidence-driven. The platform exists today; the £60k unlocks the verification, adaptive and multi-modal capabilities that turn it into the personal assistant Alicia needs. Funded once, it will serve the UK national-security community for years.*

---

*All assessable information is contained within these six pages. The annexes uploaded separately are **supporting evidence** only: **Annex C** Team CVs & Organisational Profile (HMGCC-permitted exclusion). Optional reference material: **Annex A** architecture detail, **Annex B** live threat-intel evidence, **Annex D** UI screenshots, **Annex E** commercial collateral.*

*OFFICIAL. Submitted in confidence under HMGCC Co-Creation T&Cs*
