# The Cybersecurity Architect's Handbook — Second Edition

> **An Architect's Guide to Designing, Building, and Defending the Modern Enterprise**
> by **Lester Nichols** · Foreword by **Corey Ball** (author of *Hacking APIs*) · Published by **Packt** (April 30, 2026)

This is the official code and supplemental-download repository for the **Second Edition** of *The Cybersecurity Architect's Handbook*. It hosts the companion materials referenced throughout the book — most notably the **Chapter 9 supplemental download**, which contains the full set of hands-on labs, exercises, and product showcases that could not fit within the printed page count.

[![Book](https://img.shields.io/badge/book-2nd%20Edition-blue)](https://www.amazon.com/Cybersecurity-Architects-Handbook-architects-enterprise/dp/180610539X/)
[![Publisher](https://img.shields.io/badge/publisher-Packt-orange)]()
[![Chapters](https://img.shields.io/badge/chapters-20-brightgreen)]()
[![Supplement](https://img.shields.io/badge/Chapter%209-supplemental%20download-red)]()

---

## About the Book

The role of the cybersecurity architect demands more than technical expertise — it requires the strategic mindset of a tactician defending an organization in the ever-present war in cyberspace. The Second Edition builds on the foundational, career-development, and best-practices coverage that made the first edition an essential resource, while significantly expanding its scope with an entirely new section of applied, industry-specific architecture chapters.

The first edition ran 14 chapters; the Second Edition expands that to **20 chapters**, nearly doubling the original material, plus this supplemental download packed with labs, exercises, and tooling references. Woven through every chapter is a strategic thread inspired by Sun Tzu's *The Art of War* — a deliberate reminder that architects are not merely technicians but strategists operating on a digital battlefield, where the principles of preparation, adaptation, deception, and terrain awareness that have guided conflict for millennia now govern the defense of modern digital infrastructure.

### What the Second Edition Covers

The book guides readers through the foundational concepts of cybersecurity — the CIA triad, access controls, cryptography, and BCP/DR planning — and into architecture principles, design methodologies, and analysis techniques applied across the architecture lifecycle, blueprinting, and scoping. It maps the certification landscape and career pathways from entry level to architect, then expands into the topics readers of the first edition most asked for:

- **Zero Trust Architecture implementation** — identity-centric controls, micro-segmentation, continuous verification, and realistic migration strategies for existing environments.
- **AI security architecture** — model integrity, agentic-AI attack surfaces, guardrail frameworks, and a layered reference architecture for AI systems.
- **Industry-specific architectures** — financial services (PCI-DSS, GLBA, SOX), healthcare (HIPAA/HITECH), cloud-native environments (Kubernetes, serverless, DevSecOps), and critical infrastructure (ICS/SCADA, IT/OT convergence).
- **Tool rationalization** — choosing and justifying commercial and open-source tooling by decluttering the toolset and aligning selection with business considerations.
- **Strategic thinking frameworks** — applying Sun Tzu's principles to position yourself as a tactician and strategic leader, not just a technical practitioner.

### Who This Book Is For

The material is built to meet readers where they are: aspiring architects transitioning from engineering, development, or IT operations; practicing security professionals moving from tactical execution to strategic architectural thinking; current architects expanding into AI security, cloud-native, critical infrastructure, or Zero Trust; and technology leaders who need to understand how security architecture integrates with business strategy, governance, and risk. The core philosophy is unchanged from the first edition: it prioritizes teaching you *how to think* over telling you *what to do*.

---

## The Chapter 9 Supplemental Download

Chapter 9 of the book introduces a completely updated and comprehensive set of hands-on labs and exercises designed to let architects command each tool in their arsenal. In practice that material grew far beyond what the printed book could hold — well over two hundred pages of step-by-step procedures, screenshots, product showcases, and tooling references. Rather than overwhelm the primary text, this content lives here as a dedicated **supplemental download** so it remains fully available to readers.

The supplement is a single document organized internally into **categories** that mirror the major defensive-security domains. Each category pairs a domain narrative and other material that could not fit within the book — the history of the tool class, the commercial and enterprise landscape, comparison tables, and the rationale behind the open-source choices — with one or more complete, validated, build-it-yourself labs. The labs are designed to be stood up from scratch on a single host (current builds target **Debian 13**) using **free and open-source tooling**, so the entire supplement can be completed at no software cost.

### Lab & Exercise Topics

All of the labs and exercises for each Chapter are located within their respective directories. Chapter 9 is organized **as topics within the single supplemental download document** — there are no separate per-category folders in this repository. Within the document they are grouped into the following categories, each pairing a domain narrative with one or more complete, build-it-yourself labs:

1. **Threat Modeling and Risk** — Microsoft Threat Modeling Tool, OWASP Threat Dragon, and translating architecture and data flows into a prioritized risk picture (e.g., via STRIDE).
2. **Network Security Controls** — intrusion detection and prevention with Snort, and firewall/segmentation control with OPNsense.
3. **Security Monitoring and Analytics** — SIEM and log analytics with Graylog and Wazuh, plus antivirus and endpoint detection with ClamAV.
4. **Access Control and Data Protection** — identity and access management with Keycloak, and data encryption with VeraCrypt.
5. **Vulnerability and Configuration Management** — vulnerability scanning with OpenVAS/Greenbone, configuration management with Ansible, and patch management.
6. **Incident Response and Investigation** — digital forensics with The Sleuth Kit and Autopsy, and network security monitoring / IR with Security Onion.
7. **Application Security Testing** — static analysis with SonarQube and dynamic analysis with OWASP ZAP.
8. **Enterprise and Cloud Security** — securing an AWS environment, implementing a GRC tool, and penetration testing with Kali Linux and Metasploit.
9. **Security Automation with AI Agents** — *new in the Second Edition.* Building read-only AI agents that triage SIEM alerts and vulnerability findings, then orchestrating them into an unattended daily security brief — the modern successor to the rule-engine automation (StackStorm) approach from the first edition.

### Category 9 — Security Automation with AI Agents (New)

Category 9 is the newest addition and ties the rest of the supplement together. Where earlier categories build the individual detection and assessment capabilities, Category 9 addresses what to do with their *output* — the high-volume, high-tedium, high-judgment work of triaging alerts and findings — using LLM-backed agents rather than brittle rule chains.

It opens with the case for AI-assisted triage and leads with cost and safety guardrails, defining an "agent" concretely as a read-only program that follows a **fetch → reason → report** loop and never takes destructive action on its own. From there it provides technology overviews and a lab topology in which the only outbound traffic is TLS to the model API, followed by three progressive, hands-on labs:

- **Log-triage agent** — pulls recent alerts from Wazuh or Graylog, scrubs secrets, requests a strict-JSON verdict per alert, ranks them, and renders a Markdown brief.
- **Vulnerability-report agent** — pulls the latest OpenVAS/Greenbone report over GMP, filters by quality of detection, and produces a context-aware, per-host remediation plan.
- **Orchestrator** — joins both signals by host, writes a daily brief, and runs unattended on a schedule (e.g., a systemd timer).

Each lab includes objectives, prerequisites, complete working code, validation checklists, and troubleshooting guidance, and closes with extension paths such as tool-use, ticketing integration, and air-gapped local-model options. This category builds directly on the Category 3 (SIEM) and Category 5 (vulnerability management) labs.

---

## Repository Structure

This repository follows Packt's standard companion-repo layout. Per-chapter code and assets live in chapter folders (Packt's convention is one folder per chapter, e.g., `Chapter_02`).

```
.
├── README.md
├── Chapter_XX/                              # Per-chapter code snippets and assets referenced in the book

```

## How to Use This Repository

1. **Get the book.** The labs and showcases here are companion material; the chapters supply the architectural frameworks and decision criteria that make them meaningful. They are best used together.
2. **Download the Chapter 9 supplement.** The complete narrative-plus-labs treatment lives in the single supplemental download document; each category is a section within it. Read the supplement alongside any per-chapter code in the repository's chapter folders.
3. **Provision a lab host.** Stand up a Debian 13 VM (or a small cluster) with adequate CPU, RAM, and disk — the monitoring, forensics, and AI-agent labs are the most resource-hungry. Snapshot before you begin so you can reset and re-run.
4. **Read the domain overview first.** Each category opens with background and a "lab vs. production" framing that makes the hands-on steps meaningful, then walks numbered steps to a validation checklist.

## Get the Book

The Second Edition is available from Packt and major retailers:

👉 **[The Cybersecurity Architect's Handbook, Second Edition (Amazon)](https://www.amazon.com/Cybersecurity-Architects-Handbook-architects-enterprise/dp/180610539X/)**


## Acknowledgments

Thanks to Packt, to Corey Ball for the Foreword, and to the readers of the first edition whose feedback shaped this one. The labs stand on the work of the open-source security community — Snort, OPNsense, Graylog, Wazuh, ClamAV, Keycloak, VeraCrypt, OpenVAS/Greenbone, Ansible, The Sleuth Kit, Autopsy, Security Onion, SonarQube, OWASP ZAP, Kali Linux, Metasploit, and the many other projects that make a cost-free, full-spectrum security lab possible.