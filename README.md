# 1. Introduction

Security Operations Centres (SOCs) exist to reduce cyber risk by continuously monitoring enterprise telemetry, detecting malicious behaviours, validating alerts, and coordinating incident response. A SOC relies on both visibility (log coverage and quality) and analytic capability (correlation rules, enrichment, and analyst investigation workflows). Splunk supports these needs by ingesting large-scale telemetry and providing flexible searching and correlation through the Search Processing Language (SPL).

This assessment investigates the Boss of the SOC v3 (BOTSv3) dataset. BOTSv3 is a publicly available, pre-indexed security dataset and CTF platform created by Splunk that simulates an incident at a fictitious brewing company (“Frothly”). It contains multi-domain logs including cloud audit telemetry (O365), email telemetry (SMTP), endpoint telemetry (Sysmon and osquery), and identity activity (Windows Security). The dataset is designed to support investigation through the cyber kill chain, requiring analysts to identify attacker behaviours across multiple sources and answer guided questions using evidence-driven reasoning [1].

## Objectives

Demonstrate the use of Splunk in a SOC-style workflow for ingestion readiness and investigation.

Answer BOTSv3 300-level guided questions Q1–Q8 using SPL and evidence.

Interpret findings in incident-handling terms (detection → escalation → response actions and improvements).
## Scope and assumptions

This report is restricted to Q1–Q8 as the required question set.

Evidence is drawn from Splunk searches and screenshots (Figures 1–1).

The environment is a lab/learning setup; conclusions reflect simulated incident activity and are not verified with live host forensics.

# 2. SOC Roles & Incident Handling Reflection

A SOC commonly operates using role separation to scale its response capability

Tier 1 (Triage / Monitoring) - reviews alerts, checks dashboards, validates whether activity is benign or suspicious, and performs initial pivots (user → host → time range → related indicators). Tier 1 aims to reduce noise and escalate only credible incidents.

Tier 2 (Incident Investigation / Response) - confirms the incident, builds timelines across sources, determines scope and impact, identifies attacker TTPs, and recommends containment actions.

Tier 3 (Threat Hunting / Detection Engineering) - develops correlation logic, tunes detections to reduce false positives, builds dashboards, and integrates intelligence (e.g., known bad hashes/user agents).

BOTSv3 maps well to this structure. Several Q1–Q8 answers represent “Tier 1 signals” (unusual UA, suspicious attachment), while others are “Tier 2 confirmation” (account creation, admin group escalation, listening port, and file hash). The exercise reinforces that SOC investigations progress from weak indicators to high-confidence behaviours by correlating different sources and building a coherent narrative [6,7].

Incident handling methodology relevance

Using a standard lifecycle (Preparation → Detection & Analysis → Containment/Eradication/Recovery → Lessons Learned) [2], BOTSv3 demonstrates:

The importance of Preparation (correct data onboarding and parsing) to enable accurate investigations.

Detection & Analysis via SPL pivots across sourcetypes to validate malicious intent.

Practical response implications, even in a simulation: disabling malicious accounts, removing persistence, isolating hosts, and blocking IoCs.

Lessons learned through improved SOC rules (e.g., correlation of 4720 followed by privileged group adds) [5].

# 3. Installation & Data Preparation

## 3.1 Environment setup evidence and SOC justification

Splunk Enterprise was deployed using a virtual machine environment. VM-based deployment is appropriate in SOC training because it supports

reproducibility (consistent versions/config),

isolation (reduces risk to host system),

snapshots (roll back to known good states),

controlled access (local web UI and lab-only access).

**Evidence**

![Figure 1](images/figure-01.jpeg)

*Figure 1 confirms the BotsV3 VM exists in Oracle VirtualBox.*

![Figure 2](images/figure-02.jpeg)
