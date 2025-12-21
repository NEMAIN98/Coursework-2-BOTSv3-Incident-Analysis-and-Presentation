1. Introduction 
Security Operations Centres (SOCs) exist to reduce cyber risk by continuously monitoring enterprise telemetry, detecting malicious behaviours, validating alerts, and coordinating incident response. A SOC relies on both visibility (log coverage and quality) and analytic capability (correlation rules, enrichment, and analyst investigation workflows). Splunk supports these needs by ingesting large-scale telemetry and providing flexible searching and correlation through the Search Processing Language (SPL).
This assessment investigates the Boss of the SOC v3 (BOTSv3) dataset. BOTSv3 is a publicly available, pre-indexed security dataset and CTF platform created by Splunk that simulates an incident at a fictitious brewing company (“Frothly”). It contains multi-domain logs including cloud audit telemetry (O365), email telemetry (SMTP), endpoint telemetry (Sysmon and osquery), and identity activity (Windows Security). The dataset is designed to support investigation through the cyber kill chain, requiring analysts to identify attacker behaviours across multiple sources and answer guided questions using evidence-driven reasoning [1].


Objectives
1.	Demonstrate the use of Splunk in a SOC-style workflow for ingestion readiness and investigation.
2.	Answer BOTSv3 300-level guided questions Q1–Q8 using SPL and evidence.
3.	Interpret findings in incident-handling terms (detection → escalation → response actions and improvements).

Scope and assumptions
•	This report is restricted to Q1–Q8 as the required question set.
•	Evidence is drawn from Splunk searches and screenshots (Figures 1–1).
•	The environment is a lab/learning setup; conclusions reflect simulated incident activity and are not verified with live host forensics.
