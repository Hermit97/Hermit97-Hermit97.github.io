---
layout: default
title: SMB Analysis
---
# CASE_STUDY: SMB_LATERAL_MOVEMENT

## EXECUTIVE_SUMMARY
Observed suspicious traffic originating from 192.168.1.50. This report details the identification of potential lateral movement using SMBv2.

## METHODOLOGY
1. Filtered traffic for `tcp.port == 445`.
2. Followed TCP streams to identify the NTLMSSP authentication.
3. Analyzed `Tree Connect` commands to see which folders were accessed.

## ANALYST_OBSERVATIONS
* **Source IP:** 192.168.1.50
* **Destination IP:** 192.168.1.10 (Domain Controller)
* **Action:** Attempted access to `C$` share.

## TOOLS_USED
* **Wireshark:** Primary packet analysis.
* **NetworkMiner:** Artifact extraction.

## DETECTION_LOGIC (SOC_READY)
```text
# Potential Alert Logic
alert tcp any any -> any 445 (msg:"Potential SMB Admin Share Access"; content:"C$"; sid:1000001;)
