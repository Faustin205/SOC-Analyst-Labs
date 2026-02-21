# Phishing Email Analysis Lab 🛡️

## 📝 Scenario
In this lab, I analyzed a suspicious email reported by a user to determine if it was a phishing attempt and identify potential Indicators of Compromise (IoCs).

## 🛠️ Tools Used
- [cite_start]**Wireshark** (Network traffic analysis) [cite: 43, 59]
- **Any.Run** / **VirusTotal** (Link & File analysis)
- **CyberChef** (Decoding headers)

## 🔍 Analysis Steps
1. **Header Analysis:** Checked the 'From' address and 'Return-Path' to detect spoofing.
2. **Link Inspection:** Extracted URLs and checked their reputation on VirusTotal.
3. **Attachment Analysis:** Analyzed the file hash of the attached document.

## 📉 Findings
- **Status:** Malicious 🚩
- **Sender IP:** 192.x.x.x
- **Malicious URL:** hxxp://fake-login-page[.]com
