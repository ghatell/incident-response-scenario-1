# 🚨 Incident Response: Brute Force Attempt Detection

This project simulates a brute-force attack against Azure virtual machines and documents detection, investigation, and response using Microsoft Sentinel and Defender for Endpoint (MDE).

![ChatGPT Image Apr 6, 2025 at 05_53_02 PM](https://github.com/user-attachments/assets/f62e5852-f838-456b-a385-731f1581e928)

## 🧪 Scenario Overview

A brute-force attempt was simulated on Azure virtual machines by repeatedly failing login attempts from various public IP addresses. A Microsoft Sentinel analytics rules was created to detect this behavior. The incident was then worked through the **NIST 800-61** Incident Response Lifecycle.

<img width="1440" alt="log5" src="https://github.com/user-attachments/assets/b51334e2-3c0c-4ee4-83c5-6dc2454e453b" />

---

## 🔍 Detection: Brute Force Rule Creation

A custom KQL query was written to detect repeated failed login attempts from the same remote IP address:

```kql
DeviceLogonEvents
| where ActionType == "LogonFailed" and TimeGenerated > ago(5h)
| summarize EventCount = count() by RemoteIP, DeviceName
| where EventCount >= 10
| order by EventCount
```
<img width="719" alt="log1" src="https://github.com/user-attachments/assets/699e778f-5221-4f45-8f31-63f7f8ef39e0" />

### 📊 Detection Results

Three Azure VMs were flagged as potentially targeted by brute-force attempts:

| Remote IP        | Device Name        | Attempts | Result       |
|------------------|--------------------|----------|--------------|
| 95.143.191.159   | `john-l-threat`    | 100      | Logon Failed |
| 103.237.86.97    | `first-test`       | 23       | Logon Failed |
| 194.180.49.123   | `tosinvm-ranger1`  | 12       | Logon Failed |

<img width="1440" alt="log3" src="https://github.com/user-attachments/assets/b4f2ebb6-55c4-47ae-bee3-e412c7cdfaf7" />

### 🏛️ MITRE ATT&CK Mapping

The detection rule aligns with the following MITRE ATT&CK tactics and techniques:

- **Tactic**: Credential Access
- **Technique**: Brute Force – [T1110](https://attack.mitre.org/techniques/T1110/)

These mappings ensure the threat is categorized using industry standards and allow for consistent response strategies.

---

## 🕵️ Investigation

To verify whether any of the identified IP addresses successfully logged in, the following query was used:

```kql
DeviceLogonEvents
| where RemoteIP in ("95.143.191.159", "103.237.86.97", "194.180.49.123")
| where ActionType != "LogonFailed"
```
<img width="512" alt="log2" src="https://github.com/user-attachments/assets/61f42f2e-016f-409e-8d87-db23ab996f30" />


**Outcome:**  
No successful logins were observed. The brute-force attempts did not result in unauthorized access.

---

## 🔒 Containment & Recovery

**Actions Taken:**

- ✅ **Device Isolation**: All three virtual machines were isolated using Microsoft Defender for Endpoint.
- ✅ **Anti-Malware Scans**: Full antivirus scans were conducted on all impacted systems.
- ✅ **NSG Lockdown**: Network Security Group (NSG) rules were updated to restrict RDP access to a trusted IP (home network). Public RDP was disabled.
- 🔐 **Policy Proposal**: A policy was proposed to enforce restricted NSG configurations or require the use of Azure Bastion for remote access to all VMs.

<img width="1440" alt="log4" src="https://github.com/user-attachments/assets/7651469c-7800-4c32-b5b0-f7553caff1db" />

---

## 📘 Lessons Learned & Recommendations

- 🔄 Implement Just-In-Time (JIT) VM access to minimize attack exposure.
- 🛡️ Require multi-factor authentication (MFA) for administrative access.
- 📋 Thoroughly document all findings and mark the incident in Sentinel as a **True Positive**.
- ⚙️ Recommend enforcing VM hardening policies through Azure Policy to prevent overly permissive configurations like open RDP ports.

<img width="482" alt="log6" src="https://github.com/user-attachments/assets/1df0bda3-f53d-4a0e-9e67-a53c777a2426" />

---

## 🧹 Cleanup

- The analytics rule and related incident were deleted in Microsoft Sentinel after documentation was completed.
- Verified that only resources created for this simulation were removed.

---

