![Screenshot 2025-04-20 at 17-53-05 384567925-44bac428-01bb-4fe9-9d85-96cba7698bee png (PNG Image 1200 × 725 pixels) — Scaled (88%)](https://github.com/user-attachments/assets/81104102-92d5-47ce-bcda-c03bccb64d9c)

# Threat Hunt Report: Unauthorized TOR Usage

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "tor" in it and discovered what looks like the user "employee" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop at `2025-04-21T00:20:47.7611849Z`. These events began at `2025-04-20T23:46:18.2754863Z`.

**Query used to locate events:**

```kql
DeviceFileEvents  
| where DeviceName == "test-tor"  
| where InitiatingProcessAccountName == "feecasso"  
| where FileName contains "tor"  
| where Timestamp >= datetime(2025-04-20T23:46:18.2754863Z)  
| order by Timestamp desc  
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName


```
![Screenshot 2025-04-20 at 18-09-34 Advanced hunting - Microsoft Defender](https://github.com/user-attachments/assets/fb340bed-540b-4108-8d65-ed343b2297fe)


---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-14.0.1.exe". Based on the logs returned, at `2025-04-20T23:46:18.2754863Z`, an employee on the "threat-hunt-lab" device ran the file `tor-browser-windows-x86_64-portable-14.5.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents  
| where DeviceName == "threat-hunt-lab"  
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.5.exe"  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
![Screenshot 2025-04-20 at 18-40-57 Advanced hunting - Microsoft Defender](https://github.com/user-attachments/assets/2bdb61da-745a-433f-a2a7-608b260546f4)

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "employee" actually opened the TOR browser. There was evidence that they did open it at `2025-04-20T23:51:37.5801973Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents  
| where DeviceName == "test-tor"  
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine  
| order by Timestamp desc
```
![Screenshot 2025-04-20 at 18-52-54 Advanced hunting - Microsoft Defender](https://github.com/user-attachments/assets/5a435571-7693-401e-83d0-bf10f0f00ff1)

---
### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2025-04-20T23:51:50.6711276Z`, an employee on the "threat-hunt-lab" device successfully established a connection to the remote IP address `116.255.1.163` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\feecasso\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `443`.

**Query used to locate events:**

```kql
DeviceNetworkEvents  
| where DeviceName == "test-tor"  
| where InitiatingProcessAccountName != "system"  
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")  
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")  
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath  
| order by Timestamp desc
```
![Screenshot 2025-04-20 at 19-01-05 Advanced hunting - Microsoft Defender](https://github.com/user-attachments/assets/78dbec83-76f9-4e90-a78e-9ed9dae7b93a)


---
# 🕵️‍♂️ Threat Hunt: Unauthorized TOR Usage

## 🕒 Chronological Event Timeline

| Timestamp (UTC)           | Event Description                                                                 |
|---------------------------|------------------------------------------------------------------------------------|
| **2025-04-20 23:46:18**   | TOR installer (`tor-browser-windows-x86_64-portable-14.5.exe`) executed silently on `threat-hunt-lab` by user `feecasso`. |
| **2025-04-20 23:46:18**   | TOR-related file activity begins on `test-tor`. Multiple files copied to the desktop by `feecasso`. |
| **2025-04-20 23:51:37**   | TOR browser (`tor.exe`) launched by `feecasso` on `test-tor`.                                                          |
| **2025-04-20 23:51:50**   | Outbound network connection to TOR node `116.255.1.163` over port `9001` from `tor.exe`.                              |
| **2025-04-21 00:20:47**   | File `tor-shopping-list.txt` created on `test-tor` desktop by `feecasso`.                                             |

---

## 🧑‍💻 Involved Entities

- **User**: `feecasso`  
- **Devices**: `test-tor`, `threat-hunt-lab`  
- **Processes**: `tor.exe`, `firefox.exe`, `tor-browser.exe`  
- **Remote IP**: `116.255.1.163` (TOR Node)  
- **Ports**: `9001`, `443`

---


## ✅ Summary

An investigation was conducted following concerns of unauthorized TOR browser usage within the organization. The threat hunt revealed that a user (`feecasso`) on two devices (`test-tor` and `threat-hunt-lab`) had:

- Downloaded and executed the TOR browser (`tor-browser-windows-x86_64-portable-14.5.exe`)
- Created multiple TOR-related files, including `tor.exe`, `firefox.exe`, and a suspicious text file named `tor-shopping-list.txt`
- Launched TOR processes from the desktop directory
- Established outbound connections to known TOR network entry nodes over port `9001` and port `443`

### 🔒 Risk Assessment

- TOR usage enables users to bypass corporate network controls, potentially leading to data exfiltration or access to unauthorized/dark web resources.
- Activity was deliberate and sustained, suggesting intentional circumvention of company policy.

### 📢 Recommendation Summary

- **Isolate affected endpoints** for full forensic review.
- **Reset credentials** for user `feecasso` and audit their access.
- **Update firewall and proxy rules** to block TOR-related traffic (ports and IPs).
- **Deploy detection rules** for TOR-related executables and behaviors in the EDR.
- **Conduct user awareness training** to reinforce acceptable use policies.

**Status**: 🚨 Confirmed unauthorized TOR usage.  
**Action Required**: Immediate incident response and mitigation.

## 🛠️ Response Taken

TOR usage was confirmed on the endpoint `test-tor` by the user `feecasso`.

- The device `test-tor` was **isolated** via Microsoft Defender for Endpoint to prevent further network activity.
- The user's **direct manager was notified** regarding the policy violation.





