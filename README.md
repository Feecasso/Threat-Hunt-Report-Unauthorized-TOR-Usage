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
