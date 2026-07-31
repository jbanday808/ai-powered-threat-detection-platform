# Lumma Stealer Reverse Engineering Report

## Executive Summary

This report documents the reverse engineering of a Lumma Stealer malware sample using IDA Pro inside a controlled malware-analysis lab.

The analysis reviewed the malware's internal strings, imported functions, and named functions to understand its likely capabilities.

The findings indicate that the sample contains functionality related to browser credential collection, password decryption, system discovery, process discovery, and privilege-related activity.

### Non-Technical Explanation

Reverse engineering is similar to opening a machine and examining its internal parts to understand what it was designed to do.

The analysis showed that this malware appears designed to search for valuable information, especially saved browser usernames and passwords.

## Analysis Objective

The objectives of the reverse engineering review were to:

* Confirm that the sample is a Windows executable.
* Review imported libraries and functions.
* Identify credential-theft-related strings.
* Identify Chrome and Edge credential collection functions.
* Review password decryption capabilities.
* Review Chromium master key access.
* Identify process and system discovery functions.
* Review privilege-related functions.
* Document evidence without including active malware.

## Tool Used

| Tool | Purpose |
| --- | --- |
| IDA Pro | Reverse engineering, string review, imported function review, and malware function analysis |

### Non-Technical Explanation

IDA Pro allows an analyst to examine the internal structure of a program without including the active malware in the report.

## Evidence Reviewed

### [IDA Imports](../screenshots/LummaStealer_03_IDA_Imports.png)

* **Evidence reviewed:** IDA Pro's imported-functions view.
* **Technical observation:** The screenshot records external Windows functions and libraries available to the executable. Imports indicate potential capabilities, but the screenshot alone does not prove that every import was called.
* **Non-technical explanation:** These imports are tools the program can ask Windows to provide.
* **Security importance:** Reviewing them helps analysts identify possible file, process, network, encryption, or system-control activity that may require deeper investigation.

### [IDA PE Overview](../screenshots/LummaStealer_04_IDA_PE_Overview.png)

* **Evidence reviewed:** IDA Pro's Portable Executable overview.
* **Technical observation:** The screenshot identifies a Windows Portable Executable structure.
* **Non-technical explanation:** The file is organized as a program intended for Windows.
* **Security importance:** Correctly identifying the file format helps analysts choose appropriate analysis tools and interpret its internal structure.

### [IDA Credential-Theft Indicators](../screenshots/LummaStealer_05_IDA_Credential_Theft_Indicators.png)

* **Evidence reviewed:** Credential-theft-related strings and references visible in IDA Pro.
* **Technical observation:** The visible indicators appear related to credential access and browser information.
* **Non-technical explanation:** The program contains internal labels or text associated with finding valuable login data.
* **Security importance:** These indicators help focus analysis on credential stores and other sensitive browser data.

### [IDA Credential Collection Functions](../screenshots/LummaStealer_06_IDA_Credential_Collection_Functions.png)

* **Evidence reviewed:** Named credential collection functions visible in IDA Pro.
* **Technical observation:** Function names include Chrome and Edge login collection and password-protection-related functionality.
* **Non-technical explanation:** The internal parts of the program appear designed to look for login information saved by common web browsers.
* **Security importance:** Browser credentials may provide access to personal, financial, cloud, and company accounts.

### [IDA Privilege Escalation and Credential Theft Functions](../screenshots/LummaStealer_07_IDA_Privilege_Escalation_and_Credential_Theft_Functions.png)

* **Evidence reviewed:** Named privilege-related and credential-theft-related functions visible in IDA Pro.
* **Technical observation:** The function names indicate possible privilege enabling, token access, impersonation, and credential-related capabilities. They do not independently confirm successful privilege escalation.
* **Non-technical explanation:** The program appears to contain features for seeking more control over a computer and accessing protected information.
* **Security importance:** Higher permissions may expose information and actions unavailable to a normal user account.

### [IDA Chromium Master Keys Function Reference](../screenshots/LummaStealer_08_IDA_ChromiumMasterKeys_Function_Reference.png)

* **Evidence reviewed:** The IDA Pro reference to `main.GetChromiumMasterKeys`.
* **Technical observation:** The named function is associated with Chromium master keys used in protecting browser data.
* **Non-technical explanation:** The program appears to look for a digital key that helps protect saved browser information.
* **Security importance:** Access to the correct key may support attempts to unlock protected browser data.

## Finding 1: Windows Executable Structure

### Evidence

* [LummaStealer_04_IDA_PE_Overview.png](../screenshots/LummaStealer_04_IDA_PE_Overview.png)
* Portable Executable structure observed in IDA Pro

### Technical Finding

IDA Pro identified the sample as a Windows Portable Executable.

### Non-Technical Explanation

This confirms that the file was designed to run as a Windows program.

### Why It Matters

Confirming the file type helps analysts select the correct tools and investigation methods.

## Finding 2: Imported Functions and Libraries

### Evidence

* [LummaStealer_03_IDA_Imports.png](../screenshots/LummaStealer_03_IDA_Imports.png)

### Technical Finding

The imported functions and libraries provided information about the Windows services that the program could use. The available evidence does not establish that every imported function was actively used.

### Non-Technical Explanation

Imported functions are tools that a program can request from Windows. Reviewing them helps analysts understand the types of actions the program may be able to perform.

### Why It Matters

Suspicious imports may reveal file access, process activity, network communication, encryption, or system-control capabilities.

## Finding 3: Browser Credential Collection

### Evidence

* `main.getChromeLogins`
* `main.getEdgeLogins`
* `main.GetChromiumMasterKeys`

### Technical Finding

The function names indicate functionality related to accessing saved login information from Chrome and Edge and reviewing Chromium master keys.

### Non-Technical Explanation

The malware appears designed to search for usernames and passwords saved inside Chrome and Microsoft Edge.

### Why It Matters

Stolen browser credentials could give an attacker access to email, cloud services, financial accounts, and company systems.

## Finding 4: Password Decryption

### Evidence

* `main.loginPBE.Decrypt`
* `main.DPAPI`

### Technical Finding

The identified functions appear related to decrypting protected password data and interacting with the Windows Data Protection API. The existing evidence does not directly confirm that passwords were successfully decrypted.

### Non-Technical Explanation

The malware may try to unlock password information that Windows or a browser normally keeps protected.

### Why It Matters

Protected passwords can become readable if malware gains access to the correct Windows user context or encryption material.

## Finding 5: Chromium Master Key Access

### Evidence

* `main.GetChromiumMasterKeys`
* [LummaStealer_08_IDA_ChromiumMasterKeys_Function_Reference.png](../screenshots/LummaStealer_08_IDA_ChromiumMasterKeys_Function_Reference.png)

### Technical Finding

Reverse engineering identified a function associated with Chromium master keys, which help protect saved browser information.

### Non-Technical Explanation

The malware appears to look for a digital key that browsers use to protect saved passwords and other sensitive information.

### Why It Matters

Access to the correct browser protection key may help malware unlock protected browser data.

## Finding 6: Process and System Discovery

### Evidence

* `main.findLsassProcess`
* `main.NtQuerySystemHandles`

### Technical Finding

The functions indicate that the malware may inspect running processes and system resources. The available evidence does not confirm that LSASS credentials were dumped.

### Non-Technical Explanation

The malware appears to examine the computer to learn which programs are running and what system resources are available.

### Why It Matters

Attackers use system discovery to understand a computer before attempting additional actions.

## Finding 7: Privilege-Related Activity

### Evidence

* `main.enablePrivilege`
* `main.getSystemToken`
* `main.impersonateSystem`

### Technical Finding

The function names indicate functionality related to enabling privileges, obtaining system tokens, and impersonating a higher-privileged account. The existing evidence does not confirm that privilege escalation succeeded.

### Non-Technical Explanation

The malware appears to contain features that could help it request more control over the computer.

### Why It Matters

Higher permissions could allow malware to access protected information or perform actions that a normal user cannot perform.

## Reverse Engineering Findings Summary

| Finding | Evidence | Simple Meaning | Assessment |
| --- | --- | --- | --- |
| Browser credential collection | `main.getChromeLogins`, `main.getEdgeLogins` | Searches for saved Chrome and Edge login information | Strong indication |
| Chromium key access | `main.GetChromiumMasterKeys` | Looks for keys that protect browser data | Strong indication |
| Password decryption | `main.loginPBE.Decrypt`, `main.DPAPI` | May unlock protected password information | Strong indication |
| Process discovery | `main.findLsassProcess` | Looks for an important Windows process | Function identified |
| System discovery | `main.NtQuerySystemHandles` | Examines system resources | Function identified |
| Privilege-related activity | `main.enablePrivilege`, `main.getSystemToken`, `main.impersonateSystem` | May attempt to obtain higher system access | Capability indicated |

## MITRE ATT&CK Relationships

The table below highlights relationships relevant to the reverse engineering findings. See the existing MITRE ATT&CK report for the complete case-study mapping.

| Technique | ID | Reverse Engineering Evidence |
| --- | --- | --- |
| Process Discovery | T1057 | `main.findLsassProcess` |
| System Information Discovery | T1082 | `main.NtQuerySystemHandles` |
| Credentials from Password Stores | T1555 | Browser login and password functions |
| Credentials from Web Browsers | T1555.003 | Chrome, Edge, and Chromium master key functions |
| Unsecured Credentials | T1552 | Password decryption and DPAPI-related functions |
| Access Token Manipulation | T1134 | System token and impersonation functions |
| Abuse Elevation Control Mechanism | T1548 | `main.enablePrivilege` |

[View the complete MITRE ATT&CK mapping](mitre-attack.md)

## Key Analyst Assessment

Reverse engineering provided strong evidence that the sample contains functionality associated with Lumma Stealer credential theft behavior.

The most important findings were the functions related to Chrome and Edge login collection, Chromium master key access, password decryption, process discovery, and privilege-related activity.

The function names establish likely capabilities, but they do not independently prove that every function executed successfully during the controlled test.

## Defensive Recommendations

* Monitor suspicious access to Chrome and Edge login databases.
* Monitor access to browser `Local State`, `Login Data`, `Cookies`, and `Web Data` files.
* Investigate unexpected use of Windows DPAPI-related functions.
* Alert on suspicious processes attempting to access LSASS.
* Review unusual token manipulation or privilege-enabling activity.
* Use endpoint protection to block known Lumma Stealer indicators.
* Use the existing YARA rule and Splunk searches for additional validation.
* Reset passwords and revoke active sessions when browser credential theft is suspected.

These recommendations help security teams identify similar behavior before stolen credentials are used.

## Analysis Limitations

* The report is based on existing IDA Pro screenshots and documented findings.
* Function names indicate likely capabilities but do not prove successful execution.
* No malware sample is included in the repository.
* No passwords, credentials, browser databases, or sensitive information are included.
* Additional runtime and memory analysis may be required to confirm every capability.

## Analyst Conclusion

The reverse engineering review identified internal functions associated with browser credential theft, password decryption, Chromium master key access, process discovery, system discovery, and privilege-related activity.

In simple terms, the malware appears designed to locate valuable browser information, attempt to unlock protected data, inspect the computer, and potentially request higher system access.

These findings support the overall assessment that the sample is consistent with Lumma Stealer credential-theft malware.

## Safety Notice

This report is for defensive cybersecurity research, threat hunting, incident response, and detection engineering only.

No malware samples, executable files, archives, payloads, credentials, secrets, or malware execution instructions are included.
