# A Cloud-Backed File Was Potentially Remediated to a Privileged Directory
<br>

## Use Case Documentation
### Description
This use case identifies a cloud-backed or cloud-placeholder file (e.g. a OneDrive or SharePoint file) is involved in a Defender remediation process combined with writes to a privileged directory. It is triggered when file system redirection mechanisms, such as cloud file reparse points, interact with security remediation workflows executed by system-level services like Microsoft Defender. In these cases, an incorrectly resolved or manipulated file reference may cause restored or quarantined content to be written into sensitive locations instead of its intended safe destination.

This behavior is relevant to the RedSun vulnerability, which abuses weaknesses in how Microsoft Defender handles cloud-backed file remediation. Adversaries may leverage NTFS reparse points and cloud file placeholders to manipulate the destination of Microsoft Defender's privileged write operations. When Defender (which runs as SYSTEM), attempts to remediate a detected file, the redirection logic can be abused to redirect writes into protected directories, potentially enabling arbitrary file placement in privileged locations.

### Recommended Response Actions
- Analyze both the binary executed and the initiating process.
- Check file both file prevalence and if the binary is signed.
- If this appears to be an exploit check for successful execution of the file and check for any sudden conhost process creations.

### Logging and Query Blind Spots
- The detection currently looks for certain folder combinations. If the adversary modifies the exploit to use unconventional folders, this detection might not trigger.

### Possible False Positives
- Benign processes that genuinely need to write both to the AppData Temp folder and System32 might trigger an alert if they trigger an AV detection.


### References
- https://github.com/Nightmare-Eclipse/RedSun


### MITRE ATT&CK Mapping
| Technique ID | Name | Description | Associated Tactics |
| ------------ | ---- | ------------| ------------------ |
| [T1548](https://attack.mitre.org/techniques/T1548/) | Abuse Elevation Control Mechanism | Adversaries may circumvent mechanisms designed to control elevate privileges to gain higher-level permissions. Most modern systems contain native elevation control mechanisms that are intended to limit privileges that a user can perform on a machine. Authorization has to be granted to specific users in order to perform tasks that can be considered of higher risk. An adversary can perform several methods to take advantage of built-in control mechanisms in order to escalate privileges on a system. | TA0004 - Privilege Escalation, TA0005 - Defense Evasion  |
| [T1548.002](https://attack.mitre.org/techniques/T1548/002/) | Abuse Elevation Control Mechanism: Bypass User Account Control | Adversaries may bypass UAC mechanisms to elevate process privileges on system. Windows User Account Control (UAC) allows a program to elevate its privileges (tracked as integrity levels ranging from low to high) to perform a task under administrator-level permissions, possibly by prompting the user for confirmation. The impact to the user ranges from denying the operation under high enforcement to allowing the user to perform the action if they are in the local administrators group and click through the prompt or allowing them to enter an administrator password to complete the action. | TA0004 - Privilege Escalation, TA0005 - Defense Evasion  |
| [T1548.005](https://attack.mitre.org/techniques/T1548/005/) | Abuse Elevation Control Mechanism: Temporary Elevated Cloud Access | Adversaries may abuse permission configurations that allow them to gain temporarily elevated access to cloud resources. Many cloud environments allow administrators to grant user or service accounts permission to request just-in-time access to roles, impersonate other accounts, pass roles onto resources and services, or otherwise gain short-term access to a set of privileges that may be distinct from their own.  | TA0004 - Privilege Escalation, TA0005 - Defense Evasion  |
| [T1574.010](https://attack.mitre.org/techniques/T1574/010/) | Hijack Execution Flow: Services File Permissions Weakness | Adversaries may execute their own malicious payloads by hijacking the binaries used by services. Adversaries may use flaws in the permissions of Windows services to replace the binary that is executed upon service start. These service processes may automatically execute specific binaries as part of their functionality or to perform other actions. If the permissions on the file system directory containing a target binary, or permissions on the binary itself are improperly set, then the target binary may be overwritten with another binary using user-level permissions and executed by the original process. If the original process and thread are running under a higher permissions level, then the replaced binary will also execute under higher-level permissions, which could include SYSTEM. | TA0003 - Persistence, TA0004 - Privilege Escalation, TA0005 - Defense Evasion  |
| [T1565](https://attack.mitre.org/techniques/T1565/) | Data Manipulation | Adversaries may insert, delete, or manipulate data in order to influence external outcomes or hide activity, thus threatening the integrity of the data. By manipulating data, adversaries may attempt to affect a business process, organizational understanding, or decision making. | TA0040 - Impact  |
| [T1565.001](https://attack.mitre.org/techniques/T1565/001/) | Data Manipulation: Stored Data Manipulation | Adversaries may insert, delete, or manipulate data at rest in order to influence external outcomes or hide activity, thus threatening the integrity of the data. By manipulating stored data, adversaries may attempt to affect a business process, organizational understanding, and decision making. | TA0040 - Impact  |

<br>

## Detection

### Defender Configuration
| Property                   | Value            |
| -------------------------- | ---------------- |
| Name                                          | A Cloud-Backed File Was Potentially Remediated to a Privileged Directory |
| Alert Name                                    | A Cloud-Backed File Was Potentially Remediated to a Privileged Directory |
| Platform                                      | Microsoft Defender for Endpoint \(MDE\) |
| Severity                                      | Medium |
| Category                                      | Persistence |
| Impacted Assets \(`EntityType:Identifier`\)   | `Device:DeviceId`   |
| Automated Response Actions                    |  No automated response actions defined.  |
| Query Period                                  | 1H |

### Detection Logic
```kusto
let _span = 48h;
let _FolderPaths = datatable(FolderPath:string) [
      @"\AppData\Local\Temp\"
    , @":\Windows\"
];
let _AntiVirusDetectionEvents = () {
    DeviceEvents
    |     where ingestion_time() >= ago(_span)
    |     where ActionType == "AntivirusDetection"
    |     where FolderPath has @"\AppData\Local\Temp\"
    |    extend ThreatName = extract_json("$.ThreatName", AdditionalFields, typeof(string))
    |  distinct DeviceId, FileName, ThreatName
};
DeviceFileEvents
|     where ingestion_time() >= ago(_span)
|     where FolderPath has_any (_FolderPaths)
| summarize FolderPaths = make_set(FolderPath)
          , arg_max(Timestamp, *)
         by InitiatingProcessFileName
          , InitiatingProcessUniqueId
          , DeviceId
          , FileName
|     where FolderPaths has_all (_FolderPaths)
|      join kind=inner
            _AntiVirusDetectionEvents()
         on DeviceId
          , FileName
```

---

## Version History

| Version | Date | Impact | Notes |
|---------|------|--------|-------|
| 1.0 | 2026-04-20 | Major | Initial version of the detection rule. |
