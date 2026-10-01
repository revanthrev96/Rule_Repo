index="edr_extended" sourcetype="crowdstrike:events:sensor" event_simpleName="PeFileWritten" event_platform="Win" TokenType=2
``` search where context image is within a user writeable folder and is creating a PE file in system32/syswow64 root path ```
("system32" OR "syswow64")
("users" OR "programdata" OR "temp" OR "perflogs")
ContextImageFileName IN ("*\\programdata\\*", "*\\users\\*", "*\\windows\\temp\\*", "*\\perflogs\\*")
(TargetFileName="*\\system32\\*" OR TargetFileName="*\\syswow64\\*")
| regex TargetFileName="(?i)\\\\(system32|syswow64)\\\\[^\\\\]+$"

eval

    , impersonated_as=case(
        FileOperatorSid=="S-1-5-18", "SYSTEM",
        FileOperatorSid=="S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464", "TrustedInstaller",
        match(FileOperatorSid, "^S-1-5-21-.+-500$"), "Built-in Administrator",
        true(), "Other privileged account (admin or backup operator)")

stats
, values(impersonated_as) AS impersonated_as