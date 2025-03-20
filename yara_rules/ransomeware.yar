
rule AdvancedRansomwareDetection
{
    meta:
        description = "YARA rule for detecting sophisticated ransomware behaviors, encryption techniques, and evasion tactics."
        author = "Cyberkid"
        version = "4.0"
        date = "2025-03-20"

    strings:
        // Common ransomware messages and ransom notes
        $ransom_note1 = "YOUR FILES HAVE BEEN ENCRYPTED"
        $ransom_note2 = "decrypt your files"
        $ransom_note3 = "ransom payment instructions"
        $ransom_note4 = "bitcoin address"
        $ransom_note5 = "decrypt key"
        
        // Suspicious file extensions created by ransomware
        $ransom_extension1 = ".locked"
        $ransom_extension2 = ".encrypted"
        $ransom_extension3 = ".crypt"
        $ransom_extension4 = ".payme"
        $ransom_extension5 = ".enc"
        
        // URLs used for command-and-control (C2) or ransom payments
        $ransom_url1 = /https?:\/\/[a-zA-Z0-9.-]+\/decrypt/
        $ransom_url2 = /https?:\/\/[a-zA-Z0-9.-]+\/bitcoin/
        $ransom_url3 = /https?:\/\/[a-zA-Z0-9.-]+\/payment/
        
        // Known ransomware encryption routines
        $aes_encryption = { 89 50 4E 47 0D 0A 1A 0A 00 00 00 0D 49 48 44 52 }
        $rsa_key_gen = { 30 82 ?? ?? 30 0D 06 09 2A 86 48 86 F7 0D 01 01 01 }
        $chacha20_encryption = { C7 44 24 10 01 00 00 00 44 8B C3 }
        
        // File renaming behavior
        $rename_api1 = "MoveFileExA"
        $rename_api2 = "MoveFileExW"
        $rename_api3 = "SetFileAttributesA"
        $rename_api4 = "SetFileAttributesW"
        
        // Suspicious API calls used in ransomware
        $encrypt_api1 = "CryptEncrypt"
        $encrypt_api2 = "CryptGenKey"
        $encrypt_api3 = "CryptImportKey"
        $encrypt_api4 = "CryptAcquireContextA"
        $encrypt_api5 = "CryptAcquireContextW"
        
        // Self-deletion and process persistence techniques
        $self_delete1 = "cmd.exe /c del "
        $self_delete2 = "cmd.exe /c erase "
        $persistence1 = "schtasks /create"
        $persistence2 = "reg add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        
        // Mutex, registry modifications, and privilege escalation
        $mutex_create = "CreateMutexA"
        $registry_modify = "RegSetValueExA"
        $uac_bypass = "fodhelper.exe"
        $privilege_escalation1 = "SeDebugPrivilege"
        $privilege_escalation2 = "SeShutdownPrivilege"
    
    condition:
        any of ($ransom_note*) or any of ($ransom_extension*) or any of ($ransom_url*) or any of ($aes_encryption*) or any of ($rsa_key_gen*) or any of ($chacha20_encryption*) or any of ($rename_api*) or any of ($encrypt_api*) or any of ($self_delete*) or any of ($persistence*) or any of ($privilege_escalation*) or $mutex_create or $registry_modify or $uac_bypass
}
