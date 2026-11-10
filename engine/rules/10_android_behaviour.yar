// ARGENT DEFENDER — Android behavioural indicator rules (applied to DEX/SO/resources).
// These are HEURISTICS: they describe capability patterns, not malware families.
// Confidence is deliberately LOW/MEDIUM; corroborate with permissions and intel.

rule AD_AND_Accessibility_Automation_Overlay {
    meta:
        category = "banking_trojan"
        severity = "HIGH"
        confidence = "MEDIUM"
        description = "Code uses accessibility automation together with window overlays (credential-overlay / ATS pattern)"
        recommendation = "Check whether the app's accessibility service is enabled and whether you trust the app."
    strings:
        $a1 = "performGlobalAction"
        $a2 = "getRootInActiveWindow"
        $a3 = "dispatchGesture"
        $o1 = "TYPE_APPLICATION_OVERLAY"
        $o2 = "SYSTEM_ALERT_WINDOW"
        $o3 = "addView"
    condition:
        (uint32(0) == 0x0a786564 or uint32(0) == 0x464c457f) and 2 of ($a*) and 2 of ($o*)
}

rule AD_AND_SMS_Telegram_Exfil {
    meta:
        category = "spyware"
        severity = "HIGH"
        confidence = "MEDIUM"
        description = "SMS interception code combined with a Telegram Bot API endpoint (pattern used by Indonesian 'APK undangan/resi' SMS stealers)"
        recommendation = "Uninstall the app, change banking/e-wallet PINs and contact your bank: OTP codes may have been forwarded."
    strings:
        $s1 = "android.provider.Telephony.SMS_RECEIVED"
        $s2 = "createFromPdu"
        $s3 = "getMessageBody"
        $t1 = "api.telegram.org/bot"
        $t2 = "sendMessage?chat_id="
    condition:
        2 of ($s*) and 1 of ($t*)
}

rule AD_AND_SMS_Forwarder {
    meta:
        category = "spyware"
        severity = "MEDIUM"
        confidence = "LOW"
        description = "Reads incoming SMS bodies and contains HTTP upload code"
        recommendation = "Only messaging/OTP-autofill apps legitimately read SMS. Verify the app."
    strings:
        $s1 = "android.provider.Telephony.SMS_RECEIVED"
        $s2 = "getMessageBody"
        $h1 = "HttpURLConnection"
        $h2 = "okhttp3"
    condition:
        uint32(0) == 0x0a786564 and all of ($s*) and 1 of ($h*)
}

rule AD_AND_DeviceAdmin_Locker {
    meta:
        category = "ransomware"
        severity = "HIGH"
        confidence = "MEDIUM"
        description = "Device-admin locking/password-reset capability (locker ransomware pattern)"
        recommendation = "Revoke device-admin rights for the app and uninstall it in Safe Mode if it resists removal."
    strings:
        $d = "DevicePolicyManager"
        $l1 = "lockNow"
        $l2 = "resetPassword"
        $l3 = "wipeData"
    condition:
        uint32(0) == 0x0a786564 and $d and 2 of ($l*)
}

rule AD_AND_Ransom_Note {
    meta:
        category = "ransomware"
        severity = "HIGH"
        confidence = "LOW"
        description = "Ransom-note vocabulary (EN/ID) in application code or resources"
        recommendation = "Do not pay. Isolate the device and restore from a known-good backup."
    strings:
        $r1 = "your files have been encrypted" nocase
        $r2 = "file anda telah dienkripsi" nocase
        $r3 = "telah terenkripsi" nocase
        $p1 = "bitcoin" nocase
        $p2 = "BTC wallet" nocase
        $p3 = "tebusan" nocase
    condition:
        1 of ($r*) and 1 of ($p*)
}

rule AD_AND_Hidden_Surveillance {
    meta:
        category = "stalkerware"
        severity = "HIGH"
        confidence = "LOW"
        description = "Hides its launcher icon and contains audio-recording plus location code (stalkerware capability pattern)"
        recommendation = "If you did not install this app, your device may be monitored; seek support before removal if your safety may be at risk."
    strings:
        $h1 = "setComponentEnabledSetting"
        $h2 = "COMPONENT_ENABLED_STATE_DISABLED"
        $m1 = "MediaRecorder"
        $m2 = "setAudioSource"
        $g1 = "getLastKnownLocation"
        $g2 = "requestLocationUpdates"
    condition:
        uint32(0) == 0x0a786564 and all of ($h*) and 1 of ($m*) and 1 of ($g*)
}

rule AD_AND_Dynamic_Code_Loading {
    meta:
        category = "pua"
        severity = "LOW"
        confidence = "LOW"
        description = "Loads executable code at runtime (common in packers/droppers, also in legitimate SDKs)"
        recommendation = "Informational unless combined with other indicators."
    strings:
        $c1 = "dalvik/system/DexClassLoader"
        $c2 = "dalvik/system/InMemoryDexClassLoader"
        $n = "openConnection"
    condition:
        uint32(0) == 0x0a786564 and 1 of ($c*) and $n
}
