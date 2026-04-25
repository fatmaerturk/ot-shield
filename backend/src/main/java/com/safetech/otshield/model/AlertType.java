package com.safetech.otshield.model;

public enum AlertType {
    // Network Security
    INTRUSION_DETECTION("Intrusion Detection"),
    PORT_SCAN("Port Scan"),
    BRUTE_FORCE("Brute Force Attack"),
    DDoS_ATTACK("DDoS Attack"),
    MALWARE_DETECTION("Malware Detection"),
    PHISHING_ATTACK("Phishing Attack"),
    
    // Application Security
    SQL_INJECTION("SQL Injection"),
    XSS_ATTACK("Cross-Site Scripting"),
    CSRF_ATTACK("CSRF Attack"),
    PATH_TRAVERSAL("Path Traversal"),
    COMMAND_INJECTION("Command Injection"),
    
    // Authentication & Authorization
    FAILED_LOGIN("Failed Login Attempt"),
    UNAUTHORIZED_ACCESS("Unauthorized Access"),
    PRIVILEGE_ESCALATION("Privilege Escalation"),
    ACCOUNT_LOCKOUT("Account Lockout"),
    SUSPICIOUS_LOGIN("Suspicious Login"),
    
    // System Security
    FILE_INTEGRITY("File Integrity Alert"),
    PROCESS_MONITORING("Process Monitoring"),
    REGISTRY_CHANGE("Registry Change"),
    SERVICE_CHANGE("Service Change"),
    
    // Honeypot Specific
    HONEYPOT_TRIGGER("Honeypot Trigger"),
    HONEYPOT_INTERACTION("Honeypot Interaction"),
    HONEYPOT_EXPLOIT("Honeypot Exploit"),
    
    // General
    THREAT_INTELLIGENCE("Threat Intelligence"),
    COMPLIANCE_VIOLATION("Compliance Violation"),
    DATA_LEAKAGE("Data Leakage"),
    ANOMALY_DETECTION("Anomaly Detection"),
    CUSTOM_RULE("Custom Rule"),
    
    // Additional types for compatibility
    ANOMALY("Anomaly"),
    HONEYPOT("Honeypot"),
    IOA("Indicator of Attack");

    private final String displayName;

    AlertType(String displayName) {
        this.displayName = displayName;
    }

    public String getDisplayName() {
        return displayName;
    }

    @Override
    public String toString() {
        return displayName;
    }
} 