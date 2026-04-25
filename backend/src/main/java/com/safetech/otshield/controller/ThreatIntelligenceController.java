package com.safetech.otshield.controller;

import com.safetech.otshield.mapper.Threat;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.LocalDate;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/threat-intel")
public class ThreatIntelligenceController {

    @GetMapping
    public List<Threat> getThreatIntel() {
        // build the original list
        List<Threat> threats = List.of(
                new Threat(
                        "1",
                        "Ransomware Alert",
                        "A new ransomware campaign has been detected...",
                        "OTShield",
                        "2025-04-22",
                        List.of("Ransomware", "Critical"),
                        "https://example.com/logos/fireeye.png",
                        "https://example.com/alerts/1"
                ),
                new Threat(
                        "2",
                        "Supply Chain Attack",
                        "Indicators of supply chain attacks have been observed...",
                        "OTShield",
                        "2025-03-25",
                        List.of("Supply Chain", "High"),
                        "https://example.com/logos/talos.png",
                        "https://example.com/alerts/2"
                ),
                new Threat(
                        "3",
                        "Phishing Campaign",
                        "A sophisticated phishing campaign targeting enterprise credentials...",
                        "OTShield",
                        "2025-04-01",
                        List.of("Phishing", "Medium"),
                        "https://example.com/logos/crowdstrike.png",
                        "https://example.com/alerts/3"
                ),
                new Threat(
                        "4",
                        "Zero-Day Exploit",
                        "Attackers are exploiting a zero-day vulnerability in industrial controllers...",
                        "OTShield",
                        "2025-03-02",
                        List.of("Exploit", "Critical"),
                        "https://example.com/logos/kaspersky.png",
                        "https://example.com/alerts/4"
                ),
                new Threat(
                        "5",
                        "Insider Threat Activity",
                        "Unusual access patterns detected from an internal user account...",
                        "OTShield",
                        "2025-04-03",
                        List.of("Insider", "High"),
                        "https://example.com/logos/sans.png",
                        "https://example.com/alerts/5"
                ),
                new Threat(
                        "6",
                        "DDoS Campaign",
                        "A large-scale DDoS campaign is targeting OT network resources...",
                        "OTShield",
                        "2024-04-04",
                        List.of("DDoS", "Critical"),
                        "https://example.com/logos/cisco-talos.png",
                        "https://example.com/alerts/6"
                ),
                new Threat(
                        "7",
                        "Credential Stuffing Attack",
                        "Multiple login attempts using breached credentials observed against ICS interfaces...",
                        "OTShield",
                        "2025-03-08",
                        List.of("Credential Access", "High"),
                        "https://example.com/logos/microsoft.png",
                        "https://example.com/alerts/7"
                ),
                new Threat(
                        "8",
                        "Firmware Tampering",
                        "Unauthorized firmware modification detected on remote PLC...",
                        "OTShield",
                        "2024-04-06",
                        List.of("Integrity", "Critical"),
                        "https://example.com/logos/dragos.png",
                        "https://example.com/alerts/8"
                ),
                new Threat(
                        "9",
                        "Watering Hole Attack",
                        "OT vendor portal compromised to deliver malware payloads...",
                        "OTShield",
                        "2025-04-07",
                        List.of("Execution", "Medium"),
                        "https://example.com/logos/symantec.png",
                        "https://example.com/alerts/9"
                ),
                new Threat(
                        "10",
                        "Password Spraying",
                        "Low-frequency login attempts across multiple accounts detected...",
                        "OTShield",
                        "2025-04-08",
                        List.of("Credential Access", "Medium"),
                        "https://example.com/logos/crowdstrike.png",
                        "https://example.com/alerts/10"
                ),
                new Threat(
                        "11",
                        "Insider Data Exfiltration",
                        "Unusual large data transfers detected from a control system...",
                        "OTShield",
                        "2025-04-09",
                        List.of("Exfiltration", "High"),
                        "https://example.com/logos/fireeye.png",
                        "https://example.com/alerts/11"
                ),
                new Threat(
                        "12",
                        "Brute Force SSH",
                        "Multiple failed SSH login attempts observed from single IP...",
                        "OTShield",
                        "2025-04-10",
                        List.of("Brute Force", "Medium"),
                        "https://example.com/logos/cisco-talos.png",
                        "https://example.com/alerts/12"
                ),
                new Threat(
                        "13",
                        "Malicious USB Activity",
                        "Unauthorized USB device connected to engineering workstation...",
                        "OTShield",
                        "2025-04-11",
                        List.of("Execution", "Low"),
                        "https://example.com/logos/dragos.png",
                        "https://example.com/alerts/13"
                ),
                new Threat(
                        "14",
                        "Modbus Exception Flood",
                        "High rate of Modbus error responses indicating potential DoS...",
                        "OTShield",
                        "2025-04-12",
                        List.of("Impact", "High"),
                        "https://example.com/logos/kaspersky.png",
                        "https://example.com/alerts/14"
                ),
                new Threat(
                        "15",
                        "ARP Spoofing",
                        "ARP poisoning attempts detected on the OT network segment...",
                        "OTShield",
                        "2025-04-13",
                        List.of("Evasion", "Medium"),
                        "https://example.com/logos/crowdstrike.png",
                        "https://example.com/alerts/15"
                ),
                new Threat(
                        "16",
                        "SQL Injection",
                        "Suspicious SQL queries observed against HMI database endpoints...",
                        "OTShield",
                        "2025-04-14",
                        List.of("Initial Access", "High"),
                        "https://example.com/logos/symantec.png",
                        "https://example.com/alerts/16"
                ),
                new Threat(
                        "17",
                        "DNS Tunneling",
                        "Abnormal DNS request patterns indicating data exfiltration...",
                        "OTShield",
                        "2025-04-15",
                        List.of("Command and Control", "High"),
                        "https://example.com/logos/microsoft.png",
                        "https://example.com/alerts/17"
                ),
                new Threat(
                        "18",
                        "Phantom Process",
                        "Unknown process appearing in PLC memory without registration...",
                        "OTShield",
                        "2025-04-16",
                        List.of("Persistence", "Critical"),
                        "https://example.com/logos/sans.png",
                        "https://example.com/alerts/18"
                )
        );

        // sort by date descending (newest first)
        return threats.stream()
            .sorted(Comparator.comparing((Threat t) -> LocalDate.parse(t.getDate())).reversed())
            .collect(Collectors.toList());
    }
}