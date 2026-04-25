package com.safetech.otshield.model;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "honeypot_logs")
public class HoneypotLog {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @Column(name = "timestamp", nullable = false)
    private LocalDateTime timestamp;
    
    @Column(name = "source_ip", nullable = false)
    private String sourceIp;
    
    @Column(name = "destination_ip")
    private String destinationIp;
    
    @Column(name = "source_port")
    private Integer sourcePort;
    
    @Column(name = "destination_port")
    private Integer destinationPort;
    
    @Column(name = "protocol", nullable = false)
    private String protocol;
    
    @Column(name = "attack_type")
    private String attackType;
    
    @Column(name = "payload", columnDefinition = "TEXT")
    private String payload;
    
    @Column(name = "severity")
    private String severity;
    
    @Column(name = "description", columnDefinition = "TEXT")
    private String description;
    
    @Column(name = "geo_location")
    private String geoLocation;
    
    @Column(name = "user_agent")
    private String userAgent;
    
    @Column(name = "session_id")
    private String sessionId;

    @Column(name = "username_attempt")
    private String usernameAttempt;

    @Column(name = "password_attempt")
    private String passwordAttempt;

    @Column(name = "country")
    private String country;

    @Column(name = "city")
    private String city;

    /** Where this event originated. Common values:
     *    "external"        - perimeter Conpot honeypot facing the internet
     *    "internal-decoy"  - tripwire HMI living inside an OT subnet
     *    null              - unknown / legacy rows
     */
    @Column(name = "decoy_source")
    private String decoySource;

    /** Free-form site identifier sent by internal decoys (e.g. "WATER-PLANT-A"). */
    @Column(name = "site_tag")
    private String siteTag;

    @Column(name = "is_blocked")
    private Boolean isBlocked = false;
    
    // Constructors
    public HoneypotLog() {}
    
    public HoneypotLog(String sourceIp, String protocol, String attackType, String payload) {
        this.timestamp = LocalDateTime.now();
        this.sourceIp = sourceIp;
        this.protocol = protocol;
        this.attackType = attackType;
        this.payload = payload;
        this.severity = "MEDIUM";
    }
    
    // Getters and Setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    
    public LocalDateTime getTimestamp() { return timestamp; }
    public void setTimestamp(LocalDateTime timestamp) { this.timestamp = timestamp; }
    
    public String getSourceIp() { return sourceIp; }
    public void setSourceIp(String sourceIp) { this.sourceIp = sourceIp; }
    
    public String getDestinationIp() { return destinationIp; }
    public void setDestinationIp(String destinationIp) { this.destinationIp = destinationIp; }
    
    public Integer getSourcePort() { return sourcePort; }
    public void setSourcePort(Integer sourcePort) { this.sourcePort = sourcePort; }
    
    public Integer getDestinationPort() { return destinationPort; }
    public void setDestinationPort(Integer destinationPort) { this.destinationPort = destinationPort; }
    
    public String getProtocol() { return protocol; }
    public void setProtocol(String protocol) { this.protocol = protocol; }
    
    public String getAttackType() { return attackType; }
    public void setAttackType(String attackType) { this.attackType = attackType; }
    
    public String getPayload() { return payload; }
    public void setPayload(String payload) { this.payload = payload; }
    
    public String getSeverity() { return severity; }
    public void setSeverity(String severity) { this.severity = severity; }
    
    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
    
    public String getGeoLocation() { return geoLocation; }
    public void setGeoLocation(String geoLocation) { this.geoLocation = geoLocation; }
    
    public String getUserAgent() { return userAgent; }
    public void setUserAgent(String userAgent) { this.userAgent = userAgent; }
    
    public String getSessionId() { return sessionId; }
    public void setSessionId(String sessionId) { this.sessionId = sessionId; }

    public String getUsernameAttempt() { return usernameAttempt; }
    public void setUsernameAttempt(String usernameAttempt) { this.usernameAttempt = usernameAttempt; }

    public String getPasswordAttempt() { return passwordAttempt; }
    public void setPasswordAttempt(String passwordAttempt) { this.passwordAttempt = passwordAttempt; }

    public String getCountry() { return country; }
    public void setCountry(String country) { this.country = country; }

    public String getCity() { return city; }
    public void setCity(String city) { this.city = city; }

    public String getDecoySource() { return decoySource; }
    public void setDecoySource(String decoySource) { this.decoySource = decoySource; }

    public String getSiteTag() { return siteTag; }
    public void setSiteTag(String siteTag) { this.siteTag = siteTag; }

    public Boolean getIsBlocked() { return isBlocked; }
    public void setIsBlocked(Boolean isBlocked) { this.isBlocked = isBlocked; }
}
