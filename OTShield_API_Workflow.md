# OTShield API Usage Workflow

## Overview
This document provides a comprehensive guide to the API usage workflows for OTShield, covering all modules and their interactions.

## Table of Contents
1. [Authentication & Authorization](#authentication--authorization)
2. [Dashboard API Workflow](#dashboard-api-workflow)
3. [Assets Management API Workflow](#assets-management-api-workflow)
4. [Anomaly Detection API Workflow](#anomaly-detection-api-workflow)
5. [Alerts Management API Workflow](#alerts-management-api-workflow)
6. [Honeypot API Workflow](#honeypot-api-workflow)
7. [MITRE ATT&CK Matrix API Workflow](#mitre-attck-matrix-api-workflow)
8. [Conpot Integration API Workflow](#conpot-integration-api-workflow)
9. [Threat Intelligence API Workflow](#threat-intelligence-api-workflow)
10. [User Management API Workflow](#user-management-api-workflow)
11. [Compliance (NIS2) API Workflow](#compliance-nis2-api-workflow)
12. [File Upload API Workflow](#file-upload-api-workflow)
13. [WebSocket API Workflow](#websocket-api-workflow)

---

## Authentication & Authorization

### Login Workflow
```mermaid
sequenceDiagram
    participant Client
    participant AuthController
    participant AuthService
    participant Database

    Client->>AuthController: POST /api/auth/login
    Note over Client,AuthController: {username, password}
    AuthController->>AuthService: authenticateUser()
    AuthService->>Database: findUserByUsername()
    Database-->>AuthService: User data
    AuthService->>AuthService: validatePassword()
    AuthService->>AuthService: generateJWT()
    AuthService-->>AuthController: {token, user}
    AuthController-->>Client: {success: true, token, user}
```

### API Endpoints
```http
POST /api/auth/login
Content-Type: application/json

{
  "username": "admin",
  "password": "password123"
}

Response:
{
  "success": true,
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": 1,
    "username": "admin",
    "fullName": "Administrator",
    "role": "ADMIN"
  }
}
```

### Authorization Header
```http
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

---

## Dashboard API Workflow

### Real-time Network Monitoring
```mermaid
sequenceDiagram
    participant Client
    participant DashboardController
    participant PCAPService
    participant WebSocket
    participant Database

    Client->>DashboardController: GET /api/dashboard/statistics
    DashboardController->>PCAPService: getNetworkStatistics()
    PCAPService->>Database: getPacketStats()
    Database-->>PCAPService: Statistics
    PCAPService-->>DashboardController: Network stats
    DashboardController-->>Client: Statistics data

    Client->>WebSocket: Connect to /ws/live-traffic
    WebSocket->>PCAPService: Start live capture
    PCAPService->>WebSocket: Stream packet data
    WebSocket->>Client: Real-time packets
```

### API Endpoints
```http
# Get dashboard statistics
GET /api/dashboard/statistics
Authorization: Bearer <token>

Response:
{
  "totalPackets": 15420,
  "uniqueIPs": 45,
  "uniquePorts": 23,
  "protocols": {
    "TCP": 12000,
    "UDP": 3420
  },
  "topSourceIPs": [...],
  "topDestPorts": [...]
}

# Get live network traffic
GET /api/dashboard/live-traffic
Authorization: Bearer <token>

# Upload PCAP file
POST /api/dashboard/upload-pcap
Content-Type: multipart/form-data
Authorization: Bearer <token>

# Get packet analysis
GET /api/dashboard/packets?page=0&size=50
Authorization: Bearer <token>
```

---

## Assets Management API Workflow

### Asset Discovery and Management
```mermaid
sequenceDiagram
    participant Client
    participant AssetController
    participant AssetService
    participant Database

    Client->>AssetController: POST /api/assets/discover
    AssetController->>AssetService: discoverAssets()
    AssetService->>AssetService: scanNetwork()
    AssetService->>Database: saveAssets()
    AssetService-->>AssetController: Discovery results
    AssetController-->>Client: Asset list

    Client->>AssetController: GET /api/assets
    AssetController->>AssetService: getAllAssets()
    AssetService->>Database: findAllAssets()
    Database-->>AssetService: Assets
    AssetService-->>AssetController: Asset data
    AssetController-->>Client: Assets list
```

### API Endpoints
```http
# Discover assets
POST /api/assets/discover
Authorization: Bearer <token>

{
  "networkRange": "192.168.1.0/24",
  "scanType": "FULL"
}

# Get all assets
GET /api/assets?page=0&size=20
Authorization: Bearer <token>

# Get asset by ID
GET /api/assets/{id}
Authorization: Bearer <token>

# Update asset
PUT /api/assets/{id}
Authorization: Bearer <token>
Content-Type: application/json

{
  "name": "PLC-001",
  "type": "PLC",
  "ipAddress": "192.168.1.100",
  "riskLevel": "HIGH"
}

# Delete asset
DELETE /api/assets/{id}
Authorization: Bearer <token>
```

---

## Anomaly Detection API Workflow

### Anomaly Detection and Analysis
```mermaid
sequenceDiagram
    participant Client
    participant AnomalyController
    participant AnomalyService
    participant MLService
    participant Database

    Client->>AnomalyController: GET /api/anomalies
    AnomalyController->>AnomalyService: getAnomalies()
    AnomalyService->>Database: findAnomalies()
    Database-->>AnomalyService: Anomalies
    AnomalyService-->>AnomalyController: Anomaly data
    AnomalyController-->>Client: Anomalies list

    AnomalyService->>MLService: analyzeBehavior()
    MLService->>MLService: detectAnomalies()
    MLService->>Database: saveAnomaly()
    MLService-->>AnomalyService: Detection results
```

### API Endpoints
```http
# Get anomalies
GET /api/anomalies?severity=HIGH&page=0&size=20
Authorization: Bearer <token>

# Get anomaly by ID
GET /api/anomalies/{id}
Authorization: Bearer <token>

# Update anomaly status
PUT /api/anomalies/{id}/status
Authorization: Bearer <token>
Content-Type: application/json

{
  "status": "RESOLVED",
  "notes": "False positive"
}

# Get anomaly statistics
GET /api/anomalies/statistics
Authorization: Bearer <token>
```

---

## Alerts Management API Workflow

### Alert Generation and Management
```mermaid
sequenceDiagram
    participant System
    participant AlertService
    participant AlertController
    participant NotificationService
    participant Client

    System->>AlertService: triggerAlert()
    AlertService->>AlertService: createAlert()
    AlertService->>Database: saveAlert()
    AlertService->>NotificationService: sendNotification()
    NotificationService->>Client: Push notification

    Client->>AlertController: GET /api/alerts
    AlertController->>AlertService: getAlerts()
    AlertService->>Database: findAlerts()
    Database-->>AlertService: Alerts
    AlertService-->>AlertController: Alert data
    AlertController-->>Client: Alerts list
```

### API Endpoints
```http
# Get alerts
GET /api/alerts?status=ACTIVE&page=0&size=20
Authorization: Bearer <token>

# Get alert by ID
GET /api/alerts/{id}
Authorization: Bearer <token>

# Update alert
PUT /api/alerts/{id}
Authorization: Bearer <token>
Content-Type: application/json

{
  "status": "ACKNOWLEDGED",
  "assignedTo": "admin",
  "notes": "Investigating..."
}

# Acknowledge alert
POST /api/alerts/{id}/acknowledge
Authorization: Bearer <token>

# Get alert statistics
GET /api/alerts/statistics
Authorization: Bearer <token>
```

---

## Honeypot API Workflow

### Honeypot Management and Monitoring
```mermaid
sequenceDiagram
    participant Client
    participant HoneypotController
    participant HoneypotService
    participant WebSocket
    participant Database

    Client->>HoneypotController: POST /api/honeypot/start
    HoneypotController->>HoneypotService: startHoneypot()
    HoneypotService->>HoneypotService: initializeHoneypot()
    HoneypotService->>Database: saveHoneypotStatus()
    HoneypotService-->>HoneypotController: Start result
    HoneypotController-->>Client: Success response

    Client->>WebSocket: Connect to /ws/honeypot-logs
    WebSocket->>HoneypotService: streamLogs()
    HoneypotService->>WebSocket: Real-time logs
    WebSocket->>Client: Live honeypot data
```

### API Endpoints
```http
# Start honeypot
POST /api/honeypot/start
Authorization: Bearer <token>

# Stop honeypot
POST /api/honeypot/stop
Authorization: Bearer <token>

# Get honeypot status
GET /api/honeypot/status
Authorization: Bearer <token>

# Get honeypot logs
GET /api/honeypot/logs?page=0&size=50
Authorization: Bearer <token>

# Clear honeypot logs
DELETE /api/honeypot/logs
Authorization: Bearer <token>

# Get honeypot statistics
GET /api/honeypot/statistics
Authorization: Bearer <token>
```

---

## MITRE ATT&CK Matrix API Workflow

### Threat Technique Mapping
```mermaid
sequenceDiagram
    participant Client
    participant MitreController
    participant MitreService
    participant Database

    Client->>MitreController: GET /api/mitre/techniques
    MitreController->>MitreService: getTechniques()
    MitreService->>Database: findTechniques()
    Database-->>MitreService: Techniques
    MitreService-->>MitreController: Technique data
    MitreController-->>Client: Techniques list

    Client->>MitreController: POST /api/mitre/map-event
    MitreController->>MitreService: mapEventToTechnique()
    MitreService->>MitreService: analyzeEvent()
    MitreService->>Database: saveMapping()
    MitreService-->>MitreController: Mapping result
    MitreController-->>Client: Mapped techniques
```

### API Endpoints
```http
# Get MITRE techniques
GET /api/mitre/techniques?tactic=Initial-Access
Authorization: Bearer <token>

# Get technique by ID
GET /api/mitre/techniques/{id}
Authorization: Bearer <token>

# Map event to technique
POST /api/mitre/map-event
Authorization: Bearer <token>
Content-Type: application/json

{
  "eventType": "LOGIN_ATTEMPT",
  "sourceIP": "192.168.1.100",
  "details": "Brute force attempt"
}

# Get technique statistics
GET /api/mitre/statistics
Authorization: Bearer <token>

# Get tactics
GET /api/mitre/tactics
Authorization: Bearer <token>
```

---

## Conpot Integration API Workflow

### Conpot Honeypot Management
```mermaid
sequenceDiagram
    participant Client
    participant ConpotController
    participant ConpotService
    participant WebSocket
    participant ExternalConpot

    Client->>ConpotController: POST /api/conpot/start
    ConpotController->>ConpotService: startConpot()
    ConpotService->>ExternalConpot: Start Conpot process
    ExternalConpot-->>ConpotService: Process started
    ConpotService->>Database: saveConpotStatus()
    ConpotService-->>ConpotController: Start result
    ConpotController-->>Client: Success response

    Client->>WebSocket: Connect to /ws/conpot-logs
    WebSocket->>ConpotService: streamConpotLogs()
    ConpotService->>WebSocket: Real-time logs
    WebSocket->>Client: Live Conpot data
```

### API Endpoints
```http
# Start Conpot
POST /api/conpot/start
Authorization: Bearer <token>

# Stop Conpot
POST /api/conpot/stop
Authorization: Bearer <token>

# Get Conpot status
GET /api/conpot/status
Authorization: Bearer <token>

# Get Conpot logs
GET /api/conpot/logs?page=0&size=50
Authorization: Bearer <token>

# Clear Conpot logs
DELETE /api/conpot/logs
Authorization: Bearer <token>

# Get Conpot statistics
GET /api/conpot/statistics
Authorization: Bearer <token>
```

---

## Threat Intelligence API Workflow

### Threat Intelligence Management
```mermaid
sequenceDiagram
    participant Client
    participant ThreatController
    participant ThreatService
    participant ExternalFeeds
    participant Database

    Client->>ThreatController: GET /api/threats/iocs
    ThreatController->>ThreatService: getIOCs()
    ThreatService->>Database: findIOCs()
    Database-->>ThreatService: IOCs
    ThreatService-->>ThreatController: IOC data
    ThreatController-->>Client: IOCs list

    ThreatService->>ExternalFeeds: fetchThreatFeeds()
    ExternalFeeds-->>ThreatService: Threat data
    ThreatService->>Database: updateThreatData()
    ThreatService->>ThreatService: analyzeThreats()
```

### API Endpoints
```http
# Get IOCs
GET /api/threats/iocs?type=IP&page=0&size=20
Authorization: Bearer <token>

# Add IOC
POST /api/threats/iocs
Authorization: Bearer <token>
Content-Type: application/json

{
  "type": "IP",
  "value": "192.168.1.100",
  "threatType": "MALWARE",
  "confidence": "HIGH"
}

# Get threat feeds
GET /api/threats/feeds
Authorization: Bearer <token>

# Update threat feeds
POST /api/threats/feeds/update
Authorization: Bearer <token>

# Get threat statistics
GET /api/threats/statistics
Authorization: Bearer <token>
```

---

## User Management API Workflow

### User Administration
```mermaid
sequenceDiagram
    participant Client
    participant UserController
    participant UserService
    participant Database

    Client->>UserController: GET /api/users
    UserController->>UserService: getUsers()
    UserService->>Database: findAllUsers()
    Database-->>UserService: Users
    UserService-->>UserController: User data
    UserController-->>Client: Users list

    Client->>UserController: POST /api/users
    UserController->>UserService: createUser()
    UserService->>UserService: validateUserData()
    UserService->>Database: saveUser()
    UserService-->>UserController: Created user
    UserController-->>Client: Success response
```

### API Endpoints
```http
# Get users
GET /api/users?page=0&size=20
Authorization: Bearer <token>

# Create user
POST /api/users
Authorization: Bearer <token>
Content-Type: application/json

{
  "username": "newuser",
  "password": "password123",
  "fullName": "New User",
  "role": "USER"
}

# Update user
PUT /api/users/{id}
Authorization: Bearer <token>
Content-Type: application/json

{
  "fullName": "Updated Name",
  "role": "ADMIN"
}

# Delete user
DELETE /api/users/{id}
Authorization: Bearer <token>

# Change password
POST /api/users/{id}/change-password
Authorization: Bearer <token>
Content-Type: application/json

{
  "oldPassword": "oldpass",
  "newPassword": "newpass"
}
```

---

## Compliance (NIS2) API Workflow

### Compliance Management
```mermaid
sequenceDiagram
    participant Client
    participant ComplianceController
    participant ComplianceService
    participant Database

    Client->>ComplianceController: GET /api/compliance/requirements
    ComplianceController->>ComplianceService: getRequirements()
    ComplianceService->>Database: findRequirements()
    Database-->>ComplianceService: Requirements
    ComplianceService-->>ComplianceController: Requirement data
    ComplianceController-->>Client: Requirements list

    Client->>ComplianceController: POST /api/compliance/assessment
    ComplianceController->>ComplianceService: createAssessment()
    ComplianceService->>ComplianceService: assessCompliance()
    ComplianceService->>Database: saveAssessment()
    ComplianceService-->>ComplianceController: Assessment result
    ComplianceController-->>Client: Assessment data
```

### API Endpoints
```http
# Get compliance requirements
GET /api/compliance/requirements
Authorization: Bearer <token>

# Get requirement by ID
GET /api/compliance/requirements/{id}
Authorization: Bearer <token>

# Create compliance assessment
POST /api/compliance/assessment
Authorization: Bearer <token>
Content-Type: application/json

{
  "requirementId": "NIS2-001",
  "status": "COMPLIANT",
  "evidence": "Security controls implemented",
  "assessedBy": "admin"
}

# Get compliance report
GET /api/compliance/report
Authorization: Bearer <token>

# Get compliance statistics
GET /api/compliance/statistics
Authorization: Bearer <token>
```

---

## File Upload API Workflow

### File Management
```mermaid
sequenceDiagram
    participant Client
    participant FileController
    participant FileService
    participant FileSystem

    Client->>FileController: POST /api/upload/pcap
    Note over Client,FileController: multipart/form-data
    FileController->>FileService: uploadFile()
    FileService->>FileSystem: saveFile()
    FileService->>FileService: processFile()
    FileService->>Database: saveFileMetadata()
    FileService-->>FileController: Upload result
    FileController-->>Client: Success response
```

### API Endpoints
```http
# Upload PCAP file
POST /api/upload/pcap
Content-Type: multipart/form-data
Authorization: Bearer <token>

# Upload configuration file
POST /api/upload/config
Content-Type: multipart/form-data
Authorization: Bearer <token>

# Get uploaded files
GET /api/upload/files?type=PCAP&page=0&size=20
Authorization: Bearer <token>

# Download file
GET /api/upload/files/{id}/download
Authorization: Bearer <token>

# Delete file
DELETE /api/upload/files/{id}
Authorization: Bearer <token>
```

---

## WebSocket API Workflow

### Real-time Communication
```mermaid
sequenceDiagram
    participant Client
    participant WebSocket
    participant WebSocketHandler
    participant Service
    participant Database

    Client->>WebSocket: Connect to /ws/live-traffic
    WebSocket->>WebSocketHandler: handleConnection()
    WebSocketHandler->>Service: startStreaming()
    Service->>Database: getLiveData()
    Service->>WebSocketHandler: streamData()
    WebSocketHandler->>Client: Real-time data

    Client->>WebSocket: Send message
    WebSocket->>WebSocketHandler: handleMessage()
    WebSocketHandler->>Service: processMessage()
    Service-->>WebSocketHandler: Response
    WebSocketHandler->>Client: Response
```

### WebSocket Endpoints
```javascript
// Live network traffic
const ws = new WebSocket('ws://localhost:8080/ws/live-traffic');

// Honeypot logs
const ws = new WebSocket('ws://localhost:8080/ws/honeypot-logs');

// Conpot logs
const ws = new WebSocket('ws://localhost:8080/ws/conpot-logs');

// Alert notifications
const ws = new WebSocket('ws://localhost:8080/ws/alerts');

// Message format
{
  "type": "status_update",
  "data": {
    "isRunning": true,
    "logCount": 150
  },
  "timestamp": 1640995200000
}
```

---

## Error Handling

### Standard Error Response
```json
{
  "success": false,
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid input data",
    "details": {
      "field": "username",
      "issue": "Username is required"
    }
  },
  "timestamp": "2024-01-01T12:00:00Z"
}
```

### HTTP Status Codes
- `200` - Success
- `201` - Created
- `400` - Bad Request
- `401` - Unauthorized
- `403` - Forbidden
- `404` - Not Found
- `500` - Internal Server Error

---

## Rate Limiting

### Rate Limit Headers
```http
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1640995200
```

### Rate Limit Rules
- **Authentication**: 5 requests per minute
- **API Calls**: 100 requests per hour per user
- **File Uploads**: 10 requests per hour per user
- **WebSocket**: No rate limiting

---

## Security Considerations

### Authentication
- JWT tokens with 24-hour expiration
- Refresh token mechanism
- Secure password hashing (BCrypt)

### Authorization
- Role-based access control (ADMIN, USER, VIEWER)
- Resource-level permissions
- API endpoint protection

### Data Protection
- HTTPS/TLS encryption
- Input validation and sanitization
- SQL injection prevention
- XSS protection

### Audit Logging
- All API calls logged
- User actions tracked
- Security events recorded
- Compliance audit trails

---

## Testing

### API Testing Endpoints
```http
# Health check
GET /api/health

# API documentation
GET /api/docs

# API version
GET /api/version

# System status
GET /api/status
```

### Test Data
```json
{
  "testUser": {
    "username": "testuser",
    "password": "testpass123",
    "role": "USER"
  },
  "testAdmin": {
    "username": "testadmin",
    "password": "adminpass123",
    "role": "ADMIN"
  }
}
```

This comprehensive API workflow document provides a complete guide for integrating with the OTShield platform, covering all modules and their interactions. 