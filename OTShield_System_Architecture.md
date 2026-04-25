# OTShield System Architecture Diagram (High Level)

## System Overview
OTShield is a comprehensive Industrial Control System (ICS) security platform designed to protect critical infrastructure from cyber threats through real-time monitoring, threat detection, and compliance management.

## Architecture Components

### 1. Frontend Layer (React.js)
```
┌─────────────────────────────────────────────────────────────────┐
│                        FRONTEND LAYER                          │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────┐ │
│  │   Dashboard │  │    Assets   │  │  Anomalies  │  │ Alerts  │ │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────┘ │
│                                                                 │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────┐ │
│  │  Honeypot   │  │MITRE Matrix │  │   Conpot    │  │Threat   │ │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────┘ │
│                                                                 │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────┐ │
│  │User Mgmt    │  │Alert Mgmt   │  │ NIS2        │  │Intel    │ │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

### 2. Backend Layer (Spring Boot)
```
┌─────────────────────────────────────────────────────────────────┐
│                       BACKEND LAYER                            │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐ │
│  │   REST API      │  │  WebSocket API  │  │  File Upload    │ │
│  │   Controllers   │  │   Handlers      │  │   Service       │ │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘ │
│                                                                 │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐ │
│  │  Security       │  │  Authentication │  │  Authorization  │ │
│  │  Configuration  │  │  Service        │  │  Service        │ │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘ │
│                                                                 │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐ │
│  │  Event          │  │  Notification   │  │  Logging        │ │
│  │  Publisher      │  │  Service        │  │  Service        │ │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

### 3. Service Layer
```
┌─────────────────────────────────────────────────────────────────┐
│                       SERVICE LAYER                            │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────┐ │
│  │  Asset      │  │  Anomaly    │  │  Alert      │  │  User   │ │
│  │  Service    │  │  Service    │  │  Service    │  │Service  │ │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────┘ │
│                                                                 │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────┐ │
│  │  Honeypot   │  │  Conpot     │  │  PCAP       │  │  MITRE  │ │
│  │  Service    │  │  Service    │  │  Service    │  │Service  │ │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────┘ │
│                                                                 │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────┐ │
│  │  Threat     │  │  Compliance │  │  File       │  │Security │ │
│  │  Intel      │  │  Service    │  │  Service    │  │Service  │ │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

### 4. Data Layer
```
┌─────────────────────────────────────────────────────────────────┐
│                        DATA LAYER                              │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐ │
│  │   PostgreSQL    │  │   File System   │  ┌─────────────────┐ │
│  │   (Production)  │  │   (Logs/PCAP)   │  │   Cache         │ │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘ │
│                                                                 │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐ │
│  │   JPA/Hibernate │  │   Repository    │  │   Entity        │ │
│  │   ORM Layer     │  │   Pattern       │  │   Models        │ │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

### 5. External Integrations
```
┌─────────────────────────────────────────────────────────────────┐
│                    EXTERNAL INTEGRATIONS                       │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────┐ │
│  │   Conpot    │  │   IP Geoloc │  │   Slack     │  │  Email  │ │
│  │   Honeypot  │  │   API       │  │  Webhooks   │  │Service  │ │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────┘ │
│                                                                 │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────┐ │
│  │   MITRE     │  │   OWASP     │  │   NIS2      │  │ Threat  │ │
│  │   ATT&CK    │  │   Top 10    │  │  Compliance │  │ Feeds   │ │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

## Complete System Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                                    OTShield System Architecture                    │
├─────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                     │
│  ┌─────────────────────────────────────────────────────────────────────────────────┐ │
│  │                              FRONTEND LAYER (React.js)                         │ │
│  │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐      │ │
│  │  │Dashboard│ │ Assets  │ │Anomalies│ │ Alerts  │ │Honeypot │ │MITRE    │      │ │
│  │  └─────────┘ └─────────┘ └─────────┘ └─────────┘ └─────────┘ └─────────┘      │ │
│  │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐      │ │
│  │  │ Conpot  │ │Threat   │ │User     │ │Alert    │ │ NIS2    │ │Intel    │      │ │
│  │  │         │ │Intel    │ │Mgmt     │ │Mgmt     │ │Compliance│ │         │      │ │
│  │  └─────────┘ └─────────┘ └─────────┘ └─────────┘ └─────────┘ └─────────┘      │ │
│  └─────────────────────────────────────────────────────────────────────────────────┘ │
│                                    ↕ HTTP/WebSocket                                │
│  ┌─────────────────────────────────────────────────────────────────────────────────┐ │
│  │                              BACKEND LAYER (Spring Boot)                       │ │
│  │  ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐                  │ │
│  │  │   REST API      │ │  WebSocket API  │ │  Security       │                  │ │
│  │  │   Controllers   │ │   Handlers      │ │  Configuration  │                  │ │
│  │  └─────────────────┘ └─────────────────┘ └─────────────────┘                  │ │
│  └─────────────────────────────────────────────────────────────────────────────────┘ │
│                                    ↕ Service Calls                                 │
│  ┌─────────────────────────────────────────────────────────────────────────────────┐ │
│  │                              SERVICE LAYER                                     │ │
│  │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐      │ │
│  │  │ Asset   │ │ Anomaly │ │ Alert   │ │ User    │ │Honeypot │ │ Conpot  │      │ │
│  │  │Service  │ │Service  │ │Service  │ │Service  │ │Service  │ │Service  │      │ │
│  │  └─────────┘ └─────────┘ └─────────┘ └─────────┘ └─────────┘ └─────────┘      │ │
│  │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐      │ │
│  │  │ PCAP    │ │ MITRE   │ │ Threat  │ │Compliance│ │ File    │ │Security │      │ │
│  │  │Service  │ │Service  │ │ Intel   │ │Service  │ │Service  │ │Service  │      │ │
│  │  └─────────┘ └─────────┘ └─────────┘ └─────────┘ └─────────┘ └─────────┘      │ │
│  └─────────────────────────────────────────────────────────────────────────────────┘ │
│                                    ↕ Data Access                                   │
│  ┌─────────────────────────────────────────────────────────────────────────────────┐ │
│  │                              DATA LAYER                                        │ │
│  │  ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐                  │ │
│  │  │   PostgreSQL    │ │   File System   │ │   Cache         │                  │ │
│  │  │   (Production)  │ │   (Logs/PCAP)   │ │   (Redis)       │                  │ │
│  │  └─────────────────┘ └─────────────────┘ └─────────────────┘                  │ │
│  └─────────────────────────────────────────────────────────────────────────────────┘ │
│                                    ↕ External APIs                                 │
│  ┌─────────────────────────────────────────────────────────────────────────────────┐ │
│  │                            EXTERNAL INTEGRATIONS                               │ │
│  │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐      │ │
│  │  │ Conpot  │ │ IP Geoloc│ │ Slack  │ │ Email   │ │ MITRE   │ │ OWASP   │      │ │
│  │  │Honeypot │ │ API     │ │Webhooks│ │Service  │ │ ATT&CK  │ │ Top 10  │      │ │
│  │  └─────────┘ └─────────┘ └─────────┘ └─────────┘ └─────────┘ └─────────┘      │ │
│  │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐      │ │
│  │  │ NIS2    │ │ Threat  │ │ Network │ │ Security│ │ Threat  │ │ Compliance│     │ │
│  │  │Compliance│ │ Feeds   │ │Monitoring│ │Tools    │ │Intel    │ │Standards │     │ │
│  │  └─────────┘ └─────────┘ └─────────┘ └─────────┘ └─────────┘ └─────────┘      │ │
│  └─────────────────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────────────────┘
```

## Key Features by Module

### 1. Dashboard
- Real-time network traffic monitoring
- KPI metrics and statistics
- Live packet capture and analysis
- Network topology visualization

### 2. Assets Management
- ICS device inventory
- Asset classification and tagging
- Vulnerability assessment
- Asset risk scoring

### 3. Anomaly Detection
- Behavioral analysis
- Pattern recognition
- Machine learning-based detection
- Real-time alerting

### 4. Honeypot
- Industrial honeypot simulation
- Attack pattern analysis
- Threat intelligence gathering
- Russian/Chinese attack simulation

### 5. MITRE ATT&CK Matrix
- Threat technique mapping
- Attack pattern analysis
- Defense strategy planning
- Tactic identification

### 6. Conpot Integration
- Modbus honeypot
- Industrial protocol simulation
- Real-time log monitoring
- Attack simulation

### 7. Threat Intelligence
- Threat feed integration
- IOC management
- Threat hunting
- Intelligence sharing

### 8. Compliance (NIS2)
- Regulatory compliance
- Audit trails
- Policy management
- Compliance reporting

### 9. User Management
- Role-based access control
- User authentication
- Permission management
- Audit logging

## Security Features

- **Authentication**: JWT-based authentication
- **Authorization**: Role-based access control
- **Encryption**: Data encryption at rest and in transit
- **Audit Logging**: Comprehensive audit trails
- **Network Security**: Firewall and intrusion detection
- **Compliance**: NIS2, IEC 62443, NERC CIP standards

## Technology Stack

- **Frontend**: React.js, TypeScript, Tailwind CSS
- **Backend**: Spring Boot, Java 17
- **Database**: PostgreSQL (Production)
- **Cache**: Redis (Optional)
- **Real-time**: WebSocket, Server-Sent Events
- **Security**: JWT, Spring Security
- **Monitoring**: Custom logging, metrics collection
- **Integration**: REST APIs, WebSocket APIs

## Deployment Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Load Balancer │    │   Web Servers   │    │   Database      │
│                 │───▶│                │───▶│   (PostgreSQL)  │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Frontend      │    │   File Storage  │    │   Cache         │
│   (React.js)    │    │   (Logs/PCAP)   │    │   (Redis)       │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

This architecture provides a comprehensive, scalable, and secure platform for industrial control system security monitoring and threat management. 