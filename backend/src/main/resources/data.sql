-- Seed data for audit_records (insert statements only)
INSERT INTO audit_records (username, action_type, details, timestamp) VALUES
  ('fatma.erturk@otshield.io', 'FILTER_CHANGE', '{"severities":["Critical","High","Medium"],"dateOption":"All"}', '2025-04-08T09:00:00Z'),
  ('fatma.erturk@otshield.io', 'FILTER_CHANGE', '{"severities":["High"],"dateOption":"Last 24h"}', '2025-04-08T10:15:00Z'),
  ('fatma.erturk@otshield.io', 'ROW_VIEW',       '{"id":"1","source":"OTShield"}',         '2025-04-08T10:16:05Z'),
  ('fatma.erturk@otshield.io', 'ROW_VIEW',       '{"id":"3","source":"OTShield"}',         '2025-04-08T10:18:20Z'),
  ('fatma.erturk@otshield.io', 'FILTER_CHANGE', '{"severities":["Critical","Medium"],"dateOption":"Last 7 Days"}', '2025-04-08T11:02:45Z');

-- Sample user data
INSERT INTO users (id, email, password, full_name, username, role, is_admin, is_suspended, is_expired, source, created_at, updated_at, is_active, department, phone_number, avatar_url, timezone, language, failed_login_attempts, requires_password_change, notes) VALUES
('550e8400-e29b-41d4-a716-446655440001', 'admin@otshield.com', '$2a$10$N.zmdr9k7uOCQb376NoUnuTJ8iAt6Z5EHsM8lE9lBOsl7iKTVEFDa', 'System Administrator', 'admin', 'ROLE_ADMIN', true, false, false, 'SYSTEM', '2024-01-01 08:00:00', '2024-01-01 08:00:00', true, 'IT', '+1-555-0001', 'https://ui-avatars.com/api/?name=Admin&background=random', 'UTC', 'en', 0, false, 'System administrator account'),
('550e8400-e29b-41d4-a716-446655440002', 'analyst@otshield.com', '$2a$10$N.zmdr9k7uOCQb376NoUnuTJ8iAt6Z5EHsM8lE9lBOsl7iKTVEFDa', 'Security Analyst', 'analyst', 'ROLE_USER', false, false, false, 'SYSTEM', '2024-01-01 08:00:00', '2024-01-01 08:00:00', true, 'Security', '+1-555-0002', 'https://ui-avatars.com/api/?name=Analyst&background=random', 'UTC', 'en', 0, false, 'Security analyst account'),
('550e8400-e29b-41d4-a716-446655440003', 'operator@otshield.com', '$2a$10$N.zmdr9k7uOCQb376NoUnuTJ8iAt6Z5EHsM8lE9lBOsl7iKTVEFDa', 'Plant Operator', 'operator', 'ROLE_USER', false, false, false, 'SYSTEM', '2024-01-01 08:00:00', '2024-01-01 08:00:00', true, 'Operations', '+1-555-0003', 'https://ui-avatars.com/api/?name=Operator&background=random', 'UTC', 'en', 0, false, 'Plant operator account');

-- Sample user groups data
INSERT INTO user_groups (user_id, groups) VALUES
('550e8400-e29b-41d4-a716-446655440001', 'ADMINISTRATORS'),
('550e8400-e29b-41d4-a716-446655440001', 'SECURITY_TEAM'),
('550e8400-e29b-41d4-a716-446655440002', 'SECURITY_TEAM'),
('550e8400-e29b-41d4-a716-446655440002', 'ANALYSTS'),
('550e8400-e29b-41d4-a716-446655440003', 'OPERATORS'),
('550e8400-e29b-41d4-a716-446655440003', 'PLANT_PERSONNEL');

-- Sample asset data for OT environment
INSERT INTO assets (id, name, description, ip_address, mac_address, asset_type, asset_category, purdue_level, manufacturer, model, serial_number, firmware_version, operating_system, os_version, hostname, domain, location, department, owner, responsible_person, contact_email, contact_phone, purchase_date, warranty_expiry, last_maintenance, next_maintenance, criticality_level, risk_score, vulnerability_count, patch_level, backup_status, monitoring_status, is_active, is_online, last_seen, first_seen, created_at, updated_at, created_by, updated_by, notes, custom_fields) VALUES
-- Level 0 - Process Control
('550e8400-e29b-41d4-a716-446655440101', 'PLC-001', 'Main production line PLC', '192.168.1.10', '00:1B:44:11:3A:B7', 'PLC', 'CONTROL_SYSTEM', 'LEVEL_0', 'Siemens', 'SIMATIC S7-1200', 'SN123456789', 'V4.2.3', 'Embedded', 'V4.2.3', 'plc-001', 'plant.local', 'Production Line 1', 'Operations', 'Plant Manager', 'John Smith', 'john.smith@company.com', '+1-555-0123', '2023-01-15 00:00:00', '2026-01-15 00:00:00', '2024-01-15 00:00:00', '2024-07-15 00:00:00', 'CRITICAL', 85, 2, 'Current', 'UP_TO_DATE', 'MONITORED', true, true, '2024-01-20 10:30:00', '2023-01-15 08:00:00', '2024-01-20 10:30:00', '2024-01-20 10:30:00', 'admin', 'admin', 'Critical production control system', '{"protocols": ["Modbus TCP", "Profinet"], "ports": [502, 161]}'),

('550e8400-e29b-41d4-a716-446655440102', 'HMI-001', 'Production line HMI', '192.168.1.11', '00:1B:44:11:3A:B8', 'HMI', 'CONTROL_SYSTEM', 'LEVEL_1', 'Rockwell', 'PanelView Plus 7', 'SN987654321', 'V12.0.1', 'Windows Embedded', 'V12.0.1', 'hmi-001', 'plant.local', 'Production Line 1', 'Operations', 'Plant Manager', 'John Smith', 'john.smith@company.com', '+1-555-0123', '2023-02-01 00:00:00', '2026-02-01 00:00:00', '2024-02-01 00:00:00', '2024-08-01 00:00:00', 'HIGH', 75, 1, 'Current', 'UP_TO_DATE', 'MONITORED', true, true, '2024-01-20 10:30:00', '2023-02-01 08:00:00', '2024-01-20 10:30:00', '2024-01-20 10:30:00', 'admin', 'admin', 'Human machine interface for production line', '{"protocols": ["EtherNet/IP"], "ports": [44818]}'),

('550e8400-e29b-41d4-a716-446655440103', 'RTU-001', 'Remote terminal unit for tank monitoring', '192.168.1.12', '00:1B:44:11:3A:B9', 'RTU', 'CONTROL_SYSTEM', 'LEVEL_0', 'Schneider Electric', 'Modicon M580', 'SN456789123', 'V3.1.0', 'Embedded', 'V3.1.0', 'rtu-001', 'plant.local', 'Tank Farm', 'Operations', 'Plant Manager', 'John Smith', 'john.smith@company.com', '+1-555-0123', '2023-03-01 00:00:00', '2026-03-01 00:00:00', '2024-03-01 00:00:00', '2024-09-01 00:00:00', 'HIGH', 80, 3, 'Current', 'UP_TO_DATE', 'MONITORED', true, true, '2024-01-20 10:30:00', '2023-03-01 08:00:00', '2024-01-20 10:30:00', '2024-01-20 10:30:00', 'admin', 'admin', 'Remote terminal unit for tank level monitoring', '{"protocols": ["Modbus TCP", "IEC 60870-5-104"], "ports": [502, 2404]}'),

-- Level 2 - Area Supervisory
('550e8400-e29b-41d4-a716-446655440201', 'SCADA-001', 'Main SCADA server', '192.168.2.10', '00:1B:44:11:3A:BA', 'SCADA', 'CONTROL_SYSTEM', 'LEVEL_2', 'Siemens', 'WinCC V7.5', 'SN111222333', 'V7.5.1', 'Windows Server', '2019', 'scada-001', 'plant.local', 'Control Room', 'IT', 'IT Manager', 'Jane Doe', 'jane.doe@company.com', '+1-555-0124', '2023-01-01 00:00:00', '2026-01-01 00:00:00', '2024-01-01 00:00:00', '2024-07-01 00:00:00', 'CRITICAL', 90, 5, 'Current', 'UP_TO_DATE', 'MONITORED', true, true, '2024-01-20 10:30:00', '2023-01-01 08:00:00', '2024-01-20 10:30:00', '2024-01-20 10:30:00', 'admin', 'admin', 'Main SCADA system for plant operations', '{"protocols": ["OPC UA", "Modbus TCP"], "ports": [4840, 502]}'),

('550e8400-e29b-41d4-a716-446655440202', 'HISTORIAN-001', 'Data historian server', '192.168.2.11', '00:1B:44:11:3A:BB', 'HISTORIAN', 'DATA_STORAGE', 'LEVEL_2', 'OSIsoft', 'PI Server', 'SN444555666', 'V2020', 'Windows Server', '2019', 'historian-001', 'plant.local', 'Control Room', 'IT', 'IT Manager', 'Jane Doe', 'jane.doe@company.com', '+1-555-0124', '2023-02-01 00:00:00', '2026-02-01 00:00:00', '2024-02-01 00:00:00', '2024-08-01 00:00:00', 'HIGH', 85, 2, 'Current', 'UP_TO_DATE', 'MONITORED', true, true, '2024-01-20 10:30:00', '2023-02-01 08:00:00', '2024-01-20 10:30:00', '2024-01-20 10:30:00', 'admin', 'admin', 'Data historian for process data storage', '{"protocols": ["OPC UA", "PI API"], "ports": [4840, 5450]}'),

-- Level 3 - Site Business
('550e8400-e29b-41d4-a716-446655440301', 'WORKSTATION-001', 'Engineering workstation', '192.168.3.10', '00:1B:44:11:3A:BC', 'WORKSTATION', 'ENDPOINT', 'LEVEL_3', 'Dell', 'Precision 5820', 'SN777888999', 'N/A', 'Windows 10', '21H2', 'eng-ws-001', 'plant.local', 'Engineering Office', 'Engineering', 'Engineering Manager', 'Bob Wilson', 'bob.wilson@company.com', '+1-555-0125', '2023-03-01 00:00:00', '2026-03-01 00:00:00', '2024-03-01 00:00:00', '2024-09-01 00:00:00', 'MEDIUM', 60, 8, 'Current', 'UP_TO_DATE', 'MONITORED', true, true, '2024-01-20 10:30:00', '2023-03-01 08:00:00', '2024-01-20 10:30:00', '2024-01-20 10:30:00', 'admin', 'admin', 'Engineering workstation for system configuration', '{"software": ["TIA Portal", "WinCC"], "protocols": ["OPC UA"]}'),

('550e8400-e29b-41d4-a716-446655440302', 'SERVER-001', 'Application server', '192.168.3.11', '00:1B:44:11:3A:BD', 'SERVER', 'DATA_STORAGE', 'LEVEL_3', 'HP', 'ProLiant DL380', 'SN123789456', 'N/A', 'Windows Server', '2019', 'app-server-001', 'plant.local', 'Server Room', 'IT', 'IT Manager', 'Jane Doe', 'jane.doe@company.com', '+1-555-0124', '2023-01-15 00:00:00', '2026-01-15 00:00:00', '2024-01-15 00:00:00', '2024-07-15 00:00:00', 'HIGH', 75, 4, 'Current', 'UP_TO_DATE', 'MONITORED', true, true, '2024-01-20 10:30:00', '2023-01-15 08:00:00', '2024-01-20 10:30:00', '2024-01-20 10:30:00', 'admin', 'admin', 'Application server for business systems', '{"services": ["SQL Server", "IIS"], "protocols": ["HTTP", "HTTPS", "SQL"]}'),

-- Level 4 - DMZ
('550e8400-e29b-41d4-a716-446655440401', 'FIREWALL-001', 'Main plant firewall', '192.168.4.10', '00:1B:44:11:3A:BE', 'FIREWALL', 'SECURITY_DEVICE', 'LEVEL_4', 'Cisco', 'ASA 5525-X', 'SN987123654', 'V9.18.1', 'Cisco IOS', 'V9.18.1', 'fw-001', 'plant.local', 'Network Room', 'IT', 'IT Manager', 'Jane Doe', 'jane.doe@company.com', '+1-555-0124', '2023-01-01 00:00:00', '2026-01-01 00:00:00', '2024-01-01 00:00:00', '2024-07-01 00:00:00', 'CRITICAL', 95, 1, 'Current', 'UP_TO_DATE', 'MONITORED', true, true, '2024-01-20 10:30:00', '2023-01-01 08:00:00', '2024-01-20 10:30:00', '2024-01-20 10:30:00', 'admin', 'admin', 'Main firewall protecting plant network', '{"protocols": ["IPSec", "SSL VPN"], "ports": [443, 500]}'),

('550e8400-e29b-41d4-a716-446655440402', 'IDS-001', 'Intrusion detection system', '192.168.4.11', '00:1B:44:11:3A:BF', 'IDS_IPS', 'SECURITY_DEVICE', 'LEVEL_4', 'Snort', 'Snort IDS', 'SN456123789', 'V2.9.19', 'Linux', 'Ubuntu 20.04', 'ids-001', 'plant.local', 'Network Room', 'IT', 'IT Manager', 'Jane Doe', 'jane.doe@company.com', '+1-555-0124', '2023-02-01 00:00:00', '2026-02-01 00:00:00', '2024-02-01 00:00:00', '2024-08-01 00:00:00', 'HIGH', 85, 2, 'Current', 'UP_TO_DATE', 'MONITORED', true, true, '2024-01-20 10:30:00', '2023-02-01 08:00:00', '2024-01-20 10:30:00', '2024-01-20 10:30:00', 'admin', 'admin', 'Intrusion detection system for network monitoring', '{"protocols": ["Ethernet", "IP"], "ports": [22, 514]}'),

-- Level 5 - Enterprise
('550e8400-e29b-41d4-a716-446655440501', 'ROUTER-001', 'Enterprise router', '10.0.0.1', '00:1B:44:11:3A:C0', 'ROUTER', 'NETWORK_INFRASTRUCTURE', 'LEVEL_5', 'Cisco', 'ISR 4321', 'SN789456123', 'V16.9.6', 'Cisco IOS', 'V16.9.6', 'router-001', 'enterprise.local', 'Data Center', 'IT', 'IT Manager', 'Jane Doe', 'jane.doe@company.com', '+1-555-0124', '2023-01-01 00:00:00', '2026-01-01 00:00:00', '2024-01-01 00:00:00', '2024-07-01 00:00:00', 'HIGH', 80, 1, 'Current', 'UP_TO_DATE', 'MONITORED', true, true, '2024-01-20 10:30:00', '2023-01-01 08:00:00', '2024-01-20 10:30:00', '2024-01-20 10:30:00', 'admin', 'admin', 'Enterprise router for WAN connectivity', '{"protocols": ["BGP", "OSPF"], "ports": [179, 89]}'),

('550e8400-e29b-41d4-a716-446655440502', 'SWITCH-001', 'Core network switch', '10.0.0.2', '00:1B:44:11:3A:C1', 'SWITCH', 'NETWORK_INFRASTRUCTURE', 'LEVEL_5', 'Cisco', 'Catalyst 9300', 'SN321654987', 'V17.3.3', 'Cisco IOS', 'V17.3.3', 'switch-001', 'enterprise.local', 'Data Center', 'IT', 'IT Manager', 'Jane Doe', 'jane.doe@company.com', '+1-555-0124', '2023-02-01 00:00:00', '2026-02-01 00:00:00', '2024-02-01 00:00:00', '2024-08-01 00:00:00', 'HIGH', 75, 0, 'Current', 'UP_TO_DATE', 'MONITORED', true, true, '2024-01-20 10:30:00', '2023-02-01 08:00:00', '2024-01-20 10:30:00', '2024-01-20 10:30:00', 'admin', 'admin', 'Core network switch for enterprise network', '{"protocols": ["STP", "VLAN"], "ports": [1, 48]}');

-- Sample asset tags
INSERT INTO asset_tags (asset_id, tag) VALUES
('550e8400-e29b-41d4-a716-446655440101', 'production'),
('550e8400-e29b-41d4-a716-446655440101', 'critical'),
('550e8400-e29b-41d4-a716-446655440101', 'siemens'),
('550e8400-e29b-41d4-a716-446655440102', 'production'),
('550e8400-e29b-41d4-a716-446655440102', 'hmi'),
('550e8400-e29b-41d4-a716-446655440102', 'rockwell'),
('550e8400-e29b-41d4-a716-446655440103', 'tank-farm'),
('550e8400-e29b-41d4-a716-446655440103', 'schneider'),
('550e8400-e29b-41d4-a716-446655440201', 'scada'),
('550e8400-e29b-41d4-a716-446655440201', 'critical'),
('550e8400-e29b-41d4-a716-446655440201', 'siemens'),
('550e8400-e29b-41d4-a716-446655440202', 'historian'),
('550e8400-e29b-41d4-a716-446655440202', 'data-storage'),
('550e8400-e29b-41d4-a716-446655440202', 'osisoft'),
('550e8400-e29b-41d4-a716-446655440301', 'engineering'),
('550e8400-e29b-41d4-a716-446655440301', 'workstation'),
('550e8400-e29b-41d4-a716-446655440302', 'application'),
('550e8400-e29b-41d4-a716-446655440302', 'server'),
('550e8400-e29b-41d4-a716-446655440401', 'firewall'),
('550e8400-e29b-41d4-a716-446655440401', 'security'),
('550e8400-e29b-41d4-a716-446655440401', 'cisco'),
('550e8400-e29b-41d4-a716-446655440402', 'ids'),
('550e8400-e29b-41d4-a716-446655440402', 'security'),
('550e8400-e29b-41d4-a716-446655440402', 'snort'),
('550e8400-e29b-41d4-a716-446655440501', 'router'),
('550e8400-e29b-41d4-a716-446655440501', 'wan'),
('550e8400-e29b-41d4-a716-446655440501', 'cisco'),
('550e8400-e29b-41d4-a716-446655440502', 'switch'),
('550e8400-e29b-41d4-a716-446655440502', 'core'),
('550e8400-e29b-41d4-a716-446655440502', 'cisco');

-- Sample anomaly data for OT environment
INSERT INTO anomalies (id, title, description, anomaly_type, severity, status, source_ip, destination_ip, source_port, destination_port, protocol, asset_type, asset_category, purdue_level, manufacturer, model, hostname, location, department, evidence, mitigation_steps, recommendations, confidence_score, risk_score, false_positive_probability, mitre_tactic, mitre_technique, mitre_id, detected_at, resolved_at, acknowledged_at, escalated_at, created_at, updated_at, created_by, updated_by, assigned_to, resolved_by, notes, is_active, is_escalated, is_acknowledged, is_resolved, is_false_positive) VALUES
-- Critical Network Traffic Anomaly
('550e8400-e29b-41d4-a716-446655440001', 'Unauthorized Modbus TCP Communication', 'Detected unauthorized Modbus TCP communication from external IP to PLC', 'NETWORK_TRAFFIC', 'CRITICAL', 'DETECTED', '203.0.113.45', '192.168.1.10', 54321, 502, 'TCP', 'PLC', 'CONTROL_SYSTEM', 'LEVEL_0', 'Siemens', 'SIMATIC S7-1200', 'plc-001', 'Production Line 1', 'Operations', 'Packet capture shows Modbus TCP connection attempt from external IP 203.0.113.45 to PLC on port 502. Connection was blocked by firewall.', '1. Block IP 203.0.113.45 at firewall\n2. Review PLC access controls\n3. Enable Modbus TCP authentication', 'Implement network segmentation and access control lists for PLC communication', 95.5, 95.0, 5.0, 'Initial Access', 'T1071.001', 'T1071.001', '2024-01-20 14:30:00', NULL, NULL, NULL, '2024-01-20 14:30:00', '2024-01-20 14:30:00', 'OTShield', 'OTShield', NULL, NULL, 'Critical security incident requiring immediate attention', true, false, false, false, false),

-- High Severity Protocol Violation
('550e8400-e29b-41d4-a716-446655440002', 'IEC 60870-5-104 Protocol Violation', 'Detected malformed IEC 60870-5-104 packets from RTU', 'PROTOCOL_VIOLATION', 'HIGH', 'ACKNOWLEDGED', '192.168.1.12', '192.168.2.10', 2404, 2404, 'TCP', 'RTU', 'CONTROL_SYSTEM', 'LEVEL_0', 'Schneider Electric', 'Modicon M580', 'rtu-001', 'Tank Farm', 'Operations', 'Analysis of IEC 60870-5-104 packets shows malformed frame structure and invalid control field values. Multiple packets with same issue detected.', '1. Restart RTU communication service\n2. Check RTU firmware version\n3. Verify network connectivity', 'Update RTU firmware to latest version and implement protocol validation', 87.3, 85.0, 12.0, 'Execution', 'T1040', 'T1040', '2024-01-20 13:15:00', NULL, '2024-01-20 13:45:00', NULL, '2024-01-20 13:15:00', '2024-01-20 13:45:00', 'OTShield', 'OTShield', 'analyst@otshield.com', NULL, 'RTU communication issue affecting tank monitoring', true, false, true, false, false),

-- Medium Severity Behavioral Change
('550e8400-e29b-41d4-a716-446655440003', 'Unusual HMI Access Pattern', 'Detected unusual access pattern to HMI system outside normal hours', 'BEHAVIORAL_CHANGE', 'MEDIUM', 'INVESTIGATING', '192.168.3.10', '192.168.1.11', 44818, 44818, 'TCP', 'HMI', 'CONTROL_SYSTEM', 'LEVEL_1', 'Rockwell', 'PanelView Plus 7', 'hmi-001', 'Production Line 1', 'Operations', 'HMI access detected at 02:30 AM from engineering workstation. Normal access hours are 06:00-18:00. User authentication successful.', '1. Verify if this was authorized maintenance\n2. Review access logs for similar patterns\n3. Check if maintenance was scheduled', 'Implement time-based access controls for HMI systems', 78.9, 65.0, 20.0, 'Discovery', 'T1059.001', 'T1059.001', '2024-01-20 02:30:00', NULL, NULL, NULL, '2024-01-20 02:30:00', '2024-01-20 02:30:00', 'OTShield', 'OTShield', 'analyst@otshield.com', NULL, 'Suspicious access pattern - investigation required', true, false, false, false, false),

-- Low Severity Volume Anomaly
('550e8400-e29b-41d4-a716-446655440004', 'Increased Network Traffic Volume', 'Detected 150% increase in network traffic volume on SCADA network', 'VOLUME_ANOMALY', 'LOW', 'DETECTED', '192.168.2.0/24', '192.168.2.0/24', NULL, NULL, 'TCP/UDP', 'SCADA', 'CONTROL_SYSTEM', 'LEVEL_2', 'Siemens', 'WinCC V7.5', 'scada-001', 'Control Room', 'IT', 'Network traffic analysis shows significant increase in data volume on SCADA network segment. Traffic patterns indicate normal operation but higher than usual volume.', '1. Monitor traffic patterns for next 24 hours\n2. Check if any new devices were added\n3. Verify SCADA system performance', 'Implement traffic baselining and alerting for network volume changes', 65.2, 45.0, 30.0, 'Collection', 'T1040', 'T1040', '2024-01-20 11:20:00', NULL, NULL, NULL, '2024-01-20 11:20:00', '2024-01-20 11:20:00', 'OTShield', 'OTShield', NULL, NULL, 'Monitoring traffic patterns for potential issues', true, false, false, false, false),

-- Info Severity Timing Anomaly
('550e8400-e29b-41d4-a716-446655440005', 'Irregular Data Polling Interval', 'Detected irregular polling intervals from historian to RTU', 'TIMING_ANOMALY', 'INFO', 'RESOLVED', '192.168.2.11', '192.168.1.12', 4840, 2404, 'TCP', 'HISTORIAN', 'DATA_STORAGE', 'LEVEL_2', 'OSIsoft', 'PI Server', 'historian-001', 'Control Room', 'IT', 'Historian polling intervals varied from normal 5-second intervals to 3-7 second ranges. System performance was not affected.', '1. Restart historian polling service\n2. Check network latency\n3. Verify RTU response times', 'Implement polling interval monitoring and alerting', 55.8, 25.0, 40.0, 'Collection', 'T1040', 'T1040', '2024-01-20 09:45:00', '2024-01-20 10:15:00', '2024-01-20 10:00:00', NULL, '2024-01-20 09:45:00', '2024-01-20 10:15:00', 'OTShield', 'OTShield', 'analyst@otshield.com', 'analyst@otshield.com', 'Issue resolved - normal polling intervals restored', false, false, true, true, false),

-- High Severity Access Pattern Anomaly
('550e8400-e29b-41d4-a716-446655440006', 'Multiple Failed Authentication Attempts', 'Detected multiple failed authentication attempts to SCADA system', 'ACCESS_PATTERN', 'HIGH', 'ESCALATED', '192.168.3.10', '192.168.2.10', 3389, 3389, 'TCP', 'SCADA', 'CONTROL_SYSTEM', 'LEVEL_2', 'Siemens', 'WinCC V7.5', 'scada-001', 'Control Room', 'IT', '15 failed RDP authentication attempts detected from engineering workstation within 30 minutes. Account lockout threshold reached.', '1. Block source IP temporarily\n2. Reset user account password\n3. Review account lockout policies', 'Implement account lockout policies and monitoring for failed authentication attempts', 92.1, 88.0, 8.0, 'Credential Access', 'T1110.001', 'T1110.001', '2024-01-20 16:20:00', NULL, '2024-01-20 16:25:00', '2024-01-20 16:30:00', '2024-01-20 16:20:00', '2024-01-20 16:30:00', 'OTShield', 'OTShield', 'admin@otshield.com', NULL, 'Potential brute force attack - escalated to security team', true, true, true, false, false),

-- Medium Severity Communication Pattern Anomaly
('550e8400-e29b-41d4-a716-446655440007', 'Unusual OPC UA Communication', 'Detected unusual OPC UA communication patterns between historian and PLC', 'COMMUNICATION_PATTERN', 'MEDIUM', 'DETECTED', '192.168.2.11', '192.168.1.10', 4840, 4840, 'TCP', 'HISTORIAN', 'DATA_STORAGE', 'LEVEL_2', 'OSIsoft', 'PI Server', 'historian-001', 'Control Room', 'IT', 'OPC UA communication shows unusual read/write patterns with increased frequency and different data points than normal operation.', '1. Review OPC UA configuration\n2. Check historian data collection settings\n3. Verify PLC tag configuration', 'Implement OPC UA communication monitoring and anomaly detection', 82.4, 70.0, 15.0, 'Collection', 'T1040', 'T1040', '2024-01-20 15:10:00', NULL, NULL, NULL, '2024-01-20 15:10:00', '2024-01-20 15:10:00', 'OTShield', 'OTShield', NULL, NULL, 'Investigating OPC UA communication patterns', true, false, false, false, false),

-- Low Severity Protocol Anomaly
('550e8400-e29b-41d4-a716-446655440008', 'Unexpected HTTP Traffic on OT Network', 'Detected HTTP traffic on OT network segment where only industrial protocols are expected', 'PROTOCOL_ANOMALY', 'LOW', 'DETECTED', '192.168.1.15', '192.168.1.1', 80, 80, 'HTTP', 'UNKNOWN', 'UNKNOWN', 'LEVEL_0', 'Unknown', 'Unknown', 'unknown-device', 'Production Line 1', 'Operations', 'HTTP traffic detected on OT network segment. Source device not identified in asset inventory. Traffic appears to be web browsing activity.', '1. Identify source device\n2. Check if device should be on OT network\n3. Review network segmentation', 'Implement protocol filtering on OT network segments', 70.6, 50.0, 25.0, 'Discovery', 'T1040', 'T1040', '2024-01-20 12:05:00', NULL, NULL, NULL, '2024-01-20 12:05:00', '2024-01-20 12:05:00', 'OTShield', 'OTShield', NULL, NULL, 'Unknown device detected on OT network', true, false, false, false, false),

-- Critical Severity Payload Anomaly
('550e8400-e29b-41d4-a716-446655440009', 'Malicious Modbus Payload Detected', 'Detected Modbus payload containing potential malicious code patterns', 'PAYLOAD_ANOMALY', 'CRITICAL', 'DETECTED', '203.0.113.67', '192.168.1.10', 502, 502, 'TCP', 'PLC', 'CONTROL_SYSTEM', 'LEVEL_0', 'Siemens', 'SIMATIC S7-1200', 'plc-001', 'Production Line 1', 'Operations', 'Modbus TCP payload analysis revealed suspicious byte patterns consistent with known PLC exploitation techniques. Connection was blocked.', '1. Block source IP immediately\n2. Review PLC security settings\n3. Check for any unauthorized changes\n4. Implement additional security controls', 'Implement deep packet inspection for industrial protocols and PLC security hardening', 96.8, 98.0, 2.0, 'Execution', 'T1059.001', 'T1059.001', '2024-01-20 17:45:00', NULL, NULL, NULL, '2024-01-20 17:45:00', '2024-01-20 17:45:00', 'OTShield', 'OTShield', 'admin@otshield.com', NULL, 'Critical security incident - potential PLC attack attempt', true, false, false, false, false),

-- High Severity Frequency Anomaly
('550e8400-e29b-41d4-a716-446655440010', 'Excessive SCADA Polling Frequency', 'Detected excessive polling frequency from SCADA to multiple devices', 'FREQUENCY_ANOMALY', 'HIGH', 'INVESTIGATING', '192.168.2.10', '192.168.1.0/24', 4840, 4840, 'TCP', 'SCADA', 'CONTROL_SYSTEM', 'LEVEL_2', 'Siemens', 'WinCC V7.5', 'scada-001', 'Control Room', 'IT', 'SCADA system polling frequency increased from normal 1-second intervals to 100ms intervals. Affecting multiple devices and causing network congestion.', '1. Check SCADA system configuration\n2. Review polling settings\n3. Monitor system performance\n4. Check for software updates', 'Implement polling frequency monitoring and rate limiting', 89.2, 82.0, 10.0, 'Collection', 'T1040', 'T1040', '2024-01-20 18:30:00', NULL, NULL, NULL, '2024-01-20 18:30:00', '2024-01-20 18:30:00', 'OTShield', 'OTShield', 'analyst@otshield.com', NULL, 'SCADA system performance issue affecting network', true, false, false, false, false);

-- Sample anomaly tags
INSERT INTO anomaly_tags (anomaly_id, tag) VALUES
('550e8400-e29b-41d4-a716-446655440001', 'critical'),
('550e8400-e29b-41d4-a716-446655440001', 'network'),
('550e8400-e29b-41d4-a716-446655440001', 'modbus'),
('550e8400-e29b-41d4-a716-446655440001', 'external'),
('550e8400-e29b-41d4-a716-446655440002', 'protocol'),
('550e8400-e29b-41d4-a716-446655440002', 'iec'),
('550e8400-e29b-41d4-a716-446655440002', 'rtu'),
('550e8400-e29b-41d4-a716-446655440003', 'access'),
('550e8400-e29b-41d4-a716-446655440003', 'hmi'),
('550e8400-e29b-41d4-a716-446655440003', 'behavioral'),
('550e8400-e29b-41d4-a716-446655440004', 'volume'),
('550e8400-e29b-41d4-a716-446655440004', 'network'),
('550e8400-e29b-41d4-a716-446655440004', 'scada'),
('550e8400-e29b-41d4-a716-446655440005', 'timing'),
('550e8400-e29b-41d4-a716-446655440005', 'historian'),
('550e8400-e29b-41d4-a716-446655440005', 'polling'),
('550e8400-e29b-41d4-a716-446655440006', 'authentication'),
('550e8400-e29b-41d4-a716-446655440006', 'access'),
('550e8400-e29b-41d4-a716-446655440006', 'brute-force'),
('550e8400-e29b-41d4-a716-446655440007', 'opc'),
('550e8400-e29b-41d4-a716-446655440007', 'communication'),
('550e8400-e29b-41d4-a716-446655440007', 'historian'),
('550e8400-e29b-41d4-a716-446655440008', 'protocol'),
('550e8400-e29b-41d4-a716-446655440008', 'http'),
('550e8400-e29b-41d4-a716-446655440008', 'unknown-device'),
('550e8400-e29b-41d4-a716-446655440009', 'payload'),
('550e8400-e29b-41d4-a716-446655440009', 'malicious'),
('550e8400-e29b-41d4-a716-446655440009', 'modbus'),
('550e8400-e29b-41d4-a716-446655440009', 'critical'),
('550e8400-e29b-41d4-a716-446655440010', 'frequency'),
('550e8400-e29b-41d4-a716-446655440010', 'scada'),
('550e8400-e29b-41d4-a716-446655440010', 'polling');

-- Sample anomaly indicators
INSERT INTO anomaly_indicators (anomaly_id, indicator) VALUES
('550e8400-e29b-41d4-a716-446655440001', 'External IP attempting Modbus connection'),
('550e8400-e29b-41d4-a716-446655440001', 'Port 502 access from untrusted source'),
('550e8400-e29b-41d4-a716-446655440001', 'PLC communication attempt blocked'),
('550e8400-e29b-41d4-a716-446655440002', 'Malformed IEC 60870-5-104 frame'),
('550e8400-e29b-41d4-a716-446655440002', 'Invalid control field values'),
('550e8400-e29b-41d4-a716-446655440002', 'Multiple protocol violations detected'),
('550e8400-e29b-41d4-a716-446655440003', 'HMI access outside normal hours'),
('550e8400-e29b-41d4-a716-446655440003', 'Access from engineering workstation'),
('550e8400-e29b-41d4-a716-446655440003', 'Unusual time pattern detected'),
('550e8400-e29b-41d4-a716-446655440004', '150% increase in network traffic'),
('550e8400-e29b-41d4-a716-446655440004', 'SCADA network congestion'),
('550e8400-e29b-41d4-a716-446655440004', 'Higher than baseline traffic volume'),
('550e8400-e29b-41d4-a716-446655440005', 'Irregular polling intervals'),
('550e8400-e29b-41d4-a716-446655440005', '3-7 second interval variations'),
('550e8400-e29b-44d4-a716-446655440005', 'Historian polling service issue'),
('550e8400-e29b-41d4-a716-446655440006', '15 failed authentication attempts'),
('550e8400-e29b-41d4-a716-446655440006', 'Account lockout threshold reached'),
('550e8400-e29b-41d4-a716-446655440006', 'RDP brute force attempt'),
('550e8400-e29b-41d4-a716-446655440007', 'Unusual OPC UA read/write patterns'),
('550e8400-e29b-41d4-a716-446655440007', 'Increased communication frequency'),
('550e8400-e29b-41d4-a716-446655440007', 'Different data points accessed'),
('550e8400-e29b-41d4-a716-446655440008', 'HTTP traffic on OT network'),
('550e8400-e29b-41d4-a716-446655440008', 'Unknown device detected'),
('550e8400-e29b-41d4-a716-446655440008', 'Protocol violation on OT segment'),
('550e8400-e29b-41d4-a716-446655440009', 'Malicious Modbus payload patterns'),
('550e8400-e29b-41d4-a716-446655440009', 'Suspicious byte sequences'),
('550e8400-e29b-41d4-a716-446655440009', 'PLC exploitation attempt'),
('550e8400-e29b-41d4-a716-446655440010', 'Excessive polling frequency'),
('550e8400-e29b-41d4-a716-446655440010', '100ms polling intervals'),
('550e8400-e29b-41d4-a716-446655440010', 'Network congestion caused');

-- Sample blocking rules
INSERT INTO blocking_rules (enabled, protocol, attack_type_contains, min_severity, block_action) VALUES
(true, 'MODBUS', 'Exploit', 'LOW', true),
(true, 'S7COMM', 'Exploit', 'LOW', true),
(true, 'HTTP', 'Attack', 'MEDIUM', true),
(true, 'FTP', 'Brute Force', 'HIGH', true),
(true, 'SSH', 'Brute Force', 'HIGH', true),
(true, 'TELNET', 'Login Attempt', 'MEDIUM', true),
(true, 'SNMP', 'Community String', 'LOW', true),
(true, 'IEC104', 'Protocol Violation', 'MEDIUM', true);

-- Honeypot logs are NOT seeded here — they are produced live by Conpot
-- (Docker container in production, simulation thread in dev) and flow through
-- HoneypotLogService.saveLog which enriches each row with GeoIP lookup and
-- applies blocking rules. Seeding static 2024 rows would pollute the dashboard
-- with stale timestamps (Attack Log showed "825d ago"). Start Conpot from the
-- Conpot Decoy page to populate this table with live data.

-- Sample alert comments
INSERT INTO alert_comments (id, alert_id, comment_text, created_by, created_at) VALUES
('550e8400-e29b-41d4-a716-446655440011', '550e8400-e29b-41d4-a716-446655440001', 'Initial investigation started', 'analyst@otshield.com', '2024-01-20 10:30:00'),
('550e8400-e29b-41d4-a716-446655440012', '550e8400-e29b-41d4-a716-446655440001', 'Source IP blocked successfully', 'admin@otshield.com', '2024-01-20 10:35:00');

-- Sample alert escalations
INSERT INTO alert_escalations (id, alert_id, escalated_by, escalated_to, escalation_reason, escalated_at, status) VALUES
('550e8400-e29b-41d4-a716-446655440013', '550e8400-e29b-41d4-a716-446655440001', 'analyst@otshield.com', 'security-team@otshield.com', 'Critical external attack detected', '2024-01-20 10:40:00', 'ESCALATED');

-- Sample alert rules
INSERT INTO alert_rules (id, rule_name, rule_description, rule_type, conditions, actions, is_active, priority, created_by, created_at) VALUES
('550e8400-e29b-41d4-a716-446655440014', 'External Modbus Block', 'Block all external Modbus connections', 'BLOCKING', 'protocol=MODBUS AND source_ip NOT IN (192.168.0.0/16)', 'BLOCK_IP', true, 1, 'admin@otshield.com', '2024-01-20 09:00:00');

-- Sample alert notifications
INSERT INTO alert_notifications (id, alert_id, notification_type, recipient, message, sent_at, status) VALUES
('550e8400-e29b-41d4-a716-446655440015', '550e8400-e29b-41d4-a716-446655440001', 'EMAIL', 'security-team@otshield.com', 'Critical alert: External Modbus attack detected', '2024-01-20 10:25:00', 'SENT');

-- Sample NIS2 requirements
INSERT INTO nis2_requirements (id, requirement_code, title, description, category, priority, compliance_status, created_at) VALUES
('550e8400-e29b-41d4-a716-446655440016', 'NIS2-001', 'Network Security Monitoring', 'Implement continuous monitoring of network security', 'SECURITY', 'HIGH', 'IN_PROGRESS', '2024-01-20 08:00:00');

-- Sample NIS2 email notifications
INSERT INTO nis2_email_notifications (id, recipient, subject, message, sent_at, status) VALUES
('550e8400-e29b-41d4-a716-446655440017', 'compliance@otshield.com', 'NIS2 Compliance Update', 'Monthly compliance report available', '2024-01-20 09:00:00', 'SENT');

-- Sample NIS2 compliance reports
INSERT INTO nis2_compliance_reports (id, report_name, report_type, generated_by, generated_at, compliance_score, status) VALUES
('550e8400-e29b-41d4-a716-446655440018', 'Monthly NIS2 Compliance Report', 'MONTHLY', 'system@otshield.com', '2024-01-20 09:00:00', 85.5, 'COMPLETED');