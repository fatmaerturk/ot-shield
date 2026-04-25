# PCAP Upload Troubleshooting Guide

## Problem
When trying to upload a PCAP file (sqli.pcap) on the dashboard, you get the error:
```
Selected file: sqli.pcap
Upload error: Server error
```

## Root Cause
The issue is likely caused by missing native libraries for the PCAP4J library, which is required for parsing PCAP files.

## Solutions

### 1. Added Missing Dependencies
I've added the missing PCAP4J native libraries to `backend/pom.xml`:

```xml
<!-- Native libraries for PCAP4J -->
<dependency>
    <groupId>org.pcap4j</groupId>
    <artifactId>pcap4j-native-windows-x86_64</artifactId>
    <version>1.8.2</version>
</dependency>
<dependency>
    <groupId>org.pcap4j</groupId>
    <artifactId>pcap4j-native-windows-i386</artifactId>
    <version>1.8.2</version>
</dependency>
```

### 2. Enhanced Error Handling
- Added better error logging in `FileController.java`
- Added file existence and readability checks in `PcapAnalysisService.java`
- Added support for both `.pcap` and `.pcapng` file formats

### 3. Added Health Check Endpoint
A new endpoint `/api/health/pcap` has been added to test if PCAP4J is working properly.

## Steps to Fix

### Step 1: Rebuild the Backend
```bash
cd backend
mvn clean compile
mvn spring-boot:run
```

### Step 2: Test PCAP4J Health
Visit `http://localhost:8080/api/health/pcap` to check if PCAP4J is working.

### Step 3: Check Backend Logs
Look for any error messages in the backend console when uploading a PCAP file.

### Step 4: Verify File Format
Ensure your PCAP file is in a valid format. The system now supports both `.pcap` and `.pcapng` files.

## Additional Debugging

### Check File Size
The system is configured to accept files up to 2GB. If your file is larger, you may need to increase the limit in `application.properties`:

```properties
spring.servlet.multipart.max-file-size=2GB
spring.servlet.multipart.max-request-size=2GB
```

### Check File Permissions
Ensure the upload directory (`backend/uploads/`) exists and is writable.

### Check Network Interface
If you're on Windows, you may need to install Npcap or WinPcap for PCAP4J to work properly.

## Common Issues

1. **PCAP4J Native Library Not Found**: This is the most common issue. The added dependencies should fix this.

2. **File Format Not Supported**: The system now supports both `.pcap` and `.pcapng` formats.

3. **File Too Large**: Check the file size and increase limits if necessary.

4. **Permission Issues**: Ensure the upload directory is writable.

## Testing

After making these changes, try uploading your PCAP file again. The system should now provide more detailed error messages if issues persist.

If you still encounter problems, check the backend console logs for specific error messages and refer to the PCAP4J documentation for additional troubleshooting steps. 