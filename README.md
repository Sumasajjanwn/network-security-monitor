# Network Security Monitoring Tool

A Python-based network security monitoring tool that scans TCP ports on a local or authorized host, identifies commonly used services, classifies detected services for review, and stores scan results in a log file.

## Features

* TCP port scanning using Python socket programming
* Open and closed port detection
* Common service identification
* Rule-based security risk classification
* Security alerts for detected open ports
* Scan summary with total, open, and closed ports
* Timestamped scan logging
* Command-line arguments for custom hosts and port ranges
* Port range validation
* Host resolution validation

## Technologies Used

* Python
* Socket Programming
* TCP/IP
* Command-Line Interface
* File Handling

## Project Structure

```text
network-security-monitor/
│
├── network_monitor.py
├── scan_log.txt
└── README.md
```

## How It Works

1. The user provides a target host and port range.
2. The program creates a TCP socket for each port.
3. It attempts to establish a connection using `connect_ex()`.
4. A successful connection indicates that the TCP port is open.
5. The tool maps commonly known ports to their associated services.
6. Detected services are classified for security review.
7. The scan summary is displayed in the terminal.
8. Results are stored in `scan_log.txt`.

## Running the Project

### Scan the default range

```powershell
python network_monitor.py
```

The default configuration scans:

```text
Host: 127.0.0.1
Ports: 1-100
```

### Scan a specific port

```powershell
python network_monitor.py --host 127.0.0.1 --start 8000 --end 8000
```

### Scan a port range

```powershell
python network_monitor.py --host 127.0.0.1 --start 1 --end 100
```

## Example

If an HTTP server is running on port 8000:

```text
[OPEN]   Port 8000
         Service: HTTP/Web Server

SCAN SUMMARY
-------------------------------------------------
Total Ports Scanned : 1
Open Ports          : 1
Closed Ports        : 0

Open Ports Detected:
Port 8000 -> HTTP/Web Server -> REVIEW - HTTP/Web Server

Security Alert:
Review unexpected open ports and running services.

Scan results saved to: scan_log.txt
```

## Logging

Each scan is recorded in `scan_log.txt` with:

* Scan timestamp
* Target host
* Detected open ports
* Identified services

## Security Note

This tool is intended for learning, testing, and defensive security monitoring.

Only scan systems and networks that you own or have explicit permission to test. An open port does not automatically mean that the service is vulnerable; it indicates that a service is accepting TCP connections and may require further security review.

## Limitations

* The tool currently performs TCP port scanning only.
* Service identification is based on common port mappings.
* It does not perform vulnerability exploitation.
* It does not replace professional VAPT tools.
* Risk classification is rule-based and does not confirm an actual vulnerability.

## Future Enhancements

* Banner grabbing for better service identification
* Configurable scan timeout
* CSV/JSON report generation
* Basic network monitoring dashboard
* Integration with vulnerability databases
* Additional security checks
* Improved service detection

## Author

**Sumalatha**

B.Tech Computer Science and Engineering
GITAM Bengaluru
