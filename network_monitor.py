import socket
import argparse
from datetime import datetime


# ============================================================
# COMMON TCP PORT -> SERVICE MAPPING
# ============================================================

COMMON_SERVICES = {
    20: "FTP Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    8000: "HTTP/Web Server",
    8080: "HTTP Proxy/Web Server"
}


# ============================================================
# RULE-BASED RISK CLASSIFICATION
# ============================================================

RISK_LEVELS = {
    21: "REVIEW - FTP",
    22: "REVIEW - SSH",
    23: "HIGH REVIEW - Telnet",
    25: "REVIEW - SMTP",
    53: "REVIEW - DNS",
    80: "REVIEW - HTTP",
    110: "REVIEW - POP3",
    143: "REVIEW - IMAP",
    443: "REVIEW - HTTPS",
    3306: "REVIEW - MySQL",
    5432: "REVIEW - PostgreSQL",
    6379: "REVIEW - Redis",
    8000: "REVIEW - HTTP/Web Server",
    8080: "REVIEW - HTTP Proxy/Web Server"
}


# ============================================================
# SCAN A SINGLE TCP PORT
# ============================================================

def scan_port(host, port, timeout=0.5):

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:

        result = sock.connect_ex((host, port))

        if result == 0:
            return True

        return False

    except socket.error:

        return False

    finally:

        sock.close()


# ============================================================
# GET SERVICE NAME
# ============================================================

def get_service_name(port):

    return COMMON_SERVICES.get(port, "Unknown Service")


# ============================================================
# GET RISK LEVEL
# ============================================================

def get_risk_level(port):

    return RISK_LEVELS.get(port, "REVIEW - Unknown Service")


# ============================================================
# WRITE SCAN RESULTS TO LOG FILE
# ============================================================

def write_log(host, open_ports):

    with open("scan_log.txt", "a") as log_file:

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        log_file.write("\n")
        log_file.write("=" * 65 + "\n")
        log_file.write(f"Scan Time: {timestamp}\n")
        log_file.write(f"Target: {host}\n")

        if open_ports:

            log_file.write("Open Ports:\n")

            for port, service, risk in open_ports:

                log_file.write(
                    f"Port {port} -> {service} -> {risk}\n"
                )

        else:

            log_file.write("No open TCP ports detected.\n")

        log_file.write("=" * 65 + "\n")


# ============================================================
# SCAN PORT RANGE
# ============================================================

def scan_ports(host, start_port, end_port):

    open_ports = []

    total_ports = end_port - start_port + 1
    closed_ports = 0

    print("\n" + "=" * 70)
    print("              NETWORK SECURITY MONITORING TOOL")
    print("=" * 70)

    print(f"Target       : {host}")
    print(f"Port Range   : {start_port}-{end_port}")
    print(f"Total Ports  : {total_ports}")

    print(
        "Started At   :",
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )

    print("-" * 70)

    # --------------------------------------------------------
    # PORT SCANNING
    # --------------------------------------------------------

    for port in range(start_port, end_port + 1):

        is_open = scan_port(host, port)

        if is_open:

            service = get_service_name(port)
            risk = get_risk_level(port)

            print(f"[OPEN]   Port {port}")
            print(f"         Service : {service}")
            print(f"         Risk    : {risk}")

            open_ports.append(
                (port, service, risk)
            )

        else:

            print(f"[CLOSED] Port {port}")

            closed_ports += 1

    # --------------------------------------------------------
    # SCAN SUMMARY
    # --------------------------------------------------------

    print("-" * 70)

    print("SCAN SUMMARY")
    print("-" * 70)

    print(f"Total Ports Scanned : {total_ports}")
    print(f"Open Ports          : {len(open_ports)}")
    print(f"Closed Ports        : {closed_ports}")

    # --------------------------------------------------------
    # OPEN PORT DETAILS
    # --------------------------------------------------------

    if open_ports:

        print("\nOpen Ports Detected:")

        for port, service, risk in open_ports:

            print(
                f"Port {port} -> {service} -> {risk}"
            )

        print("\nSecurity Alert:")
        print(
            "Review unexpected open ports and running services."
        )

    else:

        print("\nNo open TCP ports detected.")

    # --------------------------------------------------------
    # LOG RESULTS
    # --------------------------------------------------------

    write_log(host, open_ports)

    print("\nScan results saved to: scan_log.txt")

    print("=" * 70)

    return open_ports


# ============================================================
# MAIN PROGRAM
# ============================================================

def main():

    parser = argparse.ArgumentParser(
        description="Basic Network Security Monitoring Tool"
    )

    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Target host. Default: localhost"
    )

    parser.add_argument(
        "--start",
        type=int,
        default=1,
        help="Starting port. Default: 1"
    )

    parser.add_argument(
        "--end",
        type=int,
        default=100,
        help="Ending port. Default: 100"
    )

    args = parser.parse_args()

    # --------------------------------------------------------
    # VALIDATE PORT RANGE
    # --------------------------------------------------------

    if args.start < 1 or args.end > 65535:

        print(
            "Error: Port numbers must be between 1 and 65535."
        )

        return

    if args.start > args.end:

        print(
            "Error: Starting port must be smaller than ending port."
        )

        return

    # --------------------------------------------------------
    # VALIDATE HOST
    # --------------------------------------------------------

    try:

        socket.gethostbyname(args.host)

    except socket.gaierror:

        print(
            f"Error: Could not resolve host '{args.host}'."
        )

        return

    # --------------------------------------------------------
    # START SCAN
    # --------------------------------------------------------

    scan_ports(
        args.host,
        args.start,
        args.end
    )


# ============================================================
# PROGRAM ENTRY POINT
# ============================================================

if __name__ == "__main__":

    main()