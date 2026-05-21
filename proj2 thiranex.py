import socket
from datetime import datetime

target = input("Enter target IP or website: ")

print("\nScanning started...")
print("Target:", target)

start_time = datetime.now()

common_ports = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    443: "HTTPS",
    3306: "MySQL"
}

report = []

for port, service in common_ports.items():
    scanner = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    scanner.settimeout(1)

    result = scanner.connect_ex((target, port))

    if result == 0:
        print(f"[OPEN] Port {port} : {service}")

        risk = "Low"

        if port == 21:
            risk = "Medium (FTP may transmit data insecurely)"
        elif port == 23:
            risk = "High (Telnet sends data in plain text)"
        elif port == 3306:
            risk = "Medium (Database exposed)"

        report.append(
            f"Port: {port} | Service: {service} | Risk: {risk}"
        )

    scanner.close()

end_time = datetime.now()

print("\n----- Vulnerability Report -----")

if report:
    for item in report:
        print(item)
else:
    print("No vulnerabilities detected.")

print("\nScan completed.")
print("Duration:", end_time - start_time)
