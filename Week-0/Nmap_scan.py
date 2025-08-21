import nmap
import datetime

def main():
    target = input("Please enter the target IP address: ")
    scanner = nmap.PortScanner()
    print(f"\n[+] Scanning target: {target}...")
    
    try:
        scanner.scan(target, arguments='-sS -sV')
        print("[+] Scan complete!")
        
    except nmap.PortScannerError:
        print("[-] Nmap not found. Please install it and ensure it's in your system's PATH.")
        return 

    report_file = "scan_report.txt"
    print(f"[+] Generating report: {report_file}...")

    with open(report_file, "w") as f:
        f.write("--- Nmap Scan Report ---\n\n")
        f.write(f"Scan performed at: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Target IP: {target}\n\n")

        if not scanner.all_hosts():
            f.write("No hosts found or host is down.\n")
        
        else:
            for host in scanner.all_hosts():
                f.write(f"Host: {host} ({scanner[host].hostname()})\n")
                f.write(f"State: {scanner[host].state()}\n\n")
                
                f.write("--- Open Ports and Services ---\n")
                f.write("{:<10} {:<10} {:<20} {}\n".format('PORT', 'STATE', 'SERVICE', 'VERSION'))

                for proto in scanner[host].all_protocols():
                    ports = scanner[host][proto].keys()
                    sorted_ports = sorted(ports)
                    
                    for port in sorted_ports:
                        state = scanner[host][proto][port]['state']
                        name = scanner[host][proto][port]['name']
                        version = scanner[host][proto][port]['version']
                        
                        f.write("{:<10} {:<10} {:<20} {}\n".format(port, state, name, version))
        f.write("\n--- Scan Complete ---\n")

    print("[+] Report saved successfully.")
