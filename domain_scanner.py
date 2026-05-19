import requests
import concurrent.futures
import os
import sys
import argparse
import signal
import threading
from datetime import datetime
from urllib3.exceptions import InsecureRequestWarning
import time
import socket
import subprocess
import platform

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

shutdown_flag = False
found_buffer = []
buffer_lock = threading.Lock()
output_file_path = ""
results_table = []
table_lock = threading.Lock()


class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    RESET = '\033[0m'


def signal_handler(sig, frame):
    global shutdown_flag
    shutdown_flag = True
    flush_buffer()
    print(f"\n\n{Colors.RED}[!] CTRL+C detected, shutting down...{Colors.RESET}")


signal.signal(signal.SIGINT, signal_handler)


def flush_buffer():
    global found_buffer, output_file_path
    with buffer_lock:
        if found_buffer and output_file_path:
            with open(output_file_path, 'a') as f:
                for domain in found_buffer:
                    f.write(domain + '\n')
            found_buffer.clear()


def buffer_writer():
    while not shutdown_flag:
        time.sleep(30)
        flush_buffer()


def load_domains(filepath):
    with open(filepath, 'r') as f:
        return [line.strip() for line in f if line.strip()]


def get_domain_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except:
        return "N/A"


def ping_domain(ip):
    if ip == "N/A":
        return "N/A"
    try:
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        command = ['ping', param, '1', ip]
        result = subprocess.run(command, capture_output=True, text=True, timeout=3)
        if result.returncode == 0:
            output = result.stdout
            if 'time=' in output:
                time_part = output.split('time=')[-1].split()[0].replace('ms', '')
                return f"{time_part}ms"
            elif 'time<' in output:
                time_part = output.split('time<')[1].split()[0].replace('ms', '')
                return f"<{time_part}ms"
            return "OK"
        return "FAILED"
    except:
        return "TIMEOUT"


def test_port_443(domain, ip):
    results = {}

    if ip == "N/A":
        return {"http": "N/A", "https": "N/A", "ssl_valid": "N/A", "status_code": "N/A"}

    http_result = "CLOSED"
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex((ip, 443))
        sock.close()
        if result == 0:
            http_result = "OPEN"
    except:
        http_result = "ERROR"

    https_result = "FAILED"
    status_code = "N/A"
    try:
        url = f"https://{domain}"
        resp = requests.get(url, timeout=3, verify=False, allow_redirects=True)
        https_result = "SUCCESS"
        status_code = str(resp.status_code)
        resp.close()
    except requests.exceptions.SSLError:
        https_result = "SSL_ERROR"
    except requests.exceptions.ConnectTimeout:
        https_result = "TIMEOUT"
    except requests.exceptions.ConnectionError:
        https_result = "REFUSED"
    except:
        https_result = "FAILED"

    ssl_valid = "N/A"
    try:
        import ssl
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                ssl_valid = "VALID"
    except:
        ssl_valid = "INVALID"

    results["http"] = http_result
    results["https"] = https_result
    results["ssl_valid"] = ssl_valid
    results["status_code"] = status_code

    return results


def check_akamai(domain):
    global shutdown_flag, found_buffer

    if shutdown_flag:
        return (domain, False, "N/A", "N/A", {})

    ip = get_domain_ip(domain)
    ping = ping_domain(ip)
    port_results = test_port_443(domain, ip)

    url = f"http://{domain}"
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': '*/*',
        'Connection': 'close'
    }

    try:
        resp = requests.get(url, headers=headers, timeout=3, verify=False, allow_redirects=False, stream=True)

        server = resp.headers.get('Server', '')
        x_akamai = resp.headers.get('X-Akamai-Transformed', '')
        x_cache = resp.headers.get('X-Cache', '')
        x_check = resp.headers.get('X-Check-Cacheable', '')
        x_akamai2 = resp.headers.get('X-Akamai-Request-ID', '')

        if any('akamai' in h.lower() for h in [server, x_akamai, x_cache, x_check, x_akamai2] if h):
            with buffer_lock:
                found_buffer.append(domain)
            resp.close()
            return (domain, True, ip, ping, port_results)

        content = resp.raw.read(1500, decode_content=True)
        resp.close()

        if b'akamai' in content[:1500].lower():
            with buffer_lock:
                found_buffer.append(domain)
            return (domain, True, ip, ping, port_results)

    except:
        pass

    return (domain, False, ip, ping, port_results)


def format_time(seconds):
    if seconds < 60:
        return f"{seconds:.0f}s"
    elif seconds < 3600:
        mins = int(seconds // 60)
        secs = int(seconds % 60)
        return f"{mins}m {secs}s"
    else:
        hours = int(seconds // 3600)
        mins = int((seconds % 3600) // 60)
        return f"{hours}h {mins}m"


def print_results_table():
    global results_table

    if not results_table:
        print(f"\n{Colors.YELLOW}No Akamai domains found to display.{Colors.RESET}")
        return

    print(f"\n{Colors.CYAN}{'=' * 120}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.GREEN}RESULTS TABLE - AKAMAI DOMAINS{Colors.RESET}")
    print(f"{Colors.CYAN}{'=' * 120}{Colors.RESET}")

    header = f"{Colors.BOLD}{Colors.WHITE}{'Domain':<30} {'IP':<16} {'Ping':<12} {'Port 443':<12} {'HTTPS':<12} {'SSL':<10} {'Status':<10}{Colors.RESET}"
    print(header)
    print(f"{Colors.CYAN}{'-' * 120}{Colors.RESET}")

    for entry in results_table:
        domain = entry['domain']
        ip = entry['ip']
        ping = entry['ping']
        port_443 = entry['port_443']
        https = entry['https']
        ssl = entry['ssl_valid']
        status = entry['status_code']

        if ping != "N/A" and ping != "FAILED" and ping != "TIMEOUT":
            ping_color = Colors.GREEN
        else:
            ping_color = Colors.RED

        if port_443 == "OPEN":
            port_color = Colors.GREEN
        else:
            port_color = Colors.RED

        if https == "SUCCESS":
            https_color = Colors.GREEN
        elif https == "SSL_ERROR":
            https_color = Colors.YELLOW
        else:
            https_color = Colors.RED

        if ssl == "VALID":
            ssl_color = Colors.GREEN
        else:
            ssl_color = Colors.RED

        if status != "N/A":
            if status.startswith('2'):
                status_color = Colors.GREEN
            elif status.startswith('3'):
                status_color = Colors.YELLOW
            else:
                status_color = Colors.RED
        else:
            status_color = Colors.WHITE

        row = f"{Colors.WHITE}{domain:<30}{Colors.RESET} "
        row += f"{Colors.CYAN}{ip:<16}{Colors.RESET} "
        row += f"{ping_color}{ping:<12}{Colors.RESET} "
        row += f"{port_color}{port_443:<12}{Colors.RESET} "
        row += f"{https_color}{https:<12}{Colors.RESET} "
        row += f"{ssl_color}{ssl:<10}{Colors.RESET} "
        row += f"{status_color}{status:<10}{Colors.RESET}"

        print(row)

    print(f"{Colors.CYAN}{'=' * 120}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.GREEN}Total Akamai domains found: {len(results_table)}{Colors.RESET}\n")


def main():
    global output_file_path, results_table

    parser = argparse.ArgumentParser(description='Check domains for Akamai CDN')
    parser.add_argument('-i', '--input', default='domains.txt', help='Input file with domains (default: domains.txt)')
    parser.add_argument('-o', '--output', help='Output file name (saved in domain_result/ directory)')
    parser.add_argument('-w', '--workers', type=int, default=100, help='Number of concurrent workers (default: 100)')

    args = parser.parse_args()

    input_file = args.input

    if not os.path.exists(input_file):
        print(f"{Colors.RED}Error: {input_file} not found{Colors.RESET}")
        return

    domains = load_domains(input_file)
    total = len(domains)

    if total == 0:
        print(f"{Colors.RED}No domains found in file{Colors.RESET}")
        return

    os.makedirs('domain_result', exist_ok=True)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

    if args.output:
        output_file_path = f'domain_result/{args.output}'
    else:
        output_file_path = f'domain_result/akamai_domains_{timestamp}.txt'

    writer_thread = threading.Thread(target=buffer_writer, daemon=True)
    writer_thread.start()

    akamai_count = 0
    checked = 0
    start_time = time.time()
    last_update = 0

    print(f"{Colors.CYAN}Starting scan of {total} domains...{Colors.RESET}\n")

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
            future_to_domain = {executor.submit(check_akamai, domain): domain for domain in domains}

            for future in concurrent.futures.as_completed(future_to_domain):
                if shutdown_flag:
                    for f in future_to_domain:
                        f.cancel()
                    break

                domain, is_akamai, ip, ping, port_results = future.result()
                checked += 1

                if is_akamai:
                    akamai_count += 1
                    with table_lock:
                        results_table.append({
                            'domain': domain,
                            'ip': ip,
                            'ping': ping,
                            'port_443': port_results.get('http', 'N/A'),
                            'https': port_results.get('https', 'N/A'),
                            'ssl_valid': port_results.get('ssl_valid', 'N/A'),
                            'status_code': port_results.get('status_code', 'N/A')
                        })

                current_time = time.time()
                if current_time - last_update >= 1:
                    elapsed = current_time - start_time
                    if checked > 0:
                        eta = (elapsed / checked) * (total - checked)
                        percentage = (checked / total) * 100
                    else:
                        eta = 0
                        percentage = 0

                    sys.stdout.write(
                        f'\r{Colors.BLUE}{percentage:.1f}%{Colors.RESET} {Colors.WHITE}({checked}/{total}){Colors.RESET} {Colors.MAGENTA}| Elapsed: {format_time(elapsed)}{Colors.RESET} {Colors.CYAN}| ETA: {format_time(eta)}{Colors.RESET} {Colors.GREEN}| Found: {akamai_count}{Colors.RESET}')
                    sys.stdout.flush()
                    last_update = current_time
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}[!] Interrupted{Colors.RESET}")

    flush_buffer()
    total_time = time.time() - start_time
    print(
        f"\n\n{Colors.BOLD}{Colors.GREEN}Done: {akamai_count} Akamai domains out of {total} total{Colors.RESET} {Colors.CYAN}| Time: {format_time(total_time)}{Colors.RESET} {Colors.MAGENTA}| Saved: {output_file_path}{Colors.RESET}")

    print_results_table()


if __name__ == "__main__":
    main()