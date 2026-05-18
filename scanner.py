#!/usr/bin/env python3
import socket
import ipaddress
import concurrent.futures
import threading
import time
import sys
import os
import random
import ssl
from datetime import datetime, timedelta
import argparse


class Colors:
    RESET = '\033[0m'
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    CLEAR_LINE = '\033[2K'


class SimpleProgress:

    def __init__(self, total_ips):
        self.total_ips = total_ips
        self.scanned = 0
        self.open_ports = 0
        self.start_time = time.time()
        self.lock = threading.Lock()

    def update(self, count=1, open_found=0):
        with self.lock:
            self.scanned += count
            self.open_ports += open_found

    def get_stats(self):
        with self.lock:
            elapsed = time.time() - self.start_time
            progress = (self.scanned / self.total_ips) * 100 if self.total_ips > 0 else 0
            rate = self.scanned / elapsed if elapsed > 0 else 0
            remaining_ips = self.total_ips - self.scanned
            eta_seconds = remaining_ips / rate if rate > 0 else 0
            return self.scanned, self.open_ports, progress, rate, elapsed, eta_seconds


class PortScanner:

    def __init__(self, timeout=2, check_mode='tcp'):
        self.timeout = timeout
        self.check_mode = check_mode
        self.results = []
        self.results_lock = threading.Lock()

    def scan_port(self, ip, port=443):
        if self.check_mode == 'tcp':
            return self.tcp_connect(ip, port)
        elif self.check_mode == 'ssl':
            return self.ssl_handshake(ip, port)
        elif self.check_mode == 'http':
            return self.http_check(ip, port)
        elif self.check_mode == 'banner':
            return self.banner_grab(ip, port)
        elif self.check_mode == 'full':
            return self.full_check(ip, port)
        else:
            return self.tcp_connect(ip, port)

    def tcp_connect(self, ip, port=443):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((str(ip), port))
            sock.close()

            if result == 0:
                with self.results_lock:
                    self.results.append({'ip': str(ip), 'method': 'TCP', 'info': 'Port open'})
                return True, str(ip), 'TCP connect success'
            return False, None, None
        except Exception:
            return False, None, None

    def ssl_handshake(self, ip, port=443):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((str(ip), port))

            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            ssock = ctx.wrap_socket(sock, server_hostname=str(ip))
            cert = ssock.getpeercert()

            cert_info = {}
            if cert:
                for field in cert.get('subject', []):
                    for key, value in field:
                        if key == 'commonName':
                            cert_info['CN'] = value
                cert_info['issuer'] = dict(x[0] for x in cert.get('issuer', [])) if cert.get('issuer') else {}
                cert_info['notAfter'] = cert.get('notAfter', '')

            ssock.close()

            info = f"SSL: {cert_info.get('CN', 'N/A')}"
            with self.results_lock:
                self.results.append({'ip': str(ip), 'method': 'SSL', 'info': info})
            return True, str(ip), info
        except ssl.SSLError as e:
            with self.results_lock:
                self.results.append({'ip': str(ip), 'method': 'SSL', 'info': f'SSL Error: {str(e)[:50]}'})
            return True, str(ip), f'SSL Error: {str(e)[:50]}'
        except Exception:
            return False, None, None

    def http_check(self, ip, port=443):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)

            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ssock = ctx.wrap_socket(sock, server_hostname=str(ip))
            ssock.connect((str(ip), port))

            request = f"HEAD / HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
            ssock.send(request.encode())

            response = b""
            while True:
                try:
                    data = ssock.recv(4096)
                    if not data:
                        break
                    response += data
                except:
                    break

            ssock.close()

            response_str = response.decode('utf-8', errors='ignore')
            status_line = response_str.split('\r\n')[0] if response_str else 'No response'

            server_header = ''
            for line in response_str.split('\r\n'):
                if line.lower().startswith('server:'):
                    server_header = line.split(':', 1)[1].strip()
                    break

            info = f"HTTP: {status_line[:40]}"
            if server_header:
                info += f" | Server: {server_header}"

            with self.results_lock:
                self.results.append({'ip': str(ip), 'method': 'HTTP', 'info': info})
            return True, str(ip), info
        except Exception:
            return False, None, None

    def banner_grab(self, ip, port=443):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((str(ip), port))

            sock.settimeout(2)
            try:
                banner = sock.recv(1024)
                banner_str = banner.decode('utf-8', errors='ignore').strip()
            except:
                banner_str = "No banner"

            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ssock = ctx.wrap_socket(sock, server_hostname=str(ip))

            request = f"HEAD / HTTP/1.0\r\nHost: {ip}\r\n\r\n"
            ssock.send(request.encode())

            response = b""
            try:
                while True:
                    data = ssock.recv(4096)
                    if not data:
                        break
                    response += data
            except:
                pass

            ssock.close()

            response_str = response.decode('utf-8', errors='ignore')
            server_header = ''
            for line in response_str.split('\r\n'):
                if line.lower().startswith('server:'):
                    server_header = line.split(':', 1)[1].strip()
                    break

            info = f"Banner: {banner_str[:30]}"
            if server_header:
                info += f" | Server: {server_header}"

            with self.results_lock:
                self.results.append({'ip': str(ip), 'method': 'Banner', 'info': info})
            return True, str(ip), info
        except Exception:
            return False, None, None

    def full_check(self, ip, port=443):
        is_open, ip_str, tcp_info = self.tcp_connect(ip, port)
        if not is_open:
            return False, None, None

        _, _, ssl_info = self.ssl_handshake(ip, port)
        _, _, http_info = self.http_check(ip, port)

        info = f"TCP: OK | {ssl_info} | {http_info}"

        with self.results_lock:
            self.results[-1]['method'] = 'Full'
            self.results[-1]['info'] = info

        return True, str(ip), info


class ResultSaver:

    def __init__(self, results_dir="scan_results", check_mode='tcp'):
        self.results_dir = results_dir
        self.raw_file = None
        self.detailed_file = None
        self.check_mode = check_mode
        self.setup_files()
        self.lock = threading.Lock()
        self.saved_ips = set()

    def setup_files(self):
        if not os.path.exists(self.results_dir):
            os.makedirs(self.results_dir)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.raw_file = os.path.join(self.results_dir, f"found_ips_{timestamp}.txt")
        self.detailed_file = os.path.join(self.results_dir, f"detailed_{timestamp}.txt")

        with open(self.detailed_file, 'w') as f:
            f.write("=" * 80 + "\n")
            f.write("Port 443 Scan Results\n")
            f.write("=" * 80 + "\n\n")
            f.write(f"Scan started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Check mode: {self.check_mode.upper()}\n\n")
            f.write("-" * 80 + "\n")
            f.write(f"{'IP Address':<20} {'Method':<10} {'Info':<50}\n")
            f.write("-" * 80 + "\n")

    def append_result(self, ip, method, info):
        with self.lock:
            if ip not in self.saved_ips:
                self.saved_ips.add(ip)

                with open(self.raw_file, 'a') as f:
                    f.write(f"{ip}\n")

                with open(self.detailed_file, 'a') as f:
                    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    f.write(f"{ip:<20} {method:<10} {info:<50}\n")

    def finalize(self):
        with open(self.detailed_file, 'a') as f:
            f.write("-" * 80 + "\n")
            f.write(f"\nScan completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total found: {len(self.saved_ips)} IPs\n")


class IPScanner:

    def __init__(self, max_workers=100, timeout=2, order='random', check_mode='tcp'):
        self.max_workers = max_workers
        self.timeout = timeout
        self.order = order
        self.check_mode = check_mode
        self.scanner = PortScanner(timeout, check_mode)
        self.result_saver = ResultSaver(check_mode=check_mode)
        self.ranges = [
            "104.64.0.0/10",
            "23.32.0.0/11",
            "23.192.0.0/11",
            "23.0.0.0/12",
            "172.224.0.0/12",
            "2.16.0.0/13",
            "23.72.0.0/13",
            "172.232.0.0/13",
            "184.24.0.0/13",
            "23.64.0.0/14"
        ]

    def parse_targets_from_file(self, filepath):
        targets = []
        try:
            with open(filepath, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        if '/' in line:
                            targets.append(line)
                        else:
                            try:
                                ipaddress.ip_address(line)
                                targets.append(line)
                            except ValueError:
                                print(f"{Colors.YELLOW}Warning: Invalid IP/CIDR skipped: {line}{Colors.RESET}")
            return targets
        except FileNotFoundError:
            print(f"{Colors.RED}Error: File not found: {filepath}{Colors.RESET}")
            return []
        except Exception as e:
            print(f"{Colors.RED}Error reading file {filepath}: {e}{Colors.RESET}")
            return []

    def parse_mixed_targets(self, targets_list):
        parsed_targets = []
        for target in targets_list:
            target = target.strip()
            if not target:
                continue
            if '/' in target:
                parsed_targets.append(target)
            else:
                try:
                    ipaddress.ip_address(target)
                    parsed_targets.append(target)
                except ValueError:
                    print(f"{Colors.YELLOW}Warning: Invalid target skipped: {target}{Colors.RESET}")
        return parsed_targets

    def generate_ip_list_from_targets(self, targets):
        range_totals = {}
        all_ips = []

        for target in targets:
            try:
                if '/' in target:
                    network = ipaddress.ip_network(target, strict=False)
                    hosts = list(network.hosts())
                    range_totals[target] = len(hosts)
                    all_ips.extend(hosts)
                else:
                    ip = ipaddress.ip_address(target)
                    all_ips.append(ip)
                    range_totals[target] = 1
            except ValueError as e:
                print(f"{Colors.RED}Invalid target {target}: {e}{Colors.RESET}")

        return all_ips, range_totals

    def order_ip_list(self, ip_list):
        if self.order == 'random':
            random.shuffle(ip_list)
            return ip_list
        elif self.order == 'sequential':
            return sorted(ip_list)
        elif self.order == 'reverse':
            return sorted(ip_list, reverse=True)
        elif self.order == 'alternate':
            mid = len(ip_list) // 2
            first_half = ip_list[:mid]
            second_half = ip_list[mid:]
            result = []
            for i in range(max(len(first_half), len(second_half))):
                if i < len(second_half):
                    result.append(second_half[i])
                if i < len(first_half):
                    result.append(first_half[i])
            return result
        elif self.order == 'sparse':
            sorted_ips = sorted(ip_list)
            step = max(1, len(sorted_ips) // 100)
            result = []
            for i in range(step):
                result.extend(sorted_ips[i::step])
            return result
        elif self.order == 'dense':
            sorted_ips = sorted(ip_list)
            chunk_size = max(1, len(sorted_ips) // 10)
            result = []
            for i in range(0, len(sorted_ips), chunk_size):
                chunk = sorted_ips[i:i + chunk_size]
                random.shuffle(chunk)
                result.extend(chunk)
            return result
        elif self.order == 'incremental':
            sorted_ips = sorted(ip_list)
            result = []
            chunk_size = max(1, len(sorted_ips) // 10)
            for i in range(0, len(sorted_ips), chunk_size):
                result.extend(sorted_ips[i:i + chunk_size])
            return result
        elif self.order == 'decremental':
            sorted_ips = sorted(ip_list, reverse=True)
            result = []
            chunk_size = max(1, len(sorted_ips) // 10)
            for i in range(0, len(sorted_ips), chunk_size):
                result.extend(sorted_ips[i:i + chunk_size])
            return result
        elif self.order == 'roundrobin':
            sorted_ips = sorted(ip_list)
            num_chunks = 10
            chunk_size = len(sorted_ips) // num_chunks
            chunks = []
            for i in range(0, len(sorted_ips), chunk_size):
                chunks.append(sorted_ips[i:i + chunk_size])

            result = []
            max_len = max(len(chunk) for chunk in chunks) if chunks else 0
            for i in range(max_len):
                for chunk in chunks:
                    if i < len(chunk):
                        result.append(chunk[i])
            return result
        elif self.order == 'scanline':
            return sorted(ip_list)
        elif self.order == 'zigzag':
            sorted_ips = sorted(ip_list)
            result = []
            left, right = 0, len(sorted_ips) - 1
            toggle = True
            while left <= right:
                if toggle:
                    result.append(sorted_ips[left])
                    left += 1
                else:
                    result.append(sorted_ips[right])
                    right -= 1
                toggle = not toggle
            return result
        else:
            random.shuffle(ip_list)
            return ip_list

    def format_time(self, seconds):
        if seconds < 60:
            return f"{seconds:.0f}s"
        elif seconds < 3600:
            return f"{seconds / 60:.1f}m"
        else:
            hours = int(seconds / 3600)
            minutes = int((seconds % 3600) / 60)
            return f"{hours}h {minutes}m"

    def scan_port_and_save(self, ip):
        is_open, ip_str, info = self.scanner.scan_port(ip)
        if is_open:
            for result in self.scanner.results:
                if result['ip'] == ip_str:
                    self.result_saver.append_result(ip_str, result['method'], result.get('info', ''))
                    break
        return is_open

    def scan_range_streaming(self, targets):
        all_ips, range_totals = self.generate_ip_list_from_targets(targets)
        total_ips = len(all_ips)

        if total_ips == 0:
            print(f"{Colors.RED}No valid IPs to scan!{Colors.RESET}")
            return

        progress = SimpleProgress(total_ips)
        print(f"{Colors.YELLOW}Total IPs to scan: {total_ips:,}{Colors.RESET}")
        print(f"{Colors.YELLOW}Check mode: {self.check_mode.upper()}{Colors.RESET}")
        print(f"{Colors.YELLOW}Saving results to: {self.result_saver.raw_file}{Colors.RESET}\n")

        stop_event = threading.Event()

        def stats_printer():
            while not stop_event.is_set():
                scanned, open_ports, progress_pct, rate, elapsed, eta = progress.get_stats()

                elapsed_str = self.format_time(elapsed)
                eta_str = self.format_time(eta)

                sys.stdout.write(Colors.CLEAR_LINE)
                sys.stdout.write(f"\r{Colors.CYAN}Progress:{Colors.RESET} "
                                 f"{Colors.CYAN}{progress_pct:.1f}%{Colors.RESET} | "
                                 f"{Colors.BOLD}Scanned:{Colors.RESET} {scanned:,}/{total_ips:,} | "
                                 f"{Colors.GREEN}Found:{Colors.RESET} {open_ports} | "
                                 f"{Colors.YELLOW}Speed:{Colors.RESET} {rate:.1f}/s | "
                                 f"{Colors.CYAN}Running:{Colors.RESET} {elapsed_str} | "
                                 f"{Colors.CYAN}ETA:{Colors.RESET} {eta_str}")
                sys.stdout.flush()
                time.sleep(0.5)

        stats_thread = threading.Thread(target=stats_printer, daemon=True)
        stats_thread.start()

        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                futures = {}
                batch_size = self.max_workers * 2

                ordered_ips = self.order_ip_list(all_ips)
                ip_iterator = iter(ordered_ips)

                for _ in range(min(batch_size, total_ips)):
                    try:
                        ip = next(ip_iterator)
                        future = executor.submit(self.scan_port_and_save, ip)
                        futures[future] = ip
                    except StopIteration:
                        break

                while futures:
                    done_futures = []
                    for future in list(futures.keys()):
                        if future.done():
                            done_futures.append(future)

                    for future in done_futures:
                        try:
                            is_open = future.result()
                            progress.update(open_found=1 if is_open else 0)
                        except Exception:
                            progress.update()

                        del futures[future]

                        try:
                            new_ip = next(ip_iterator)
                            new_future = executor.submit(self.scan_port_and_save, new_ip)
                            futures[new_future] = new_ip
                        except StopIteration:
                            pass

                    if not futures:
                        break

                    time.sleep(0.001)

        finally:
            stop_event.set()
            stats_thread.join(timeout=1)
            sys.stdout.write(Colors.CLEAR_LINE)
            sys.stdout.write("\n")

        self.result_saver.finalize()
        self.display_final_stats(progress)
        return self.scanner.results

    def run_scan(self, custom_ranges=None, target_files=None):
        all_targets = []

        if target_files:
            for filepath in target_files:
                print(f"{Colors.CYAN}Loading targets from: {filepath}{Colors.RESET}")
                file_targets = self.parse_targets_from_file(filepath)
                all_targets.extend(file_targets)
                print(f"{Colors.GREEN}Loaded {len(file_targets)} targets from {filepath}{Colors.RESET}")

        if custom_ranges:
            all_targets.extend(custom_ranges)

        if not all_targets:
            all_targets = self.ranges

        scan_targets = self.parse_mixed_targets(all_targets)

        print(f"{Colors.BOLD}{Colors.CYAN}")
        print("╔════════════════════════════════════════════════╗")
        print("║     IP Range Port 443 Scanner - High Speed     ║")
        print("╚════════════════════════════════════════════════╝")
        print(f"{Colors.RESET}")
        print(f"{Colors.YELLOW}Total targets: {len(scan_targets)}{Colors.RESET}")
        print(f"{Colors.CYAN}Workers: {self.max_workers} | Timeout: {self.timeout}s{Colors.RESET}")
        print(f"{Colors.CYAN}Check mode: {self.check_mode.upper()} | Order: {self.order}{Colors.RESET}")
        print()

        return self.scan_range_streaming(scan_targets)

    def display_final_stats(self, progress):
        scanned, open_ports, _, rate, elapsed, _ = progress.get_stats()
        elapsed_str = self.format_time(elapsed)

        print(f"\n{Colors.BOLD}{'=' * 50}{Colors.RESET}")
        print(f"{Colors.CYAN}{Colors.BOLD}SCAN COMPLETED{Colors.RESET}")
        print(f"{Colors.BOLD}{'=' * 50}{Colors.RESET}")
        print(f"{Colors.YELLOW}Total Scanned:{Colors.RESET} {scanned:,} IPs")
        print(f"{Colors.GREEN}Open Ports Found:{Colors.RESET} {open_ports}")
        print(f"{Colors.CYAN}Total Time:{Colors.RESET} {elapsed_str}")
        print(f"{Colors.BOLD}Average Speed:{Colors.RESET} {rate:.1f} IPs/s")
        print(f"{Colors.CYAN}Check Mode:{Colors.RESET} {self.check_mode.upper()}")
        print(f"{Colors.CYAN}Results saved to:{Colors.RESET} {self.result_saver.raw_file}")


def main():
    parser = argparse.ArgumentParser(
        description='IP Range Port 443 Scanner with multiple check modes',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s
  %(prog)s -m ssl
  %(prog)s -m http -w 200
  %(prog)s -m banner -f targets.txt
  %(prog)s -m full -t 3

Check modes:
  tcp    - TCP connect only (fastest, default)
  ssl    - SSL/TLS handshake + certificate info
  http   - HTTP HEAD request + server header
  banner - Banner grab + HTTP response
  full   - All checks combined (slowest)
        """
    )

    parser.add_argument('-w', '--workers', type=int, default=100,
                        help='Number of worker threads (default: 100)')
    parser.add_argument('-t', '--timeout', type=float, default=2.0,
                        help='Connection timeout in seconds (default: 2.0)')
    parser.add_argument('-m', '--mode', type=str, default='tcp',
                        choices=['tcp', 'ssl', 'http', 'banner', 'full'],
                        help='Check mode (default: tcp)')
    parser.add_argument('-r', '--ranges', nargs='+',
                        help='Custom IP ranges to scan')
    parser.add_argument('-f', '--files', nargs='+',
                        help='Input files with targets')
    parser.add_argument('--order', type=str, default='random',
                        choices=['random', 'sequential', 'reverse', 'alternate',
                                 'sparse', 'dense', 'incremental', 'decremental',
                                 'roundrobin', 'scanline', 'zigzag'],
                        help='IP scanning order (default: random)')

    args = parser.parse_args()

    scanner = IPScanner(max_workers=args.workers, timeout=args.timeout,
                        order=args.order, check_mode=args.mode)

    try:
        scanner.run_scan(custom_ranges=args.ranges, target_files=args.files)

    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}Scan interrupted by user{Colors.RESET}")
        scanner.result_saver.finalize()
        sys.exit(1)
    except Exception as e:
        print(f"\n{Colors.RED}Error: {e}{Colors.RESET}")
        sys.exit(1)


if __name__ == "__main__":
    main()