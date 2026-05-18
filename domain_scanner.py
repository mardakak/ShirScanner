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

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

shutdown_flag = False
found_buffer = []
buffer_lock = threading.Lock()
output_file_path = ""


def signal_handler(sig, frame):
    global shutdown_flag
    shutdown_flag = True
    flush_buffer()
    print("\n\n[!] CTRL+C detected, shutting down...")


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


def check_akamai(domain):
    global shutdown_flag, found_buffer

    if shutdown_flag:
        return (domain, False)

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
            return (domain, True)

        content = resp.raw.read(1500, decode_content=True)
        resp.close()

        if b'akamai' in content[:1500].lower():
            with buffer_lock:
                found_buffer.append(domain)
            return (domain, True)

    except:
        pass

    return (domain, False)


def spinning_cursor():
    while True:
        for cursor in '|/-\\':
            yield cursor


def format_time(seconds):
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        mins = int(seconds // 60)
        secs = seconds % 60
        return f"{mins}m {secs:.0f}s"
    else:
        hours = int(seconds // 3600)
        mins = int((seconds % 3600) // 60)
        return f"{hours}h {mins}m"


def main():
    global output_file_path

    parser = argparse.ArgumentParser(description='Check domains for Akamai CDN')
    parser.add_argument('-i', '--input', default='domains.txt', help='Input file with domains (default: domains.txt)')
    parser.add_argument('-o', '--output', help='Output file name (saved in domain_result/ directory)')
    parser.add_argument('-w', '--workers', type=int, default=100, help='Number of concurrent workers (default: 100)')

    args = parser.parse_args()

    input_file = args.input

    if not os.path.exists(input_file):
        print(f"Error: {input_file} not found")
        return

    domains = load_domains(input_file)
    total = len(domains)

    if total == 0:
        print("No domains found in file")
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
    spinner = spinning_cursor()
    start_time = time.time()

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
            future_to_domain = {executor.submit(check_akamai, domain): domain for domain in domains}

            for future in concurrent.futures.as_completed(future_to_domain):
                if shutdown_flag:
                    for f in future_to_domain:
                        f.cancel()
                    break

                domain, is_akamai = future.result()
                checked += 1

                if is_akamai:
                    akamai_count += 1

                elapsed = time.time() - start_time
                if checked > 0:
                    eta = (elapsed / checked) * (total - checked)
                else:
                    eta = 0

                progress = checked / total * 100
                bar_length = 40
                filled = int(bar_length * checked // total)
                bar = '█' * filled + '░' * (bar_length - filled)

                sys.stdout.write(
                    f'\r{next(spinner)} |{bar}| {progress:.1f}% ({checked}/{total}) | ETA: {format_time(eta)} | Found: {akamai_count}')
                sys.stdout.flush()
    except KeyboardInterrupt:
        print("\n[!] Interrupted")

    flush_buffer()
    total_time = time.time() - start_time
    print(
        f"\n\nDone: {akamai_count}/{total} Akamai domains | Time: {format_time(total_time)} | Saved: {output_file_path}")


if __name__ == "__main__":
    main()