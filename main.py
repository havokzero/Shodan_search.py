import shodan
import argparse
import json
import threading
import os
import time
import logging
import requests
import signal
import sys
from queue import Queue
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from requests.exceptions import RequestException, ConnectionError, Timeout
from helper import save_config, load_config, update_config, build_query, print_results, save_results_to_file
from filters import FILTERS
from queries import SEARCH_QUERIES

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def fetch_results(api, query, page, results_queue):
    for attempt in range(3):
        try:
            results = api.search(query, page=page)
            results_queue.put(results['matches'])
            logging.info(f'Page {page} fetched successfully.')
            return
        except shodan.APIError as e:
            logging.error(f'Shodan API Error on page {page}: {e}')
            if e.code == 403:
                logging.error("Access denied (403 Forbidden). Check your API key permissions.")
                return
            if "usage limits" in str(e):
                time.sleep(60)  # Wait before retrying if rate limit is hit
        except (RequestException, ConnectionError, Timeout) as e:
            logging.error(f'Network error on page {page}: {e}')
        except Exception as e:
            logging.error(f'Unexpected error on page {page}: {e}')
        time.sleep(2 ** attempt)
    logging.error(f'Failed to fetch page {page} after 3 attempts.')

def save_images(results_list, output_dir):
    os.makedirs(output_dir, exist_ok=True)
    for result in results_list:
        if 'html' in result and '<img' in result['html']:
            ip_str = result.get('ip_str', 'N/A')
            port = result.get('port', 'N/A')
            image_url = f"https://www.shodan.io/host/{ip_str}/image"
            image_path = os.path.join(output_dir, f"{ip_str}_{port}.png")
            metadata_path = os.path.join(output_dir, f"{ip_str}_{port}.json")
            try:
                response = requests.get(image_url, stream=True)
                if response.status_code == 200:
                    with open(image_path, 'wb') as file:
                        for chunk in response.iter_content(1024):
                            file.write(chunk)
                    with open(metadata_path, 'w') as file:
                        json.dump(result, file, indent=4)
                    logging.info(f'Image and metadata saved for {ip_str}:{port}')
                else:
                    logging.error(f'Failed to save image for {ip_str}:{port} with status code {response.status_code}')
            except Exception as e:
                logging.error(f'Error saving image for {ip_str}:{port}: {e}')

def handle_stream(api_key, filters, output_dir):
    try:
        api = shodan.Shodan(api_key)
        stream = api.stream
        for banner in stream.banners():
            if all(f in banner.get('data', '') for f in filters.values() if f):
                ip_str = banner.get('ip_str', 'N/A')
                port = banner.get('port', 'N/A')
                org = banner.get('org', 'N/A')
                os = banner.get('os', 'N/A')
                shodan_url = f"https://www.shodan.io/host/{ip_str}"
                result = {
                    'ip_str': ip_str,
                    'port': port,
                    'org': org,
                    'os': os,
                    'shodan_url': shodan_url,
                    'banner': banner
                }
                print_results([result])
                date_str = datetime.now().strftime("%Y-%m-%d")
                output_file = os.path.join(output_dir, f"stream_{date_str}.json")
                save_results_to_file([result], output_file)
    except shodan.APIError as e:
        logging.error(f'Shodan Stream API Error: {e}')
    except Exception as e:
        logging.error(f'Unexpected error in stream: {e}')

def get_ip_info(api, ip):
    try:
        info = api.host(ip)
        return info
    except shodan.APIError as e:
        logging.error(f'Shodan API Error retrieving IP info: {e}')
        return None

def get_scans(api):
    try:
        scans = api.scans()
        return scans
    except shodan.APIError as e:
        logging.error(f'Shodan API Error retrieving scans: {e}')
        return None

def create_scan(api, ip):
    try:
        scan = api.scan(ip)
        return scan
    except shodan.APIError as e:
        logging.error(f'Shodan API Error creating scan: {e}')
        return None

def graceful_shutdown(signum, frame):
    logging.info("Graceful shutdown initiated...")
    sys.exit(0)

def main(page_limit=20, threads=10, filters={}, no_password=False, specific_ip=None, output_dir="results", use_stream=False, scan_ip=None, custom_query=None):
    api_key = load_config()
    if not api_key:
        update_config()
        api_key = load_config()

    try:
        # Initialize Shodan API
        api = shodan.Shodan(api_key)
        
        # Verify API key validity
        try:
            api.info()
        except shodan.APIError as e:
            logging.error(f'Invalid API key: {e}')
            return

        if use_stream:
            handle_stream(api_key, filters, output_dir)
            return

        if specific_ip:
            info = get_ip_info(api, specific_ip)
            if info:
                print_results([info])
                date_str = datetime.now().strftime("%Y-%m-%d")
                output_file = os.path.join(output_dir, f"{specific_ip}_{date_str}.json")
                save_results_to_file([info], output_file)
            return

        if scan_ip:
            scan = create_scan(api, scan_ip)
            if scan:
                logging.info(f'Scan created: {scan}')
            return

        if custom_query:
            query = custom_query
            query_name = "custom_query"
        else:
            while True:
                # Display options to the user
                print("Choose a system/server type to search for:")
                for key, query in SEARCH_QUERIES.items():
                    print(f"{key}. {query}")

                choice = input("Enter the number of your choice (or 'exit' to quit): ").strip()
                if choice.lower() == 'exit':
                    break

                if choice not in SEARCH_QUERIES:
                    print("Invalid choice. Please try again.")
                    continue

                base_query = SEARCH_QUERIES[choice]
                query = build_query(base_query, filters, no_password)
                query_name = base_query.split(":")[1].strip('"')
                break

        date_str = datetime.now().strftime("%Y-%m-%d")
        output_file = os.path.join(output_dir, f"{query_name}_{date_str}.json")
        image_dir = os.path.join(output_dir, f"{query_name}_{date_str}_images")

        # Initialize the queue and thread pool
        results_queue = Queue()

        with ThreadPoolExecutor(max_workers=threads) as executor:
            for page in range(1, page_limit + 1):
                executor.submit(fetch_results, api, query, page, results_queue)

        # Collect results
        results_list = []
        while not results_queue.empty():
            results_list.extend(results_queue.get())
            save_results_to_file(results_list, output_file)  # Save intermediate results

        # Print and save results
        print_results(results_list)
        save_results_to_file(results_list, output_file)
        save_images(results_list, image_dir)

    except shodan.APIError as e:
        logging.error(f'Shodan API Error: {e}')
    except (RequestException, ConnectionError, Timeout) as e:
        logging.error(f'Network error: {e}')
    except Exception as e:
        logging.error(f'Unexpected error: {e}')

if __name__ == '__main__':
    signal.signal(signal.SIGINT, graceful_shutdown)
    signal.signal(signal.SIGTERM, graceful_shutdown)

    parser = argparse.ArgumentParser(description='Search Shodan for vulnerable systems and servers.')
    parser.add_argument('--pages', type=int, default=20, help='Number of pages to search')
    parser.add_argument('--threads', type=int, default=10, help='Number of concurrent threads')
    parser.add_argument('--update-key', action='store_true', help='Update the Shodan API key')
    parser.add_argument('--city', help='Filter by city name')
    parser.add_argument('--country', help='Filter by 2-letter country code')
    parser.add_argument('--http-title', help='Filter by HTTP title')
    parser.add_argument('--net', help='Filter by network range or IP in CIDR notation')
    parser.add_argument('--org', help='Filter by organization name')
    parser.add_argument('--port', type=int, help='Filter by port number')
    parser.add_argument('--product', help='Filter by product name')
    parser.add_argument('--screenshot-label', help='Filter by screenshot label')
    parser.add_argument('--state', help='Filter by U.S. state')
    parser.add_argument('--asn', help='Filter by Autonomous System Number')
    parser.add_argument('--hostname', help='Filter by hostname')
    parser.add_argument('--before', help='Filter by time before Shodan last observed the device (YYYY-MM-DD)')
    parser.add_argument('--after', help='Filter by time after Shodan last observed the device (YYYY-MM-DD)')
    parser.add_argument('--no-password', action='store_true', help='Search for open VNC or RDP connections without password')
    parser.add_argument('--specific-ip', help='Search for a specific IP address')
    parser.add_argument('--output-dir', help='Specify a custom output directory for saving results', default="results")
    parser.add_argument('--use-stream', action='store_true', help='Enable Shodan Stream API for real-time data')
    parser.add_argument('--scan-ip', help='Create an on-demand scan for a specific IP address')
    parser.add_argument('--custom-query', help='Specify a custom Shodan search query')

    args = parser.parse_args()

    filters = {
        "city": args.city,
        "country": args.country,
        "http.title": args.http_title,
        "net": args.net,
        "org": args.org,
        "port": args.port,
        "product": args.product,
        "screenshot.label": args.screenshot_label,
        "state": args.state,
        "asn": args.asn,
        "hostname": args.hostname,
        "before": args.before,
        "after": args.after,
    }

    if args.update_key:
        update_config()
    else:
        main(args.pages, args.threads, filters, args.no_password, args.specific_ip, args.output_dir, args.use_stream, args.scan_ip, args.custom_query)
