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

CONFIG_FILE = "config.json"

# Define search queries for known vulnerable systems, including SCADA, ICS, CMS, forums, VNC, RDP, specific IP addresses, and SS7 systems
SEARCH_QUERIES = {
    "1": 'os:"Windows XP"',
    "2": 'product:"MySQL"',
    "3": 'product:"Jenkins"',
    "4": 'title:"Webcam"',
    "5": 'product:"MongoDB"',
    "6": 'product:"Elasticsearch"',
    "7": 'title:"IP Camera"',
    "8": 'product:"Kibana"',
    "9": 'product:"Hadoop"',
    "10": 'title:"DVR Login"',
    "11": 'port:502 name:"Modbus"',
    "12": 'port:102 name:"Siemens S7"',
    "13": 'port:44818 name:"EtherNet/IP"',
    "14": 'port:47808 name:"BACnet"',
    "15": 'port:20000 name:"DNP3"',
    "16": 'product:"HP Printer"',
    "17": 'product:"vsftpd"',
    "18": 'port:23',
    "19": 'product:"Apache httpd"',
    "20": 'product:"Redis"',
    "21": 'product:"Oracle DB"',
    "22": 'http.title:"WordPress"',
    "23": 'http.title:"Joomla"',
    "24": 'http.title:"Drupal"',
    "25": 'http.title:"phpBB"',
    "26": 'http.title:"vBulletin"',
    "27": 'port:5900 product:VNC',
    "28": 'port:3389 product:Terminal Services',
    "29": 'product:"Siemens PLC"',
    "30": 'product:"D-Link Router"',
    "31": 'product:"MikroTik Router"',
    "32": 'product:"Netgear Router"',
    "33": 'product:"QNAP NAS"',
    "34": 'product:"VoIP Phone"',
    "35": 'ip:"SPECIFIC_IP"',  # Placeholder for specific IP search
    "36": 'port:2905 protocol:ss7'
}

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def build_query(base_query, filters, no_password=False, specific_ip=None, custom_query=None):
    if custom_query:
        return custom_query
    query = base_query
    if specific_ip:
        query = f'ip:"{specific_ip}"'
    else:
        for key, value in filters.items():
            if value:
                query += f' {key}:"{value}"'
        if no_password:
            if "VNC" in base_query:
                query += ' authentication disabled'
            elif "Terminal Services" in base_query:
                query += ' "authentication disabled"'
    return query

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

def save_config(api_key):
    try:
        with open(CONFIG_FILE, 'w') as file:
            json.dump({"api_key": api_key}, file)
        logging.info(f'API key saved to {CONFIG_FILE}')
    except IOError as e:
        logging.error(f'Error saving API key to config file: {e}')

def load_config():
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r') as file:
                config = json.load(file)
            return config.get("api_key")
        except IOError as e:
            logging.error(f'Error loading config file: {e}')
    return None

def update_config():
    api_key = input("Enter your Shodan API key: ").strip()
    save_config(api_key)

def print_results(results_list):
    for result in results_list:
        ip_str = result.get('ip_str', 'N/A')
        port = result.get('port', 'N/A')
        org = result.get('org', 'N/A')
        os = result.get('os', 'N/A')
        data = result.get('data', '')
        shodan_url = f"https://www.shodan.io/host/{ip_str}"
        if 'html' in result and '<img' in result['html']:
            image_url = "Image available"
        else:
            image_url = "No image"
        logging.info(f'IP: {ip_str}')
        logging.info(f'Port: {port}')
        logging.info(f'Organization: {org}')
        logging.info(f'OS: {os}')
        logging.info(f'Data: {data}')
        logging.info(f'Shodan URL: {shodan_url}')
        logging.info(f'Image: {image_url}')
        logging.info('-' * 60)

def save_results_to_file(results_list, output_file):
    try:
        with open(output_file, 'w') as file:
            json.dump(results_list, file, indent=4)
        logging.info(f'Results saved to {output_file}')
    except IOError as e:
        logging.error(f'Error saving results to file: {e}')

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
    parser.add.argument('--threads', type=int, default=10, help='Number of concurrent threads')
    parser.add.argument('--update-key', action='store_true', help='Update the Shodan API key')
    parser.add.argument('--city', help='Filter by city name')
    parser.add.argument('--country', help='Filter by 2-letter country code')
    parser.add.argument('--http-title', help='Filter by HTTP title')
    parser.add.argument('--net', help='Filter by network range or IP in CIDR notation')
    parser.add.argument('--org', help='Filter by organization name')
    parser.add.argument('--port', type=int, help='Filter by port number')
    parser.add.argument('--product', help='Filter by product name')
    parser.add.argument('--screenshot-label', help='Filter by screenshot label')
    parser.add.argument('--state', help='Filter by U.S. state')
    parser.add.argument('--asn', help='Filter by Autonomous System Number')
    parser.add.argument('--hostname', help='Filter by hostname')
    parser.add.argument('--before', help='Filter by time before Shodan last observed the device (YYYY-MM-DD)')
    parser.add.argument('--after', help='Filter by time after Shodan last observed the device (YYYY-MM-DD)')
    parser.add.argument('--no-password', action='store_true', help='Search for open VNC or RDP connections without password')
    parser.add.argument('--specific-ip', help='Search for a specific IP address')
    parser.add.argument('--output-dir', help='Specify a custom output directory for saving results', default="results")
    parser.add.argument('--use-stream', action='store_true', help='Enable Shodan Stream API for real-time data')
    parser.add.argument('--scan-ip', help='Create an on-demand scan for a specific IP address')
    parser.add.argument('--custom-query', help='Specify a custom Shodan search query')

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
