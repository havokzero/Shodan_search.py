import shodan
import argparse
import json
import threading
import os
import time
from queue import Queue
from datetime import datetime
from requests.exceptions import RequestException, ConnectionError, Timeout

CONFIG_FILE = "config.json"

# Define search queries for known vulnerable systems, including SCADA, ICS, CMS, and forums
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
    "26": 'http.title:"vBulletin"'
}

def build_query(base_query, filters):
    query = base_query
    for key, value in filters.items():
        if value:
            query += f' {key}:"{value}"'
    return query

def fetch_results(api, query, page, results_queue):
    try:
        results = api.search(query, page=page)
        results_queue.put(results['matches'])
    except shodan.APIError as e:
        print(f'Shodan API Error on page {page}: {e}')
    except (RequestException, ConnectionError, Timeout) as e:
        print(f'Network error on page {page}: {e}')
    except Exception as e:
        print(f'Unexpected error on page {page}: {e}')

def save_config(api_key):
    try:
        with open(CONFIG_FILE, 'w') as file:
            json.dump({"api_key": api_key}, file)
        print(f'API key saved to {CONFIG_FILE}')
    except IOError as e:
        print(f'Error saving API key to config file: {e}')

def load_config():
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r') as file:
                config = json.load(file)
            return config.get("api_key")
        except IOError as e:
            print(f'Error loading config file: {e}')
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
        shodan_url = f"https://www.shodan.io/host/{ip_str}"
        if 'html' in result and '<img' in result['html']:
            image_url = "Image available"
        else:
            image_url = "No image"
        print(f'IP: {ip_str}')
        print(f'Port: {port}')
        print(f'Organization: {org}')
        print(f'OS: {os}')
        print(f'Shodan URL: {shodan_url}')
        print(f'Image: {image_url}')
        print('-' * 60)

def save_results_to_file(results_list, output_file):
    try:
        with open(output_file, 'w') as file:
            json.dump(results_list, file, indent=4)
        print(f'Results saved to {output_file}')
    except IOError as e:
        print(f'Error saving results to file: {e}')

def save_images(results_list, output_dir):
    os.makedirs(output_dir, exist_ok=True)
    for result in results_list:
        if 'html' in result and '<img' in result['html']:
            ip_str = result.get('ip_str', 'N/A')
            port = result.get('port', 'N/A')
            image_url = f"https://www.shodan.io/host/{ip_str}/image"
            image_path = os.path.join(output_dir, f"{ip_str}_{port}.png")
            try:
                response = requests.get(image_url, stream=True)
                if response.status_code == 200:
                    with open(image_path, 'wb') as file:
                        for chunk in response.iter_content(1024):
                            file.write(chunk)
                    print(f'Image saved to {image_path}')
                else:
                    print(f'Failed to save image for {ip_str}:{port}')
            except Exception as e:
                print(f'Error saving image for {ip_str}:{port}: {e}')

def main(page_limit=20, threads=10, filters={}):
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
            print(f'Invalid API key: {e}')
            return

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
            query = build_query(base_query, filters)
            query_name = base_query.split(":")[1].strip('"')
            date_str = datetime.now().strftime("%Y-%m-%d")
            output_file = f"{query_name}_{date_str}.json"
            image_dir = f"{query_name}_{date_str}_images"

            # Initialize the queue and threads
            results_queue = Queue()
            threads_list = []

            # Create and start threads
            for page in range(1, page_limit + 1):
                thread = threading.Thread(target=fetch_results, args=(api, query, page, results_queue))
                thread.start()
                threads_list.append(thread)
                time.sleep(1 / threads)  # Adjust delay to respect rate limits

            # Wait for all threads to finish
            for thread in threads_list:
                thread.join()

            # Collect results
            results_list = []
            while not results_queue.empty():
                results_list.extend(results_queue.get())

            # Print and save results
            print_results(results_list)
            save_results_to_file(results_list, output_file)
            save_images(results_list, image_dir)

    except shodan.APIError as e:
        print(f'Shodan API Error: {e}')
    except (RequestException, ConnectionError, Timeout) as e:
        print(f'Network error: {e}')
    except Exception as e:
        print(f'Unexpected error: {e}')

if __name__ == '__main__':
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
    }

    if args.update_key:
        update_config()
    else:
        main(args.pages, args.threads, filters)
                
