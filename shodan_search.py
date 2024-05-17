import shodan
import argparse
import json
import threading
import os
from queue import Queue
from datetime import datetime
from requests.exceptions import RequestException, ConnectionError, Timeout

CONFIG_FILE = "config.json"

# Define search queries for known vulnerable systems
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
}

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

def main(page_limit=1, threads=5):
    api_key = load_config()
    if not api_key:
        api_key = input("Enter your Shodan API key: ").strip()
        save_config(api_key)

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

            search_query = SEARCH_QUERIES[choice]
            query_name = search_query.split(":")[1].strip('"')
            date_str = datetime.now().strftime("%Y-%m-%d")
            output_file = f"{query_name}_{date_str}.json"

            # Initialize the queue and threads
            results_queue = Queue()
            threads_list = []

            # Create and start threads
            for page in range(1, page_limit + 1):
                thread = threading.Thread(target=fetch_results, args=(api, search_query, page, results_queue))
                thread.start()
                threads_list.append(thread)

            # Wait for all threads to finish
            for thread in threads_list:
                thread.join()

            # Collect results
            results_list = []
            while not results_queue.empty():
                results_list.extend(results_queue.get())

            # Print results
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

            # Save results to file
            if results_list:
                for result in results_list:
                    result['shodan_url'] = f"https://www.shodan.io/host/{result.get('ip_str', 'N/A')}"
                    result['image_url'] = image_url

                try:
                    with open(output_file, 'w') as file:
                        json.dump(results_list, file, indent=4)
                    print(f'Results saved to {output_file}')
                except IOError as e:
                    print(f'Error saving results to file: {e}')

    except shodan.APIError as e:
        print(f'Shodan API Error: {e}')
    except (RequestException, ConnectionError, Timeout) as e:
        print(f'Network error: {e}')
    except Exception as e:
        print(f'Unexpected error: {e}')

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Search Shodan for vulnerable systems and servers.')
    parser.add_argument('--pages', type=int, default=1, help='Number of pages to search')
    parser.add_argument('--threads', type=int, default=5, help='Number of concurrent threads')

    args = parser.parse_args()
    main(args.pages, args.threads)
