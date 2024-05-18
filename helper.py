import json
import os
import logging
from datetime import datetime

CONFIG_FILE = "config.json"

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

def build_query(base_query, filters, no_password=False, specific_ip=None, custom_query=None, has_image=False):
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
        if has_image:
            query += ' has_screenshot:true'
    return query

def print_results(results_list):
    formatted_results = []
    for result in results_list:
        ip_str = result.get('ip_str', 'N/A')
        port = result.get('port', 'N/A')
        org = result.get('org', 'N/A')
        os = result.get('os', 'N/A')
        data = result.get('data', '')
        shodan_url = f"https://www.shodan.io/host/{ip_str}"
        if result.get('opts', {}).get('screenshot'):
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

        formatted_result = {
            "IP": ip_str,
            "Port": port,
            "Organization": org,
            "OS": os,
            "Data": data,
            "Shodan URL": shodan_url,
            "Image": image_url
        }
        formatted_results.append(formatted_result)
    
    return formatted_results

def sanitize_filename(filename):
    """ Sanitize the filename by removing or replacing invalid characters and spaces. """
    return "_".join("".join(c if c.isalnum() or c in (' ', '_') else '' for c in filename).split())

def save_results_to_file(results_list, output_dir, query_name):
    date_str = datetime.now().strftime("%Y%m%d")
    sanitized_query_name = sanitize_filename(query_name)
    output_file = os.path.join(output_dir, f"{sanitized_query_name}_{date_str}.json")
    os.makedirs(output_dir, exist_ok=True)  # Ensure the output directory exists
    formatted_results = print_results(results_list)
    
    try:
        with open(output_file, 'w') as file:
            json.dump(formatted_results, file, indent=4)
        logging.info(f'Results saved to {output_file}')
    except IOError as e:
        logging.error(f'Error saving results to file: {e}')
