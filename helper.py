import json
import os
import logging

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
