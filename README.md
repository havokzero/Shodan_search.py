# Shodan Search Tool

This tool allows you to perform comprehensive searches on Shodan using various filters. It retrieves results, saves them to JSON files, and handles images when available. The tool is designed to be flexible and user-friendly, accommodating multiple search options and configurations.

## Features

- **API Key Management:** Prompts for the Shodan API key on the first run and saves it to a configuration file for future use.
- **Multiple Filters:** Supports various Shodan filters (except `vuln` and `tag`) for targeted searches.
- **Parallel Processing:** Utilizes multiple threads to perform searches efficiently.
- **Result Handling:** Saves search results to JSON files and retrieves images when available.
- **Retry Logic:** Implements retry logic for network errors, making the script robust and reliable.
- **Continuous Search Loop:** Allows performing multiple searches in a single session without restarting the script.

## Installation

1. **Clone the repository:**
    ```bash
    git clone https://github.com/havokzero/Shodan_search.py.git
    cd Shodan_search.py
    ```

2. **Install the required dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

## Usage

### Basic Usage

On the first run, the tool will ask for your Shodan API key and save it to a configuration file. You can then run the tool using the following command:

```bash
python3 shodan_search.py --pages 10 --threads 5
```

Utilizing the Basic Paid API AccessIf you have the basic paid API access, you can obtain more results with a higher number of threads:

```bash
python3 shodan_search.py --pages 20 --threads 10
```

Using Shodan FiltersTo use Shodan filters (all except vuln and tag), you can run the tool with the desired filters. Here is an example:
```bash
python3 shodan_search.py --pages 20 --threads 10 --city "San Diego" --country "US" --http-title "Hacked"
```

Searching for Open VNC or RDP ConnectionsTo search for connections such as VNC or RDP with no password, use the following command:
```bash
python3 shodan_search.py --pages 20 --threads 10 --no-password
```

Updating the API KeyTo update the Shodan API key, run the following command:
```bash
python3 shodan_search.py --update-key
```

Examples:

Basic Search
```bash
python3 shodan_search.py --pages 10 --threads 5
```
Advanced Search with Filters:
```bash
python3 shodan_search.py --pages 20 --threads 10 --city "San Diego" --country "US" --http-title "Hacked"
```
Search for a Specific IP Address
```bash
python3 shodan_search.py --pages 1 --threads 1 --specific-ip "1.2.3.4"
```

Search for SS7 Systems
```bash
python3 shodan_search.py --pages 20 --threads 10 --port 2905 --protocol ss7
```


### Summary of Changes

1. **Script Updates:** 
    - Added functionality to search for SS7 systems by port and protocol.
    - Simplified the usage for specific IP address searches.
2. **README.md Updates:** 
    - Included instructions for the new functionalities.
    - Improved formatting and added examples for specific searches
