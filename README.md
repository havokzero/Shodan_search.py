this tool will ask you for the api key on the furst run then save it to a configuration file

you should run the tool with this command 

python3 shodan_search.py --pages 10 --threads 5

if you have the basic paid api access you have the ability ti obtain more results with this command

python3 shodan_search.py --pages 10 --threads 10

to urilize shodan filers all exept "vuln" and "tag" here is an example 

python3 shodan_search.py --pages 20 --threads 10 --city "San Diego" --country "US" --http-title "Hacked"


the tool will automatically save the output to a json file for easy reading.

to search for connections such as vnc or rdp woth no password you can run this command

python3 shodan_search.py --pages 20 --threads 10 --no-password

to update the API key you can run this command 

python3 shodan_search.py --update-key
