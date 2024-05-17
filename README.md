this tool will ask you for the api key on the furst run then save it to a configuration file


you should run the tool with this command 

python3 shodan_search.py --pages 10 --threads 5

if you have the basic paid api access you have the ability ti obtain more results with this command

python3 shodan_search.py --pages 10 --threads 10




the tool will automatically save the output to a json file for easy reading.


to update the API key you can run this command 

python3 shodan_search.py --update-key
