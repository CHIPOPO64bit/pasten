import json
import requests

SOL = json.load(open("user_conf.json", "r"))
ENDPOINT = "http://127.0.0.1:8080/upload"

def main():
    requests.post(ENDPOINT, json=SOL)

if __name__ == "__main__":
    main()