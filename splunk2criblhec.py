from typing import List, Tuple, TypedDict
import csv, json, requests
import argparse

class KVPair(TypedDict):
    name: str
    value: str

class CriblToken:
    token: str
    description: str
    metadata: List[KVPair]
    FIELDS = ["token", "description", "metadata"]

    def __init__(self, **kwargs):
        for i in self.FIELDS:
            setattr(self, i, kwargs[i])

    def to_json(self):
        myjson = {}
        for i in self.FIELDS:
            myjson[i] = getattr(self, i)
        return myjson

class HecToken:
    title: str
    description: str
    token: str
    source: str
    sourcetype: str
    index: str
    indexes: str
    FIELDS = ["title", "description", "token", "source", "sourcetype", "index", "indexes"]

    def __init__(self, **kwargs):
        for i in self.FIELDS:
            if i == "indexes":
                kwargs[i] = kwargs[i].split(",")
            setattr(self, i, kwargs[i])

    def to_json(self):
        myjson = {}
        for i in self.FIELDS:
            myjson[i] = getattr(self, i)
        return myjson

def read_csv(csv_path: str) -> List[HecToken]:
    my_tokens = []
    tokens_csv = open(csv_path, encoding="utf-8")
    my_tokens = csv.DictReader(tokens_csv, delimiter=",", quotechar="\"")
    my_token_classes = []
    for dict_token in my_tokens:
        my_token_classes.append(HecToken(**dict_token))
    return my_token_classes

def js_exists(var: str):
    return '{0} !== "" && {0} !== undefined && {0} !== null'.format(var)

def convert_to_cribl(splunk_token: HecToken):
    indexes_statement = ""
    if splunk_token.indexes and splunk_token.indexes != "" and splunk_token.indexes is not None and splunk_token.indexes != [""]:
        indexes_statement = '(["' + '", "'.join(splunk_token.indexes) + '"].includes(index)) ? index : '
    index_eval = f'{indexes_statement}"{splunk_token.index}"'
    cribl_token = CriblToken(
        token=splunk_token.token,
        description=json.dumps({"message": "Imported from Splunk", "title": splunk_token.title, "description": splunk_token.description}),
        metadata=[
            {
                "name": "index",
                "value": index_eval
            }
        ]
    )
    if splunk_token.sourcetype and splunk_token.sourcetype != "" and splunk_token.sourcetype is not None:
        cribl_token.metadata.append({
            "name": "sourcetype",
            "value": f'({js_exists("sourcetype")}) ? sourcetype : "{splunk_token.sourcetype}"'
        })
    if splunk_token.source and splunk_token.source != "" and splunk_token.source is not None:
        cribl_token.metadata.append({
            "name": "source",
            "value": f'({js_exists("source")}) ? source : "{splunk_token.source}"'
        })
    return cribl_token

def get_cribl_auth_session(host: str, auth: Tuple[str, str]):
    sess = requests.session()
    sess.headers.update({"Accept": "application/json"})
    sess.headers.update({"Content-Type": "application/json"})
    response = sess.post(
        host + "/api/v1/auth/login",
        json={"username": auth[0], "password": auth[1]}
    )
    sess.headers.update({"Authorization": f"Bearer {response.json().get('token')}"})
    print("Authentication successful")
    return sess

def post_cribl_token(host: str, session: requests.Session, input_id: str, worker_group: str, cribl_token: CriblToken):
    response = session.post(
        host + f"/api/v1/m/{worker_group}/system/inputs/{input_id}/hectoken",
        json=cribl_token.to_json()
    )
    if response.status_code >= 400:
        print("\033[91m{}\033[00m".format(response.text))
        response.raise_for_status()
    return response.json()

def parser():
    parse = argparse.ArgumentParser()
    parse.add_argument('csv_path', help="path to csv file")
    parse.add_argument('host', help="On-prem Cribl host in format 'https://cribl.myhost'")
    parse.add_argument('username', help="Username to authenticate to Cribl with")
    parse.add_argument('password', help="Password to authenticate to Cribl with")
    parse.add_argument('--input-id', dest="input_id", help="Input ID without the colon prefix, so if your __inputId=='splunk_hec:in_splunk_hec', you would put 'in_splunk_hec'. Defaults to 'in_splunk_hec'.", default='in_splunk_hec', required=False)
    parse.add_argument('--worker-group', dest="worker_group", help="Worker group name to send to. Deafults to 'default'.", default='default', required=False)
    return parse

if __name__ == "__main__":
    args = parser().parse_args()

    csv_data = read_csv(args.csv_path)
    cribl_host = args.host
    my_session = get_cribl_auth_session(cribl_host, (args.username, args.password))
    for token in csv_data:
        print("Moving " + token.title)
        cribl_data = convert_to_cribl(token)
        details = post_cribl_token(
            cribl_host,
            my_session,
            args.input_id,
            args.worker_group,
            cribl_data
        )
