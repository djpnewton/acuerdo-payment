#!/usr/bin/python3

import sys
import argparse
import requests
import time
import hmac
import hashlib
import base64
import json

URL_BASE = "http://localhost:5000/"

EXIT_NO_COMMAND = 1

def construct_parser():
    # construct argument parser
    parser = argparse.ArgumentParser()

    subparsers = parser.add_subparsers(dest="command")

    ## Account / Device creation

    parser_req_create = subparsers.add_parser("request_create", help="Create an request")
    parser_req_create.add_argument("api_key", metavar="API_KEY", type=str, help="the API key")
    parser_req_create.add_argument("api_secret", metavar="API_SECRET", type=str, help="the API secret")
    parser_req_create.add_argument("token", metavar="TOKEN", type=str, help="the request token")
    parser_req_create.add_argument("asset", metavar="ASSET", type=str, help="the request asset (NZD)")
    parser_req_create.add_argument("amount", metavar="AMOUNT", type=int, help="the request amount (in cents)")
    parser_req_create.add_argument("return_url", metavar="RETURN_URL", type=str, help="the return url")

    parser_req_status = subparsers.add_parser("request_status", help="Check a request request")
    parser_req_status.add_argument("api_key", metavar="API_KEY", type=str, help="the API key")
    parser_req_status.add_argument("api_secret", metavar="API_SECRET", type=str, help="the API secret")
    parser_req_status.add_argument("token", metavar="TOKEN", type=str, help="the request token")

    return parser

def create_sig(api_secret, message):
    _hmac = hmac.new(api_secret.encode('latin-1'), msg=message.encode('latin-1'), digestmod=hashlib.sha256)
    signature = _hmac.digest()
    signature = base64.b64encode(signature).decode("utf-8")
    return signature

def req(endpoint, params=None, api_key=None, api_secret=None):
    if api_key:
        if not params:
            params = {}
        params["nonce"] = int(time.time())
        params["api_key"] = api_key
    url = URL_BASE + endpoint
    if params:
        headers = {"Content-type": "application/json"}
        body = json.dumps(params)
        if api_key:
            headers["X-Signature"] = create_sig(api_secret, body)
        print("   POST - " + url)
        r = requests.post(url, headers=headers, data=body)
    else:
        print("   GET - " + url)
        r = requests.get(url)
    return r

def check_request_status(r):
    try:
        r.raise_for_status()
    except Exception as e:
        print("::ERROR::")
        print(str(r.status_code) + " - " + r.url)
        print(r.text)
        raise e

def request_create(args):
    print(":: calling request create..")
    r = req("request", {"token": args.token, "asset": args.asset, "amount": args.amount, "return_url": args.return_url}, args.api_key, args.api_secret)
    check_request_status(r)
    print(r.text)

def request_status(args):
    print(":: calling request status..")
    r = req("status", {"token": args.token}, args.api_key, args.api_secret)
    check_request_status(r)
    print(r.text)

if __name__ == "__main__":
    # parse arguments
    parser = construct_parser()
    args = parser.parse_args()

    # set appropriate function
    function = None
    if args.command == "request_create":
        function = request_create
    elif args.command == "request_status":
        function = request_status
    else:
        parser.print_help()
        sys.exit(EXIT_NO_COMMAND)

    if function:
        function(args)
