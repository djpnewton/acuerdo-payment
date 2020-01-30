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

    parser_payment_create = subparsers.add_parser("payment_create", help="Create a payment request")
    parser_payment_create.add_argument("api_key", metavar="API_KEY", type=str, help="the API key")
    parser_payment_create.add_argument("api_secret", metavar="API_SECRET", type=str, help="the API secret")
    parser_payment_create.add_argument("token", metavar="TOKEN", type=str, help="the request token")
    parser_payment_create.add_argument("asset", metavar="ASSET", type=str, help="the request asset (NZD)")
    parser_payment_create.add_argument("amount", metavar="AMOUNT", type=int, help="the request amount (in cents)")
    parser_payment_create.add_argument("return_url", metavar="RETURN_URL", type=str, help="the return url")

    parser_payment_status = subparsers.add_parser("payment_status", help="Check a payment request")
    parser_payment_status.add_argument("api_key", metavar="API_KEY", type=str, help="the API key")
    parser_payment_status.add_argument("api_secret", metavar="API_SECRET", type=str, help="the API secret")
    parser_payment_status.add_argument("token", metavar="TOKEN", type=str, help="the request token")

    parser_payout_create = subparsers.add_parser("payout_create", help="Create a payout request")
    parser_payout_create.add_argument("api_key", metavar="API_KEY", type=str, help="the API key")
    parser_payout_create.add_argument("api_secret", metavar="API_SECRET", type=str, help="the API secret")
    parser_payout_create.add_argument("token", metavar="TOKEN", type=str, help="the request token")
    parser_payout_create.add_argument("asset", metavar="ASSET", type=str, help="the request asset (NZD)")
    parser_payout_create.add_argument("amount", metavar="AMOUNT", type=int, help="the request amount (in cents)")
    parser_payout_create.add_argument("account_number", metavar="ACCOUNT_NUMBER", type=str, help="the request bank account number")
    parser_payout_create.add_argument("account_name", metavar="ACCOUNT_NAME", type=str, help="the request bank account name")
    parser_payout_create.add_argument("reference", metavar="REFERENCE", type=str, help="the request reference")
    parser_payout_create.add_argument("code", metavar="CODE", type=str, help="the request code")

    parser_payout_status = subparsers.add_parser("payout_status", help="Check a payout request")
    parser_payout_status.add_argument("api_key", metavar="API_KEY", type=str, help="the API key")
    parser_payout_status.add_argument("api_secret", metavar="API_SECRET", type=str, help="the API secret")
    parser_payout_status.add_argument("token", metavar="TOKEN", type=str, help="the request token")

    parser_payout_group_create = subparsers.add_parser("payout_group_create", help="Create a payout group and send the email")
    parser_payout_group_create.add_argument("api_key", metavar="API_KEY", type=str, help="the API key")
    parser_payout_group_create.add_argument("api_secret", metavar="API_SECRET", type=str, help="the API secret")

    parser_bankaccount_is_valid = subparsers.add_parser("bankaccount_is_valid", help="Check a bank account")
    parser_bankaccount_is_valid.add_argument("account", metavar="ACCOUNT", type=str, help="the bank account")

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

def payment_create(args):
    print(":: calling payment create..")
    r = req("payment_create", {"token": args.token, "asset": args.asset, "amount": args.amount, "return_url": args.return_url}, args.api_key, args.api_secret)
    check_request_status(r)
    print(r.text)

def payment_status(args):
    print(":: calling payment status..")
    r = req("payment_status", {"token": args.token}, args.api_key, args.api_secret)
    check_request_status(r)
    print(r.text)

def payout_create(args):
    print(":: calling payout create..")
    r = req("payout_create", {"token": args.token, "asset": args.asset, "amount": args.amount, "account_number": args.account_number, "account_name": args.account_name, "reference": args.reference, "code": args.code}, args.api_key, args.api_secret)
    check_request_status(r)
    print(r.text)

def payout_status(args):
    print(":: calling payout status..")
    r = req("payout_status", {"token": args.token}, args.api_key, args.api_secret)
    check_request_status(r)
    print(r.text)

def payout_group_create(args):
    print(":: calling payout group create..")
    r = req("payout_group_create", {}, args.api_key, args.api_secret)
    check_request_status(r)
    print(r.text)

def bankaccount_is_valid(args):
    print(":: calling bank account is valid..")
    r = req("bankaccount_is_valid", {"account": args.account}, None, None)
    check_request_status(r)
    print(r.text)

if __name__ == "__main__":
    # parse arguments
    parser = construct_parser()
    args = parser.parse_args()

    # set appropriate function
    function = None
    if args.command == "payment_create":
        function = payment_create
    elif args.command == "payment_status":
        function = payment_status
    if args.command == "payout_create":
        function = payout_create
    elif args.command == "payout_status":
        function = payout_status
    elif args.command == "payout_group_create":
        function = payout_group_create
    elif args.command == "bankaccount_is_valid":
        function = bankaccount_is_valid
    else:
        parser.print_help()
        sys.exit(EXIT_NO_COMMAND)

    if function:
        function(args)
