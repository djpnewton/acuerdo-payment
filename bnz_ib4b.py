#!/usr/bin/env python3

import datetime
import re

# file format description: https://www.bnz.co.nz/assets/business-banking-help-support/internet-banking/ib4b-file-format-guide.pdf?v=3

def strip_account_number(num):
    return re.sub(r"[\s|-]+", "", num)

def hash_total_component(account_number):
    return int(account_number[2:13])

def hash_total_finalize(value):
    value = str(value)
    value = value[-11:]
    l = len(value)
    if l < 11:
        value = (11 - l) * "0" + value
    return value

def write_header_record(f, direct_debit_auth_code, sending_bank_account_number, due_date, creation_date):
    due_date = due_date.strftime("%y%m%d")
    creation_date = creation_date.strftime("%y%m%d")
    s = "1,%s,,,%s,6,%s,%s,I\n" % (direct_debit_auth_code, sending_bank_account_number, due_date, creation_date)
    s = "1,,,,%s,7,%s,%s,I\n" % (sending_bank_account_number, due_date, creation_date)
    f.write(s)

def write_transaction_record(f, account_number, amount_cents, sender_name, sender_ref, sender_code, receiver_name, receiver_ref, receiver_code):
    s = "2,%s,50,%d,%s,%s,%s,,,%s,%s,%s,\n" % (account_number, amount_cents, receiver_name, receiver_ref, receiver_code, sender_name, sender_code, sender_ref)
    f.write(s)

def write_footer_record(f, amount_total_cents, num_txs, hash_total):
    s = "3,%d,%d,%s\n" % (amount_total_cents, num_txs, hash_total)
    f.write(s)

def write_txs(f, direct_debit_auth_code, sending_bank_account_number, sender_name, txs):
    date = datetime.datetime.now()

    # write header
    sending_bank_account_number = strip_account_number(sending_bank_account_number)
    write_header_record(f, direct_debit_auth_code, sending_bank_account_number, date, date)
    # write txs
    count = 0
    amount_total_cents = 0
    hash_total = 0
    for tx in txs:
        account_number, amount_cents, sender_ref, sender_code, receiver_name, receiver_ref, receiver_code = tx
        account_number = strip_account_number(account_number)
        write_transaction_record(f, account_number, amount_cents, sender_name, sender_ref, sender_code, receiver_name, receiver_ref, receiver_code)
        amount_total_cents += amount_cents
        count += 1
        hash_total += hash_total_component(account_number)
    # write footer
    hash_total = hash_total_finalize(hash_total)
    write_footer_record(f, amount_total_cents, count, hash_total)

if __name__ == "__main__":
    txs = [("0201910003676004", 1050, "SENDER_REF1", "SENDER_CODE1", "CUST1", "CUST_REF1", "CUST_CODE1"), ("0201910003676004", 500, "SENDER_REF2", "SENDER_CODE2", "CUST2", "CUST_REF2", "CUST_CODE2")]
    with open("test.txt", "w") as f:
        write_txs(f, "", "0201910003676005", "test sender", txs)
