#!/usr/bin/python3
import os
import logging
import secrets
import hmac
import hashlib
import base64
import sys
from decimal import *
import json

from flask import Flask, request, jsonify, abort, render_template
import requests

from database import db_session, init_db
from models import PaymentRequest

init_db()
logger = logging.getLogger(__name__)
app = Flask(__name__)

PRODUCTION = os.environ.get('PRODUCTION', '')
WINDCAVE_API_URL = 'https://sec.windcave.com/api/v1'
WINDCAVE_API_USER = os.environ.get('WINDCAVE_API_USER', '')
WINDCAVE_API_KEY = os.environ.get('WINDCAVE_API_KEY', '')
API_KEY = os.environ.get('API_KEY', '')
API_SECRET = os.environ.get('API_SECRET', '')
SITE_URL = os.environ.get('SITE_URL', '')
if not WINDCAVE_API_USER:
    print('ERROR: no windcave api user')
    sys.exit(1)
if not WINDCAVE_API_KEY:
    print('ERROR: no windcave api key')
    sys.exit(1)
if not API_KEY:
    print('ERROR: no api key')
    sys.exit(1)
if not API_SECRET:
    print('ERROR: no api secret')
    sys.exit(1)
if not SITE_URL:
    print('ERROR: no site url')
    sys.exit(1)

def setup_logging(level):
    # setup logging
    logger.setLevel(level)
    ch = logging.StreamHandler()
    ch.setLevel(level)
    ch.setFormatter(logging.Formatter('[%(name)s %(levelname)s] %(message)s'))
    logger.addHandler(ch)
    # clear loggers set by any imported modules
    logging.getLogger().handlers.clear()

def moneyfmt(value, places=2, curr='', sep=',', dp='.',
             pos='', neg='-', trailneg=''):
    """Convert Decimal to a money formatted string.

    places:  required number of places after the decimal point
    curr:    optional currency symbol before the sign (may be blank)
    sep:     optional grouping separator (comma, period, space, or blank)
    dp:      decimal point indicator (comma or period)
             only specify as blank when places is zero
    pos:     optional sign for positive numbers: '+', space or blank
    neg:     optional sign for negative numbers: '-', '(', space or blank
    trailneg:optional trailing minus indicator:  '-', ')', space or blank

    >>> d = Decimal('-1234567.8901')
    >>> moneyfmt(d, curr='$')
    '-$1,234,567.89'
    >>> moneyfmt(d, places=0, sep='.', dp='', neg='', trailneg='-')
    '1.234.568-'
    >>> moneyfmt(d, curr='$', neg='(', trailneg=')')
    '($1,234,567.89)'
    >>> moneyfmt(Decimal(123456789), sep=' ')
    '123 456 789.00'
    >>> moneyfmt(Decimal('-0.02'), neg='<', trailneg='>')
    '<0.02>'

    """
    q = Decimal(10) ** -places      # 2 places --> '0.01'
    sign, digits, exp = value.quantize(q).as_tuple()
    result = []
    digits = list(map(str, digits))
    build, next = result.append, digits.pop
    if sign:
        build(trailneg)
    for i in range(places):
        build(next() if digits else '0')
    if places:
        build(dp)
    if not digits:
        build('0')
    i = 0
    while digits:
        build(next())
        i += 1
        if i == 3 and digits:
            i = 0
            build(sep)
    build(curr)
    build(neg if sign else pos)
    return ''.join(reversed(result))

def auth_header():
    raw = bytearray(WINDCAVE_API_USER + ':' + WINDCAVE_API_KEY, 'utf-8')
    data = base64.b64encode(raw).decode('utf-8')
    return 'Basic ' + data

def create_session(amount, token):
    body = {'type': 'purchase', 'amount': moneyfmt(Decimal(amount), sep=''), 'currency': 'NZD', 'merchantReference': token}
    #body['methods'] = ['account2account']
    body['methods'] = ['card']
    callback_url = SITE_URL + '/request/' + token
    body['callbackUrls'] = {'approved': callback_url, 'declined': callback_url, 'cancelled': callback_url}
    body['notificationUrl'] = callback_url
    print(json.dumps(body))
    headers = {'Content-Type': 'application/json', 'Authorization': auth_header()}
    r = requests.post(WINDCAVE_API_URL + '/sessions', headers=headers, json=body)
    print(r.text)
    r.raise_for_status()
    if r.status_code == 202:
        jsn = r.json()
        return jsn['id'], jsn['state']
    return None, None

def get_session_status(windcave_session_id):
    headers = {'Authorization': auth_header()}
    r = requests.get(WINDCAVE_API_URL + '/sessions/' + windcave_session_id, headers=headers)
    print(r.text)
    r.raise_for_status()
    jsn = r.json()
    state = jsn['state']
    link = ""
    for ln_data in jsn['links']:
        if ln_data['method'] == 'REDIRECT':
            link = ln_data['href']
            break
    tx_state = None
    if 'transactions' in jsn:
        txs = jsn['transactions']
        if len(txs) > 0:
            tx_state = txs[0]['authorised'], txs[0]['allowRetry']
    return state, link, tx_state

def create_sig(api_secret, message):
    _hmac = hmac.new(api_secret.encode('latin-1'), msg=message, digestmod=hashlib.sha256)
    signature = _hmac.digest()
    signature = base64.b64encode(signature).decode("utf-8")
    return signature

def check_auth(api_key, sig, body):
    if api_key != API_KEY:
        return False
    our_sig = create_sig(API_SECRET, body)
    return sig == our_sig

@app.route('/')
def hello():
    if PRODUCTION:
        return 'payment svc'
    else:
        return 'payment svc (DEV MODE)'

@app.route('/request', methods=['POST'])
def request_create():
    sig = request.headers.get('X-Signature')
    content = request.json
    try:
        api_key = content['api_key']
    except:
        print('api_key not in request')
        abort(400)
    try:
        token = content['token']
    except:
        print('token not in request')
        abort(400)
    try:
        asset = content['asset']
    except:
        print('asset not in request')
        abort(400)
    try:
        amount = content['amount']
    except:
        print('amount not in request')
        abort(400)
    try:
        return_url = content['return_url']
    except:
        print('return_url not in request')
        abort(400)
    if asset != 'NZD':
        print('asset %s not supported' % asset)
        abort(400, 'asset (%s) not supported' % asset)
    if not check_auth(api_key, sig, request.data):
        print('auth failure')
        abort(400)
    req = PaymentRequest.from_token(db_session, token)
    if req:
        print('%s already exists' % token)
        abort(400)
    print("creating session with windcave")
    windcave_session_id, windcave_status = create_session(amount, token)
    if not windcave_session_id:
        abort(400)
    print("creating payment request object for %s" % token)
    req = PaymentRequest(token, asset, amount, windcave_session_id, windcave_status, return_url)
    db_session.add(req)
    db_session.commit()
    return jsonify(req.to_json())

@app.route('/status', methods=['POST'])
def status():
    content = request.json
    token = content['token']
    print("looking for %s" % token)
    req = PaymentRequest.from_token(db_session, token)
    if req:
        return jsonify(req.to_json())
    return abort(404)

@app.route('/request/<token>', methods=['GET'])
def request_action(token=None):
    CMP = 'completed'
    CND = 'cancelled'
    req = PaymentRequest.from_token(db_session, token)
    if not req:
        return abort(404, 'sorry, request not found')
    completed = req.status == CMP
    cancelled = req.status == CND
    windcave_url = ''
    # get status from windcave
    if not completed and not cancelled:
        state, windcave_url, tx_state = get_session_status(req.windcave_session_id)
        req.windcave_status = state
        if tx_state:
            if tx_state[0]:
                req.status = CMP
            elif not tx_state[1]:
                req.status = CND
            req.windcave_authorised = tx_state[0]
            req.windcave_allow_retry = tx_state[1]
        db_session.add(req)
        db_session.commit()
    completed = req.status == CMP
    cancelled = req.status == CND
    return render_template('request.html', production=PRODUCTION, token=token, completed=completed, cancelled=cancelled, req=req, windcave_url=windcave_url, return_url=req.return_url)

if __name__ == '__main__':
    setup_logging(logging.DEBUG)

    # Bind to PORT if defined, otherwise default to 5000.
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
