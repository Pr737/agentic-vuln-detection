"""
A small benchmark: short Python snippets with KNOWN vulnerabilities (the "answer key").
"expected" lists the CWE ids a correct detector should report. Safe snippets have an empty list.
These snippets are only ever read as text; they are never executed.
"""

SAMPLES = [
    {"name": "sqli_login", "expected": ["CWE-89"], "code": '''
def get_user(conn, username):
    query = f"SELECT * FROM users WHERE name = '{username}'"
    cur = conn.cursor()
    cur.execute(query)
    return cur.fetchone()
'''},
    {"name": "cmd_injection_ping", "expected": ["CWE-78"], "code": '''
import os

def ping_host(host):
    os.system("ping -c 1 " + host)
'''},
    {"name": "eval_calculator", "expected": ["CWE-95"], "code": '''
def calculate(user_expression):
    result = eval(user_expression)
    return result
'''},
    {"name": "pickle_load", "expected": ["CWE-502"], "code": '''
import pickle

def load_session(request_body):
    data = pickle.loads(request_body)
    return data
'''},
    {"name": "hardcoded_secret", "expected": ["CWE-798"], "code": '''
import requests

API_KEY = "sk-live-9f8e7d6c5b4a"

def fetch_orders():
    headers = {"Authorization": "Bearer " + API_KEY}
    return requests.get("https://api.example.com/orders", headers=headers).json()
'''},
    {"name": "weak_hash", "expected": ["CWE-327"], "code": '''
import hashlib

def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()
'''},
    {"name": "tls_disabled", "expected": ["CWE-295"], "code": '''
import requests

def download(url):
    response = requests.get(url, verify=False)
    return response.text
'''},
    {"name": "path_traversal", "expected": ["CWE-22"], "code": '''
def read_report(filename):
    with open("/var/reports/" + filename) as f:
        return f.read()
'''},
    {"name": "yaml_load", "expected": ["CWE-502"], "code": '''
import yaml

def parse_config(text):
    return yaml.load(text)
'''},
    {"name": "xss_greeting", "expected": ["CWE-79"], "code": '''
from flask import Flask, request

app = Flask(__name__)

@app.route("/hello")
def hello():
    name = request.args.get("name", "")
    return f"<h1>Hello {name}</h1>"
'''},
    {"name": "insecure_random_token", "expected": ["CWE-338"], "code": '''
import random

def make_reset_token():
    token = str(random.randint(100000, 999999))
    return token
'''},
    {"name": "flask_debug", "expected": ["CWE-489"], "code": '''
from flask import Flask

app = Flask(__name__)

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")
'''},
    {"name": "multi_vuln_account", "expected": ["CWE-89", "CWE-327", "CWE-798"], "code": '''
import hashlib

DB_PASSWORD = "root1234"

def create_user(conn, name, password):
    digest = hashlib.md5(password.encode()).hexdigest()
    sql = "INSERT INTO users (name, pw) VALUES ('%s', '%s')" % (name, digest)
    conn.cursor().execute(sql)
'''},
    # ---- safe code: a good detector should report nothing ----
    {"name": "safe_query_and_hash", "expected": [], "code": '''
import hashlib
import secrets

def get_user(conn, username):
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name = ?", (username,))
    return cur.fetchone()

def make_token():
    return secrets.token_urlsafe(32)

def fingerprint(data):
    return hashlib.sha256(data).hexdigest()
'''},
    {"name": "safe_subprocess", "expected": [], "code": '''
import subprocess

def ping_host(host):
    return subprocess.run(["ping", "-c", "1", host], check=True, capture_output=True, text=True)
'''},
    {"name": "safe_file_read", "expected": [], "code": '''
import os

BASE_DIR = "/var/reports"

def read_report(filename):
    safe_name = os.path.basename(filename)
    with open(os.path.join(BASE_DIR, safe_name)) as f:
        return f.read()
'''},

    # ---- HARD tier: patterns the simple rule scanner is NOT written for ----
    {"name": "sqli_multiline", "expected": ["CWE-89"], "tier": "hard", "code": '''
def find_orders(conn, customer_id):
    query = "SELECT * FROM orders WHERE customer_id = "
    query += customer_id
    return conn.cursor().execute(query).fetchall()
'''},
    {"name": "ssrf_proxy", "expected": ["CWE-918"], "tier": "hard", "code": '''
import requests
from flask import request

def proxy():
    url = request.args.get("url")
    return requests.get(url, timeout=5).text
'''},
    {"name": "open_redirect", "expected": ["CWE-601"], "tier": "hard", "code": '''
from flask import request, redirect

def login_done():
    return redirect(request.args.get("next"))
'''},
    {"name": "des_ecb_encrypt", "expected": ["CWE-327"], "tier": "hard", "code": '''
from Crypto.Cipher import DES

def encrypt(key, data):
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.encrypt(data)
'''},
    {"name": "insecure_tempfile", "expected": ["CWE-377"], "tier": "hard", "code": '''
import tempfile

def make_scratch():
    path = tempfile.mktemp()
    return open(path, "w")
'''},
    {"name": "creds_in_connection_string", "expected": ["CWE-798"], "tier": "hard", "code": '''
import psycopg2

def connect():
    return psycopg2.connect("postgres://admin:hunter2@db.internal/prod")
'''},
    {"name": "missing_authorization", "expected": ["CWE-862"], "tier": "hard", "code": '''
from flask import Flask, request

app = Flask(__name__)

@app.route("/admin/delete_user", methods=["POST"])
def delete_user():
    user_id = request.form["user_id"]
    db.delete_user(user_id)
    return "deleted"
'''},
]

for s in SAMPLES:
    s.setdefault("tier", "easy")
    s["code"] = s["code"].strip("\n") + "\n"
