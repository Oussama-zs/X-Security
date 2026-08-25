# ==============================================================================
# X-SECURITY - Hybrid AI-Powered Vulnerability Scanner
# 
# Author: Oussama Elattaoui (GitHub: oussama-zs)
# Institution: Ecole des Sciences de l'Information (ESI), Rabat
# Project: Projet de Fin d'Annee (PFA) 2025/2026
# Company: CGX (Creative Generated Experience)
#
# This software is part of an academic project.
# Unauthorized copying, modification, or distribution without credit is prohibited.
# ==============================================================================

import sqlite3
import subprocess
import urllib.request
import pickle
import base64
import os
from flask import Flask, request, render_template_string

app = Flask(__name__)

# Setup a dummy database in memory
def init_db():
    conn = sqlite3.connect(':memory:', check_same_thread=False)
    conn.execute('CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)')
    conn.execute('INSERT INTO users (username, password) VALUES ("admin", "supersecret")')
    conn.commit()
    return conn

db_conn = init_db()

@app.route('/')
def home():
    return """
    <h1>Advanced Dummy Vulnerable App</h1>
    <ul>
        <li><a href="/search?q=test">Search (XSS)</a></li>
        <li><a href="/user?id=1">User Info (SQLi)</a></li>
        <li><a href="/ping?ip=127.0.0.1">Ping (Command Injection)</a></li>
        <li><a href="/read?file=app.py">Read File (Path Traversal/LFI)</a></li>
        <li><a href="/fetch?url=http://example.com">Fetch URL (SSRF)</a></li>
        <li><a href="/session?data=gASVJgAAAAAAAACMCF9fbWFpbl9flIwEVXNlcpSTlCmMWAUAAABhZG1pbpRSlC4=">Load Session (Deserialization)</a></li>
    </ul>
    """

# VULNERABILITY 1: Reflected Cross-Site Scripting (XSS)
@app.route('/search')
def search():
    query = request.args.get('q', '')
    html = f"<h2>Search Results for: {query}</h2><p>No results found.</p>"
    return render_template_string(html)

# VULNERABILITY 2: SQL Injection (SQLi)
@app.route('/user')
def get_user():
    user_id = request.args.get('id', '')
    query = f"SELECT username FROM users WHERE id = {user_id}"
    try:
        cursor = db_conn.cursor()
        cursor.execute(query)
        result = cursor.fetchall()
        if result:
            return f"User found: {result[0][0]}"
        return "User not found."
    except Exception as e:
        return f"Database Error: {e}", 500

# VULNERABILITY 3: OS Command Injection
@app.route('/ping')
def ping():
    ip = request.args.get('ip', '127.0.0.1')
    # DANGEROUS: Passing user input directly to shell=True
    command = f"ping -n 1 {ip}"
    try:
        output = subprocess.check_output(command, shell=True, text=True)
        return f"<pre>{output}</pre>"
    except Exception as e:
        return f"Command failed: {e}", 500

# VULNERABILITY 4: Path Traversal / LFI
@app.route('/read')
def read_file():
    filename = request.args.get('file', '')
    # DANGEROUS: No sanitization of file path (allows reading outside directory)
    try:
        with open(filename, 'r') as f:
            content = f.read()
        return f"<pre>{content}</pre>"
    except Exception as e:
        return f"File Error: {e}", 500

# VULNERABILITY 5: Server-Side Request Forgery (SSRF)
@app.route('/fetch')
def fetch_url():
    url = request.args.get('url', '')
    # DANGEROUS: Fetching arbitrary URL requested by user
    try:
        response = urllib.request.urlopen(url)
        return response.read()
    except Exception as e:
        return f"Network Error: {e}", 500

# VULNERABILITY 6: Insecure Deserialization (Pickle)
@app.route('/session')
def load_session():
    data = request.args.get('data', '')
    # DANGEROUS: Deserializing untrusted data
    try:
        decoded = base64.b64decode(data)
        obj = pickle.loads(decoded)
        return f"Session loaded for object type: {type(obj)}"
    except Exception as e:
        return f"Deserialization Error: {e}", 500

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=False)
