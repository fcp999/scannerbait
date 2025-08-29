from flask import Flask, request
import logging
from datetime import datetime

app = Flask(__name__)
log = logging.getLogger('werkzeug')
log.setLevel(logging.INFO)

# Log everything to a file
handler = logging.FileHandler('honeypot.log')
handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(message)s')
handler.setFormatter(formatter)
log.addHandler(handler)

# --- Fake endpoints ---
@app.route('/')
def index():
    log.info("[+] GET / - home page accessed")
    return "Welcome to Bank of Florida", 200

@app.route('/admin/login.asp')
@app.route('/wp-login.php')
@app.route('/xmlrpc.php')
@app.route('/api', methods=["GET", "POST"])
@app.route('/phpinfo.php')
@app.route('/stats')
@app.route('/version')
@app.route('/openapi/v2')
@app.route('/containers/json')
@app.route('/.env')
@app.route('/.git/config')
@app.route('/db.sqlite')
@app.route('/etc/passwd')
def bait_404():
    log.info(f"[!] 404 bait: {request.path}")
    return "Not found", 404

@app.route('/login', methods=['POST'])
@app.route('/admin', methods=['POST'])
@app.route('/search', methods=['GET', 'POST'])
def fake_login():
    user = request.form.get("user", "none")
    password = request.form.get("pass", "none")
    log.info(f"[!!] Login attempt to {request.path}: {user}:{password}")
    return "Invalid credentials", 401

@app.route('/product')
def vulnerable_product():
    q = request.args.get("id", "")
    log.info(f"[***] SQLi probe: /product?id={q}")
    if "'" in q or "--" in q or "1=1" in q:
        return "Internal Server Error", 500
    return f"Product {q} not found", 404

@app.route('/favicon.ico')
def no_favicon():
    return "", 404

@app.errorhandler(404)
def handle_404(e):
    log.info(f"[!] Unknown 404: {request.path}")
    return "404 Not Found", 404

# --- Main entry ---
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)
