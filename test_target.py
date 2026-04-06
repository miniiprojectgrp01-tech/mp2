"""
Intentionally Vulnerable Test Server
ONLY for testing VulnScanner Pro — DO NOT deploy to production!
Runs on port 9999
"""
from flask import Flask, request
import time

app = Flask(__name__)


def check_all_params():
    """Check ALL query parameters for injection payloads (like a real vulnerable app would)"""
    all_values = ' '.join(request.args.values())
    return all_values


@app.route('/')
def index():
    # Also check params on root so scanner can test with ?id=1&test=payload
    all_input = check_all_params()
    if "'" in all_input or "OR" in all_input.upper() or "--" in all_input:
        return f'''<html><body>
        <b>Error:</b> You have an error in your SQL syntax;
        check the manual that corresponds to your MySQL server version
        for the right syntax to use near '{all_input}' at line 1<br>
        mysql_fetch_array() expects parameter 1 to be resource
        </body></html>''', 500
    return '<h1>Test Target Server</h1><p>This is an intentionally vulnerable app for scanner testing.</p>'


@app.route('/search')
def search():
    all_input = check_all_params()
    # XSS: reflect ALL input
    return f'<html><body><h1>Search Results</h1><p>You searched for: {all_input}</p></body></html>'


@app.route('/products')
def products():
    all_input = check_all_params()
    # Error-based SQLi: return SQL errors when any param has injection chars
    if "'" in all_input or "OR" in all_input.upper() or "--" in all_input:
        return f'''<html><body>
        <b>Error:</b> You have an error in your SQL syntax;
        check the manual that corresponds to your MySQL server version
        for the right syntax to use near '{all_input}' at line 1<br>
        mysql_fetch_array() expects parameter 1 to be resource
        </body></html>''', 500
    pid = request.args.get('id', '1')
    return f'<html><body><h1>Product #{pid}</h1><p>Product details here.</p></body></html>'


@app.route('/login')
def login():
    all_input = check_all_params()
    # Boolean-based: true/false conditions give different response sizes
    if "1'='1" in all_input:
        return '<html><body>' + 'A' * 5000 + '</body></html>'
    elif "1'='2" in all_input:
        return '<html><body>No results</body></html>'
    # Error-based fallback
    if "'" in all_input:
        return '<html><body>Error: unclosed quotation mark after the character string</body></html>', 500
    return '<html><body><h1>Login Page</h1></body></html>'


@app.route('/api/data')
def api_data():
    all_input = check_all_params()
    # Time-based: sleep on SLEEP/WAITFOR payloads in ANY param
    if 'SLEEP' in all_input.upper() or 'WAITFOR' in all_input.upper():
        time.sleep(5)
    # Also respond to error-based
    if "'" in all_input or "--" in all_input:
        return '<html><body>Error: sql syntax error near input</body></html>', 500
    return '<html><body>{"data": "ok"}</body></html>'


if __name__ == '__main__':
    print("\n🎯 Vulnerable Test Target running on http://127.0.0.1:9999")
    print("   Use these URLs to scan:")
    print("   • http://127.0.0.1:9999/products?id=1  (SQLi error-based)")
    print("   • http://127.0.0.1:9999/login?user=test (SQLi boolean/error)")
    print("   • http://127.0.0.1:9999/search?q=test   (XSS reflection)")
    print("   • http://127.0.0.1:9999/api/data         (Time-based SQLi)\n")
    app.run(host='127.0.0.1', port=9999, debug=False)
