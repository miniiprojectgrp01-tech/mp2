from flask import Flask, render_template, request, jsonify
import requests
from urllib.parse import urlparse
import os
from groq import Groq
import json
import re
from datetime import datetime
import sqlite3

app = Flask(__name__)

# --- CONFIGURATION ---
# Optional: Paste your Groq API key here to avoid exporting it in the terminal every time.
# Example: GROQ_API_KEY = "gsk_..."
GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
# --------------------

# Database setup
def init_db():
    conn = sqlite3.connect('instance/scans.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS scans
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  url TEXT NOT NULL,
                  timestamp TEXT NOT NULL,
                  risk_score INTEGER,
                  risk_level TEXT,
                  findings TEXT,
                  ai_summary TEXT)''')
    conn.commit()
    conn.close()

init_db()

# OWASP mapping function (moved from Jinja2 to Python)
def map_to_owasp(finding_type):
    """Map vulnerability types to OWASP Top 10 categories"""
    owasp_map = {
        'missing_security_headers': 'A05:2021 - Security Misconfiguration',
        'information_leakage': 'A05:2021 - Security Misconfiguration',
        'http_only': 'A01:2021 - Broken Access Control',
        'https_enforcement': 'A02:2021 - Cryptographic Failures',
        'cookie_security': 'A05:2021 - Security Misconfiguration',
        'xss_vulnerability': 'A03:2021 - Injection',
        'sql_injection': 'A03:2021 - Injection',
        'robots_txt': 'A05:2021 - Security Misconfiguration',
        'security_txt': 'A05:2021 - Security Misconfiguration',
        'rate_limiting': 'A05:2021 - Security Misconfiguration'
    }
    return owasp_map.get(finding_type, 'A05:2021 - Security Misconfiguration')

def get_groq_client():
    """Get Groq client if API key is available, otherwise return None"""
    api_key = GROQ_API_KEY or os.getenv('GROQ_API_KEY')
    if not api_key:
        return None
    try:
        return Groq(api_key=api_key)
    except:
        return None

def analyze_with_groq(findings_data):
    """Generate AI summary using Groq API if available"""
    client = get_groq_client()
    if not client:
        return None
    
    try:
        # Prepare findings summary for AI
        findings_summary = json.dumps(findings_data, indent=2)
        
        prompt = f"""You are a cybersecurity expert. Analyze these vulnerability findings and provide a brief 2-3 sentence executive summary of the overall security posture.

Findings:
{findings_summary}

Provide only the summary, no preamble."""

        chat_completion = client.chat.completions.create(
            messages=[{"role": "user", "content": prompt}],
            model="llama-3.3-70b-versatile",
            temperature=0.7,
            max_tokens=200
        )
        
        return chat_completion.choices[0].message.content.strip()
    except Exception as e:
        print(f"Groq API error: {e}")
        return None

def check_sql_injection(url, level=1):
    """
    SQL Injection Detection with 4 levels:
    Level 1: Error-based detection
    Level 2: Boolean-based blind detection
    Level 3: Time-based blind detection
    Level 4: All methods combined
    """
    results = {
        'vulnerable': False,
        'evidence': [],
        'level_used': level,
        'methods_detected': []
    }
    
    # SQL payloads for different detection methods
    error_payloads = ["'", "' OR '1'='1", "'; --", "' OR 1=1--"]
    boolean_payloads = [
        "' AND '1'='1",
        "' AND '1'='2",
        "1' AND '1'='1'--",
        "1' AND '1'='2'--"
    ]
    time_payloads = [
        "'; WAITFOR DELAY '00:00:05'--",
        "' OR SLEEP(5)--",
        "1'; SELECT SLEEP(5)--"
    ]
    
    # Error signatures
    error_signatures = [
        'sql syntax',
        'mysql_fetch',
        'ora-01756',
        'syntax error',
        'unclosed quotation',
        'quoted string not properly terminated',
        'microsoft ole db provider for sql server'
    ]
    
    test_url = url if '?' in url else f"{url}?id=1"
    
    # Level 1: Error-based detection
    if level >= 1:
        for payload in error_payloads:
            try:
                response = requests.get(f"{test_url}&test={payload}", timeout=5)
                response_lower = response.text.lower()
                
                for signature in error_signatures:
                    if signature in response_lower:
                        results['vulnerable'] = True
                        results['evidence'].append(f"Error-based: SQL error with payload '{payload}'")
                        results['methods_detected'].append('Error-based')
                        break
            except:
                continue
    
    # Level 2: Boolean-based detection
    if level >= 2:
        try:
            # Baseline request
            baseline = requests.get(test_url, timeout=5)
            baseline_len = len(baseline.text)
            
            true_payload = "' AND '1'='1"
            false_payload = "' AND '1'='2"
            
            true_response = requests.get(f"{test_url}&test={true_payload}", timeout=5)
            false_response = requests.get(f"{test_url}&test={false_payload}", timeout=5)
            
            # If true and false conditions give different responses, likely vulnerable
            if abs(len(true_response.text) - len(false_response.text)) > 100:
                results['vulnerable'] = True
                results['evidence'].append("Boolean-based: Different responses for true/false conditions")
                results['methods_detected'].append('Boolean-based')
        except:
            pass
    
    # Level 3: Time-based detection
    if level >= 3:
        for payload in time_payloads:
            try:
                start_time = datetime.now()
                requests.get(f"{test_url}&test={payload}", timeout=10)
                elapsed = (datetime.now() - start_time).total_seconds()
                
                if elapsed >= 4:  # If response delayed by ~5 seconds
                    results['vulnerable'] = True
                    results['evidence'].append(f"Time-based: {elapsed:.1f}s delay with payload '{payload}'")
                    results['methods_detected'].append('Time-based')
                    break
            except:
                continue
    
    # Remove duplicates from methods_detected
    results['methods_detected'] = list(set(results['methods_detected']))
    
    return results

def check_xss(url):
    """Check for reflected XSS vulnerability"""
    xss_payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "'\"><script>alert(String.fromCharCode(88,83,83))</script>"
    ]
    
    test_url = url if '?' in url else f"{url}?search=test"
    
    for payload in xss_payloads:
        try:
            response = requests.get(f"{test_url}&q={payload}", timeout=5)
            if payload in response.text:
                return {
                    'vulnerable': True,
                    'evidence': f'Payload reflected: {payload[:50]}...'
                }
        except:
            continue
    
    return {'vulnerable': False, 'evidence': 'No XSS detected'}

def scan_url(url, sqli_level=1, sqli_enabled=True):
    """Main scanning function that checks all vulnerabilities"""
    try:
        # Parse URL
        parsed = urlparse(url)
        if not parsed.scheme:
            url = 'https://' + url
        
        # Fetch headers with redirect following
        session = requests.Session()
        session.max_redirects = 5
        
        # Track all headers through redirects
        all_headers = {}
        
        # Follow redirects manually to capture headers
        current_url = url
        for _ in range(5):
            try:
                response = session.get(current_url, allow_redirects=False, timeout=10)
                
                # Merge headers from this response
                for key, value in response.headers.items():
                    all_headers[key] = value
                
                # Check if there's a redirect
                if response.status_code in [301, 302, 303, 307, 308]:
                    if 'Location' in response.headers:
                        current_url = response.headers['Location']
                        # Handle relative redirects
                        if not current_url.startswith('http'):
                            current_url = f"{parsed.scheme}://{parsed.netloc}{current_url}"
                        continue
                break
            except:
                break
        
        # Final request
        try:
            response = session.get(current_url, timeout=10)
            # Merge final headers
            for key, value in response.headers.items():
                all_headers[key] = value
        except:
            pass
        
        findings = []
        total_score = 0
        
        # Security Headers Check (Weight: 3 points each)
        security_headers = {
            'Strict-Transport-Security': 'HSTS missing',
            'X-Content-Type-Options': 'X-Content-Type-Options missing',
            'X-Frame-Options': 'X-Frame-Options missing',
            'Content-Security-Policy': 'CSP missing',
            'X-XSS-Protection': 'X-XSS-Protection missing',
            'Referrer-Policy': 'Referrer-Policy missing',
            'Permissions-Policy': 'Permissions-Policy missing'
        }
        
        for header, description in security_headers.items():
            if header not in all_headers:
                findings.append({
                    'type': 'missing_security_headers',
                    'severity': 'MEDIUM',
                    'title': description,
                    'description': f'Missing {header} header exposes the application to various attacks',
                    'owasp': map_to_owasp('missing_security_headers')
                })
                total_score += 3  # Medium severity = 3 points
        
        # Information Leakage (Weight: 2 points)
        if 'Server' in all_headers:
            findings.append({
                'type': 'information_leakage',
                'severity': 'LOW',
                'title': 'Server header reveals version',
                'description': f'Server: {all_headers["Server"]}',
                'owasp': map_to_owasp('information_leakage')
            })
            total_score += 2  # Low severity = 2 points
        
        # HTTPS Check (Weight: 5 points)
        if not url.startswith('https://'):
            findings.append({
                'type': 'https_enforcement',
                'severity': 'HIGH',
                'title': 'No HTTPS enforcement',
                'description': 'Site is not using HTTPS, exposing data to interception',
                'owasp': map_to_owasp('https_enforcement')
            })
            total_score += 5  # High severity = 5 points
        
        # Cookie Security (Weight: 3 points each)
        if 'Set-Cookie' in all_headers:
            cookie = all_headers['Set-Cookie'].lower()
            if 'httponly' not in cookie:
                findings.append({
                    'type': 'cookie_security',
                    'severity': 'MEDIUM',
                    'title': 'Cookie missing HttpOnly flag',
                    'description': 'Cookies are vulnerable to XSS attacks',
                    'owasp': map_to_owasp('cookie_security')
                })
                total_score += 3
            
            if 'secure' not in cookie:
                findings.append({
                    'type': 'cookie_security',
                    'severity': 'MEDIUM',
                    'title': 'Cookie missing Secure flag',
                    'description': 'Cookies can be transmitted over HTTP',
                    'owasp': map_to_owasp('cookie_security')
                })
                total_score += 3
        
        # XSS Detection (Weight: 5 points)
        xss_result = check_xss(url)
        if xss_result['vulnerable']:
            findings.append({
                'type': 'xss_vulnerability',
                'severity': 'HIGH',
                'title': 'Reflected XSS vulnerability detected',
                'description': xss_result['evidence'],
                'owasp': map_to_owasp('xss_vulnerability')
            })
            total_score += 5
        
        # SQL Injection Detection (Weight: 10 points for HIGH)
        sqli_score = 0
        if sqli_enabled:
            sqli_result = check_sql_injection(url, level=sqli_level)
            if sqli_result['vulnerable']:
                evidence_text = '; '.join(sqli_result['evidence'])
                methods_text = ', '.join(sqli_result['methods_detected'])
                findings.append({
                    'type': 'sql_injection',
                    'severity': 'HIGH',
                    'title': f'SQL Injection detected (Level {sqli_level})',
                    'description': f'Methods: {methods_text}. Evidence: {evidence_text}',
                    'owasp': map_to_owasp('sql_injection')
                })
                total_score += 10
                sqli_score = 10
        else:
            # Marker so results page knows SQLi was intentionally skipped
            findings.append({
                'type': 'sqli_skipped',
                'severity': 'INFO',
                'title': 'SQL Injection scan skipped',
                'description': 'SQL Injection detection was disabled for this scan.',
                'owasp': map_to_owasp('sql_injection')
            })
        
        # Robots.txt exposure (Weight: 1 point)
        try:
            robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
            robots_response = requests.get(robots_url, timeout=5)
            if robots_response.status_code == 200 and len(robots_response.text) > 0:
                findings.append({
                    'type': 'robots_txt',
                    'severity': 'INFO',
                    'title': 'robots.txt exposed',
                    'description': 'File may reveal sensitive directories',
                    'owasp': map_to_owasp('robots_txt')
                })
                total_score += 1
        except:
            pass
        
        # Security.txt check (Weight: 1 point)
        try:
            security_txt_url = f"{parsed.scheme}://{parsed.netloc}/.well-known/security.txt"
            sec_response = requests.get(security_txt_url, timeout=5)
            if sec_response.status_code != 200:
                findings.append({
                    'type': 'security_txt',
                    'severity': 'INFO',
                    'title': 'security.txt missing',
                    'description': 'No security disclosure policy found',
                    'owasp': map_to_owasp('security_txt')
                })
                total_score += 1
        except:
            pass
        
        # Rate limiting check (Weight: 2 points)
        if 'X-RateLimit-Limit' not in all_headers and 'RateLimit-Limit' not in all_headers:
            findings.append({
                'type': 'rate_limiting',
                'severity': 'LOW',
                'title': 'No rate limiting headers detected',
                'description': 'API may be vulnerable to abuse',
                'owasp': map_to_owasp('rate_limiting')
            })
            total_score += 2
        
        # Calculate risk level with adjusted thresholds
        # Well-configured sites like google.com typically score 15-25
        if total_score <= 20:
            risk_level = 'LOW'
        elif total_score <= 40:
            risk_level = 'MEDIUM'
        else:
            risk_level = 'HIGH'
        
        # Generate AI summary if Groq is available
        ai_summary = analyze_with_groq({
            'url': url,
            'risk_score': total_score,
            'risk_level': risk_level,
            'findings_count': len(findings),
            'severity_breakdown': {
                'high': sum(1 for f in findings if f['severity'] == 'HIGH'),
                'medium': sum(1 for f in findings if f['severity'] == 'MEDIUM'),
                'low': sum(1 for f in findings if f['severity'] == 'LOW')
            }
        })
        
        # Save to database
        conn = sqlite3.connect('instance/scans.db')
        c = conn.cursor()
        c.execute('''INSERT INTO scans (url, timestamp, risk_score, risk_level, findings, ai_summary)
                     VALUES (?, ?, ?, ?, ?, ?)''',
                  (url, datetime.now().isoformat(), total_score, risk_level, 
                   json.dumps(findings), ai_summary or ''))
        conn.commit()
        scan_id = c.lastrowid
        conn.close()
        
        return {
            'success': True,
            'url': url,
            'risk_score': total_score,
            'risk_level': risk_level,
            'findings': findings,
            'ai_summary': ai_summary,
            'scan_id': scan_id,
            'sqli_enabled': sqli_enabled,
            'sqli_score': sqli_score,
            'timestamp': datetime.now().isoformat()
        }
        
    except Exception as e:
        return {
            'success': False,
            'error': str(e)
        }

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    data = request.get_json()
    url = data.get('url', '').strip()
    sqli_level = int(data.get('sqli_level', 1))
    sqli_enabled = data.get('sqli_enabled', True)
    
    if not url:
        return jsonify({'success': False, 'error': 'URL is required'})
    
    result = scan_url(url, sqli_level, sqli_enabled)
    return jsonify(result)

@app.route('/history')
def history():
    conn = sqlite3.connect('instance/scans.db')
    c = conn.cursor()
    c.execute('SELECT id, url, timestamp, risk_score, risk_level FROM scans ORDER BY id DESC LIMIT 50')
    scans = []
    for row in c.fetchall():
        scans.append({
            'id': row[0],
            'url': row[1],
            'timestamp': row[2],
            'risk_score': row[3],
            'risk_level': row[4]
        })
    conn.close()
    return render_template('history.html', scans=scans)

@app.route('/scan/<int:scan_id>/delete', methods=['POST'])
def delete_scan(scan_id):
    conn = sqlite3.connect('instance/scans.db')
    c = conn.cursor()
    c.execute('DELETE FROM scans WHERE id = ?', (scan_id,))
    conn.commit()
    conn.close()
    return jsonify({'success': True})

@app.route('/history/clear', methods=['POST'])
def clear_history():
    conn = sqlite3.connect('instance/scans.db')
    c = conn.cursor()
    c.execute('DELETE FROM scans')
    conn.commit()
    conn.close()
    return jsonify({'success': True})


@app.route('/scan/<int:scan_id>')
def view_scan(scan_id):
    conn = sqlite3.connect('instance/scans.db')
    c = conn.cursor()
    c.execute('SELECT * FROM scans WHERE id = ?', (scan_id,))
    row = c.fetchone()
    conn.close()
    
    if not row:
        return render_template('404.html'), 404
    
    scan_data = {
        'id': row[0],
        'url': row[1],
        'timestamp': row[2],
        'risk_score': row[3],
        'risk_level': row[4],
        'findings': json.loads(row[5]),
        'ai_summary': row[6]
    }
    
    return render_template('results.html', scan=scan_data)

@app.errorhandler(404)
def not_found(e):
    return render_template('404.html'), 404

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)