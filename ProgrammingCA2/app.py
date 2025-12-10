import os
import time
import sqlite3
from datetime import datetime
from flask import Flask, request, render_template, jsonify, flash, redirect, url_for, session
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import requests
from dotenv import load_dotenv
from flask_cors import CORS  


app = Flask(__name__)
CORS(app)
app.secret_key = 'supersecretkey'
app.config['UPLOAD_FOLDER'] = 'uploads'

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

load_dotenv()
VT_API_KEY = os.getenv('VT_API_KEY')
if not VT_API_KEY:
    raise Exception("VirusTotal API Key not found! Please set it in .env file.")
VT_HEADERS = {"x-apikey": VT_API_KEY}


def init_db():
    conn = sqlite3.connect("viroscan.db")
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            email TEXT UNIQUE,
            password TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

   
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            date TEXT,
            scan_type TEXT,
            target TEXT,
            file_hash TEXT,
            status TEXT,
            result TEXT
        )
    """)

   
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS suspicious_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            target TEXT,
            email TEXT,
            issue TEXT
        )
    """)

    conn.commit()
    conn.close()

init_db()


def scan_url_with_virustotal(url):
    scan_url = "https://www.virustotal.com/api/v3/urls"
    response = requests.post(scan_url, headers=VT_HEADERS, data={"url": url})

    if response.status_code == 401:
        return {"error": "Unauthorized. Check your VirusTotal API key."}
    elif response.status_code != 200:
        return {"error": f"VirusTotal scan failed. Status: {response.status_code}"}

    data_id = response.json()["data"]["id"]
    report_url = f"https://www.virustotal.com/api/v3/analyses/{data_id}"

    max_attempts = 10
    attempt = 0
    while attempt < max_attempts:
        report_response = requests.get(report_url, headers=VT_HEADERS)
        if report_response.status_code != 200:
            return {"error": "Failed to retrieve analysis report."}
        result = report_response.json()
        status = result.get("data", {}).get("attributes", {}).get("status")
        if status == "completed":
            scan_result = result.get("data", {}).get("attributes", {}).get("stats", {})
            malicious = scan_result.get("malicious", 0)
            harmless = scan_result.get("harmless", 0)
            return {
                "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "type": "URL",
                "target": url,
                "status": "Completed",
                "result": f"Malicious: {malicious} | Clean: {harmless}",
                "malicious": malicious,
                "harmless": harmless
            }
        else:
            time.sleep(3)
            attempt += 1

    return {"error": "Analysis timed out. Please try again later."}

def save_scan_to_db(scan_type, target, status, result):
    conn = sqlite3.connect("viroscan.db")
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO scan_history (date, scan_type, target, status, result) VALUES (?, ?, ?, ?, ?)",
        (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), scan_type, target, status, result)
    )
    conn.commit()
    conn.close()

def save_report_to_db(name, target, email, issue):
    conn = sqlite3.connect("viroscan.db")
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO suspicious_reports (name, target, email, issue) VALUES (?, ?, ?, ?)",
        (name, target, email, issue)
    )
    conn.commit()
    conn.close()



@app.route('/')
def index():
    
    conn = sqlite3.connect("viroscan.db")
    cursor = conn.cursor()
    cursor.execute("SELECT id, date, scan_type, target, status, result FROM scan_history ORDER BY id DESC LIMIT 3")
    records = cursor.fetchall()
    conn.close()

    parsed_records = []
    for record in records:
        malicious = 0
        if record[5]:
            parts = record[5].split('|')
            for part in parts:
                if 'Malicious:' in part:
                    try:
                        malicious = int(part.split(':')[1].strip())
                    except:
                        malicious = 0

        parsed_records.append({
            'record': record,
            'malicious': malicious
        })
    return render_template('index.html', scan_history=parsed_records)

@app.route('/full-history')
def full_history():
    conn = sqlite3.connect("viroscan.db")
    cursor = conn.cursor()
    cursor.execute("SELECT id, date, scan_type, target, status, result FROM scan_history ORDER BY id DESC")
    records = cursor.fetchall()
    conn.close()

    parsed_records = []
    for record in records:
        malicious = 0
        if record[5]:
            parts = record[5].split('|')
            for part in parts:
                if 'Malicious:' in part:
                    try:
                        malicious = int(part.split(':')[1].strip())
                    except:
                        malicious = 0
        parsed_records.append({
            'record': record,
            'malicious': malicious
        })
    return render_template('full_history.html', scan_history=parsed_records)


@app.route('/scan-url', methods=['POST'])
def scan_url():
    url = request.form.get('url')
    result = scan_url_with_virustotal(url)

    scan_data = {
        "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "type": "URL",
        "target": url,
        "status": "Completed" if 'result' in result else "Failed",
        "result": result.get("result", result.get("error", "Error during scan")),
        "malicious": result.get("malicious", 0),
        "harmless": result.get("harmless", 0)
    }

    save_scan_to_db(scan_data['type'], scan_data['target'], scan_data['status'], scan_data['result'])

    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify(scan_data)

    if 'result' in result:
        flash("URL scanned successfully! Result: " + scan_data['result'], "url_scan")
    else:
        flash(f"URL scan failed: {result.get('error', 'Unknown error')}", "url_scan")

    return redirect(url_for('index') + '#scan-section')


@app.route('/scan_file', methods=['POST'])
def scan_file():
    if 'file' not in request.files:
        flash("No file part in the request.", "file_scan")
        return redirect(url_for('index') + '#scan-section')

    file = request.files['file']
    if file.filename == '':
        flash(" No file selected.", "file_scan")
        return redirect(url_for('index') + '#scan-section')

    filename = secure_filename(file.filename)
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(file_path)

    abs_file_path = os.path.abspath(file_path).replace("\\", "/")
    raw_path = r"{}".format(abs_file_path)

    with open(raw_path, 'rb') as f:
        files = {'file': (filename, f)}
        response = requests.post('https://www.virustotal.com/api/v3/files', headers=VT_HEADERS, files=files)

    if response.status_code != 200:
        flash(f" File scan failed. Status: {response.status_code}", "file_scan")
        return redirect(url_for('index') + '#scan-section')

    data = response.json()
    data_id = data.get('data', {}).get('id')
    file_hash = data.get('data', {}).get('attributes', {}).get('sha256')

    if not data_id:
        flash("Failed to get scan ID from VirusTotal.", "file_scan")
        return redirect(url_for('index') + '#scan-section')

    report_url = f"https://www.virustotal.com/api/v3/analyses/{data_id}"

    max_attempts = 10
    attempt = 0
    scan_result = None
    malicious = 0
    harmless = 0
    while attempt < max_attempts:
        report_response = requests.get(report_url, headers=VT_HEADERS)
        if report_response.status_code != 200:
            flash("Failed to retrieve analysis report.", "file_scan")
            return redirect(url_for('index') + '#scan-section')
        result = report_response.json()
        status = result.get("data", {}).get("attributes", {}).get("status")
        if status == "completed":
            scan_stats = result.get("data", {}).get("attributes", {}).get("stats", {})
            malicious = scan_stats.get("malicious", 0)
            harmless = scan_stats.get("harmless", 0)
            scan_result = f"Malicious: {malicious} | Clean: {harmless}"
            break
        else:
            time.sleep(3)
            attempt += 1

    if scan_result is None:
        flash("Analysis timed out. Please try again later.", "file_scan")
        return redirect(url_for('index') + '#scan-section')

    scan_data = {
        "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "type": "File",
        "target": filename,
        "file_hash": file_hash,
        "status": "Completed",
        "result": scan_result,
        "malicious": malicious,
        "harmless": harmless
    }

    conn = sqlite3.connect("viroscan.db")
    cursor = conn.cursor()

    try:
        cursor.execute("INSERT INTO scan_history (date, scan_type, target, file_hash, status, result) VALUES (?, ?, ?, ?, ?, ?)",
                       (scan_data['date'], scan_data['type'], scan_data['target'], scan_data['file_hash'], scan_data['status'], scan_data['result']))
    except sqlite3.OperationalError:
        result_with_hash = scan_data['result'] + f" | SHA256: {scan_data['file_hash']}"
        cursor.execute("INSERT INTO scan_history (date, scan_type, target, status, result) VALUES (?, ?, ?, ?, ?)",
                       (scan_data['date'], scan_data['type'], scan_data['target'], scan_data['status'], result_with_hash))
    conn.commit()
    conn.close()

    flash("File scanned successfully! Result: " + scan_data['result'], "file_scan")
    return redirect(url_for('index') + '#scan-section')


@app.route('/report', methods=['POST'])
def report():
    name = request.form.get('name')
    target = request.form.get('target')
    email = request.form.get('email')
    issue = request.form.get('message')

    if name and target and email and issue:
        save_report_to_db(name, target, email, issue)
        flash("Your report has been submitted successfully!", "report")
    else:
        flash("Please fill in all fields.", "report")

    return redirect(url_for('index') + "#contact")


@app.route('/scan_report/<int:scan_id>')
def scan_report(scan_id):
    def fetch_virustotal_file_details(file_hash):
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        response = requests.get(url, headers=VT_HEADERS)
        if response.status_code != 200:
            return {}
        data = response.json().get("data", {}).get("attributes", {})

        return {
            "md5": data.get("md5"),
            "sha1": data.get("sha1"),
            "sha256": data.get("sha256"),
            "ssdeep": data.get("ssdeep"),
            "tlsh": data.get("tlsh"),
            "file_type": data.get("type_description"),
            "source": data.get("meaningful_name"),
            "magic": data.get("magic"),
            "trid": data.get("trid", {}).get("file_type", None) if data.get("trid") else None,
            "magika": data.get("magik", None),
            "file_size": data.get("size")
        }

    def fetch_virustotal_url_details(url_id):
        url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        response = requests.get(url, headers=VT_HEADERS)
        if response.status_code != 200:
            return {}
        data = response.json().get("data", {}).get("attributes", {})

        return {
            "last_final_url": data.get("last_final_url"),
            "reputation": data.get("reputation"),
            "categories": data.get("categories"),
            "last_analysis_stats": data.get("last_analysis_stats"),
            "last_analysis_results": data.get("last_analysis_results")
        }

    conn = sqlite3.connect("viroscan.db")
    cursor = conn.cursor()
    cursor.execute("SELECT id, date, scan_type, target, status, result FROM scan_history WHERE id = ?", (scan_id,))
    record = cursor.fetchone()
    conn.close()
    if record is None:
        return "Scan report not found", 404

    scan_dict = {
        'id': record[0],
        'date': record[1],
        'scan_type': record[2],
        'target': record[3],
        'status': record[4],
        'result': record[5]
    }

    malicious = 0
    harmless = 0
    file_hash = None
    if scan_dict['result']:
        parts = scan_dict['result'].split('|')
        for part in parts:
            if 'Malicious:' in part:
                try:
                    malicious = int(part.split(':')[1].strip())
                except:
                    malicious = 0
            elif 'Clean:' in part:
                try:
                    harmless = int(part.split(':')[1].strip())
                except:
                    harmless = 0
            elif 'SHA256:' in part:
                try:
                    file_hash = part.split(':')[1].strip()
                except:
                    file_hash = None
    scan_dict['malicious'] = malicious
    scan_dict['harmless'] = harmless

    if not file_hash:
        target = scan_dict.get('target')
        if target:
            if len(target) == 64 and all(c in '0123456789abcdefABCDEF' for c in target):
                file_hash = target.lower()
            elif len(target) == 32 and all(c in '0123456789abcdefABCDEF' for c in target):
                file_hash = target.lower()

    file_details = {}
    url_details = {}
    if scan_dict['scan_type'].lower() == 'file' and file_hash:
        file_details = fetch_virustotal_file_details(file_hash)
    elif scan_dict['scan_type'].lower() == 'url':
        import base64
        url_id = base64.urlsafe_b64encode(scan_dict['target'].encode()).decode().rstrip("=")
        url_details = fetch_virustotal_url_details(url_id)

    scan_dict.update({
        "md5": file_details.get("md5"),
        "sha1": file_details.get("sha1"),
        "sha256": file_details.get("sha256"),
        "ssdeep": file_details.get("ssdeep"),
        "tlsh": file_details.get("tlsh"),
        "file_type": file_details.get("file_type"),
        "source": file_details.get("source"),
        "magic": file_details.get("magic"),
        "trid": file_details.get("trid"),
        "magika": file_details.get("magika"),
        "file_size": file_details.get("file_size"),
        "url_last_final_url": url_details.get("last_final_url"),
        "url_reputation": url_details.get("reputation"),
        "url_categories": url_details.get("categories"),
        "url_last_analysis_stats": url_details.get("last_analysis_stats"),
        "url_last_analysis_results": url_details.get("last_analysis_results")
    })

    return render_template('report_detail.html', scan=scan_dict)

from flask import send_file
import io

@app.route('/download_report/<int:scan_id>')
def download_report(scan_id):
    conn = sqlite3.connect("viroscan.db")
    cursor = conn.cursor()
    cursor.execute("SELECT result FROM scan_history WHERE id = ?", (scan_id,))
    record = cursor.fetchone()
    conn.close()
    if record is None:
        return "Report not found", 404
    report_content = record[0]

    buffer = io.BytesIO()
    buffer.write(report_content.encode('utf-8'))
    buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name=f"scan_report_{scan_id}.txt", mimetype='text/plain')

@app.route('/rescan/<int:scan_id>')
def rescan(scan_id):
    flash(f"Rescan requested for scan ID {scan_id}. Feature not implemented yet.", "info")
    return redirect(url_for('index'))

@app.route('/signup', methods=['GET'])
def signup():
    return render_template('signup.html')

@app.route('/signup', methods=['POST'])
def signup_post():
    name = request.form.get('name')
    email = request.form.get('email')
    password = request.form.get('password')

    if not (name and email and password):
        flash("Please fill all fields.", "error")
        return redirect(url_for('signup'))

    hashed = generate_password_hash(password)

    conn = sqlite3.connect("viroscan.db")
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
                       (name, email, hashed))
        conn.commit()
        flash("Account created successfully! Please login.", "success")
        return redirect(url_for('login'))
    except sqlite3.IntegrityError:
        flash("Email already exists. Try another email!", "error")
        return redirect(url_for('signup'))
    finally:
        conn.close()

@app.route('/login', methods=['GET'])
def login():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login_post():
    email = request.form.get('email')
    password = request.form.get('password')

    conn = sqlite3.connect("viroscan.db")
    cursor = conn.cursor()
    cursor.execute("SELECT id, name, email, password FROM users WHERE email = ?", (email,))
    user = cursor.fetchone()
    conn.close()

    if user and check_password_hash(user[3], password):
        session['user_id'] = user[0]
        session['user_name'] = user[1]
        flash("Login successful!", "success")
        return redirect(url_for('index'))
    else:
        flash("Invalid email or password", "error")
        return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out", "info")
    return redirect(url_for('login'))

@app.route('/forgot-password')
def forgot_password():
    return "Forgot password page coming soon!"


if __name__ == '__main__':
    app.run(debug=True)
