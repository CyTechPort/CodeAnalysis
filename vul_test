# Example 1: SQL Injection Vulnerability
import sqlite3

def get_user(username):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # Vulnerable code - direct string concatenation
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)  # Vulnerable to SQL injection
    return cursor.fetchone()

# Usage that could be exploited: get_user("admin' OR '1'='1")

# Example 2: Command Injection
import os

def backup_file(filename):
    # Vulnerable code - unsanitized input passed to os.system
    os.system("tar -czf /tmp/backup.tar.gz " + filename)
    return "Backup completed"

# Usage that could be exploited: backup_file("important.txt; rm -rf /")

# Example 3: Path Traversal
def read_file(filename):
    # Vulnerable code - no path validation
    with open(filename, 'r') as file:
        content = file.read()
    return content

# Usage that could be exploited: read_file("../../../etc/passwd")

# Example 4: Insecure Deserialization
import pickle

def load_preferences(serialized_data):
    # Vulnerable code - unsafe deserialization
    return pickle.loads(serialized_data)  # Can execute arbitrary code

# Usage that could be exploited with malicious serialized data

# Example 5: Hardcoded Credentials
def connect_to_database():
    username = "admin"
    password = "super_secret_password123"  # Hardcoded credentials
    connection_string = f"mysql://username:{password}@database:3306/production"
    # Connect to database...
    return connection_string

# Example 6: Broken Authentication
def verify_password(stored_hash, provided_password):
    # Vulnerable code - weak comparison
    if stored_hash == provided_password:  # Plain text comparison instead of proper hashing
        return True
    return False

# Example 7: XML External Entity (XXE) Vulnerability
import xml.etree.ElementTree as ET
import xml.sax

def parse_xml(xml_data):
    # Vulnerable code - no protection against XXE
    return ET.fromstring(xml_data)  # Vulnerable to XXE attacks

# Example 8: Cross-Site Scripting (XSS) in a web context
from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route('/profile')
def profile():
    username = request.args.get('username', '')
    # Vulnerable code - unsanitized input directly in template
    template = f"<h1>Profile for {username}</h1>"
    return render_template_string(template)  # Vulnerable to XSS

# Usage that could be exploited: /profile?username=<script>alert('XSS')</script>

# Example 9: Insecure Random Values
import random

def generate_session_token():
    # Vulnerable code - predictable random values
    return str(random.randint(10000, 99999))  # Not cryptographically secure

# Example 10: Sensitive Data Exposure
def process_payment(credit_card):
    # Log sensitive data
    print(f"Processing payment for card: {credit_card}")  # Logs sensitive data
    # Process payment...
    return "Payment processed"
