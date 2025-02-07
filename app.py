import os
import re
import sqlite3
from datetime import datetime, timedelta

from flask import Flask, request, redirect, render_template, url_for
import requests

from cryptography.fernet import Fernet

app = Flask(__name__)

DATABASE = 'database.db'

# --- Encryption Setup ---
ENCRYPT_KEY = os.environ.get('ENCRYPT_KEY', None)
if not ENCRYPT_KEY:
    # For demonstration, but in production, raise an error or generate a key.
    print("[WARNING] ENCRYPT_KEY not set. Using an insecure fallback key!")
    ENCRYPT_KEY = Fernet.generate_key()

fernet = Fernet(ENCRYPT_KEY)

def encrypt_string(plaintext: str) -> str:
    """Encrypt a plaintext string using Fernet."""
    if not plaintext:
        return ""
    return fernet.encrypt(plaintext.encode('utf-8')).decode('utf-8')

def decrypt_string(ciphertext: str) -> str:
    """Decrypt a ciphertext string using Fernet."""
    if not ciphertext:
        return ""
    return fernet.decrypt(ciphertext.encode('utf-8')).decode('utf-8')


# For SendLayer
SENDLAYER_API_KEY = os.environ.get('SENDLAYER_API_KEY')  # e.g. store in Render env variable
SENDLAYER_FROM_EMAIL = os.environ.get('SENDLAYER_FROM_EMAIL', 'noreply@301er.io')

# ----- Basic Bot Detection Setup -----
KNOWN_BOT_PATTERNS = [
    'bot', 'spider', 'crawl', 'slurp',
    'facebookexternalhit', 'mediapartners-google'
]

def is_bot(user_agent: str) -> bool:
    """Very naive check for common bot/spider user-agents."""
    if not user_agent:
        return False
    ua_lower = user_agent.lower()
    return any(bot_substring in ua_lower for bot_substring in KNOWN_BOT_PATTERNS)

# ----- Database Helpers -----
def get_db():
    """Returns a connection to the SQLite database."""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Create or update the table if it doesn't exist, adding any new columns if necessary."""
    with get_db() as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS redirect_links (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                short_id TEXT UNIQUE NOT NULL,
                original_url TEXT NOT NULL,
                max_redirects INTEGER NOT NULL,
                current_count INTEGER NOT NULL DEFAULT 0,
                trigger_email TEXT,
                exceeded_url TEXT,
                email_count INTEGER NOT NULL DEFAULT 0,
                expiration_timestamp TEXT
            );
        ''')
    print("Database initialized.")

def generate_short_id():
    """Generate a random short identifier."""
    import random
    import string
    return ''.join(random.choices(string.ascii_letters + string.digits, k=6))


# ----- Notification Triggers -----
def send_email_notification(api_key, from_email, to_email, short_id,
                            original_url, user_agent, ip, click_time):
    """
    Sends an email via SendLayer when a redirect occurs.
    Uses the 'console.sendlayer.com/api/v1/email' endpoint and
    the JSON format specified in SendLayer's current documentation.
    """
    if not api_key:
        print("[WARNING] SENDLAYER_API_KEY is not set. Email not sent.")
        return

    url = "https://console.sendlayer.com/api/v1/email"

    subject = f"Your Link {short_id} ({original_url}) was triggered"

    plain_content = (
        f"The 301er.io link {short_id} was just used.\n\n"
        f"Original URL: {original_url}\n"
        f"IP: {ip}\n"
        f"User-Agent: {user_agent}\n"
        f"Timestamp: {click_time}\n"
    )

    html_content = (
        f"<p>The link <strong>{short_id}</strong> was just used.</p>"
        f"<ul>"
        f"<li>Original URL: {original_url}</li>"
        f"<li>From IP Address: {ip}</li>"
        f"<li>User-Agent info: {user_agent}</li>"
        f"<li>Timestamp: {click_time}</li>"
        f"</ul>"
    )

    payload = {
        "From": {
            "email": from_email
        },
        "To": [
            {
                "email": to_email
            }
        ],
        "Subject": subject,
        "ContentType": "HTML",
        "HTMLContent": html_content,
        "PlainContent": plain_content
    }

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}"
    }

    try:
        response = requests.post(url, json=payload, headers=headers, timeout=10)
        if 200 <= response.status_code < 300:
            print(f"[DEBUG] Email sent to {to_email} via SendLayer. Response: {response.json()}")
        else:
            print(f"[ERROR] SendLayer response: {response.status_code}, {response.text}")
    except Exception as e:
        print(f"[ERROR] Exception while sending email: {e}")

# ----- Flask Routes -----

@app.route('/', methods=['GET', 'POST'])
def index():
    """
    Displays a form to create a new redirect link.
    On POST, it handles the creation logic.
    """
    if request.method == 'POST':
        original_url = request.form.get('original_url', '').strip()
        max_redirects_str = request.form.get('max_redirects', '0').strip()
        trigger_email = request.form.get('trigger_email', '').strip()
        exceeded_url = request.form.get('exceeded_url', '').strip()
        expiry_minutes_str = request.form.get('expiry_minutes', '0').strip()

        # Validate the original URL
        if not original_url:
            return render_template('index.html', error="Original URL is required.")
        if not re.match(r'^https?://', original_url, re.IGNORECASE):
            return render_template('index.html', error="URL must start with http:// or https://")

        # Convert max_redirects to int
        try:
            max_redirects = int(max_redirects_str)
            if max_redirects < 0 or max_redirects > 1000:
                raise ValueError
        except ValueError:
            return render_template('index.html', error="Max redirects must be between 0 and 1000.")

        # Convert expiry_minutes to int
        try:
            expiry_minutes = int(expiry_minutes_str)
            if expiry_minutes < 0 or expiry_minutes > 10080:  # up to 7 days
                raise ValueError
        except ValueError:
            return render_template('index.html', error="Expiry must be between 0 and 10080 minutes (7 days).")

        # If the user sets neither expiry nor max_redirects, it's an error.
        if max_redirects == 0 and expiry_minutes == 0:
            return render_template('index.html', error="Please set at least a time expiry or a max-click limit.")

        # If no exceeded_url is provided, default to google
        if not exceeded_url:
            exceeded_url = 'https://google.com'

        # Build the expiration timestamp if we have an expiry
        expiration_timestamp = ""
        if expiry_minutes > 0:
            expiration_time = datetime.utcnow() + timedelta(minutes=expiry_minutes)
            expiration_timestamp = expiration_time.isoformat()

        short_id = generate_short_id()

        # Encrypt fields
        enc_original_url = encrypt_string(original_url)
        enc_exceeded_url = encrypt_string(exceeded_url)
        enc_trigger_email = encrypt_string(trigger_email)

        with get_db() as conn:
            conn.execute('''
                INSERT INTO redirect_links
                (short_id, original_url, max_redirects, current_count, trigger_email, exceeded_url, email_count, expiration_timestamp)
                VALUES (?, ?, ?, 0, ?, ?, 0, ?);
            ''', (
                short_id,
                enc_original_url,
                max_redirects,
                enc_trigger_email,
                enc_exceeded_url,
                expiration_timestamp
            ))

        short_url = request.url_root.rstrip('/') + url_for('redirect_handler', short_id=short_id)
        return render_template('index.html', short_url=short_url)

    # GET request: show the form
    return render_template('index.html')


@app.route('/r/<short_id>')
def redirect_handler(short_id):
    """
    When someone accesses /r/<short_id>:
    - Decrypt the stored values
    - If there's a time expiry, check if it's past
    - If there's a max_redirect limit, check if we've exceeded it
    - If limit/expiry is reached, wipe the original_url in the DB
      (to remove sensitive data) and always redirect to exceeded_url.
    - Otherwise, increment usage, optionally send email, and redirect
      to the original.
    """
    user_agent = request.headers.get('User-Agent', '')
    ip = request.remote_addr or 'Unknown IP'
    click_time = datetime.utcnow()

    with get_db() as conn:
        row = conn.execute('SELECT * FROM redirect_links WHERE short_id = ?;', (short_id,)).fetchone()

        if not row:
            return render_template('expired.html', message="This link does not exist."), 404

        # Decrypt fields
        dec_original_url = decrypt_string(row['original_url'])
        dec_exceeded_url = decrypt_string(row['exceeded_url']) or 'https://google.com'
        dec_trigger_email = decrypt_string(row['trigger_email'])

        max_redirects = row['max_redirects']
        current_count = row['current_count']
        expiration_timestamp = row['expiration_timestamp'] or ""

        # 1. Time-based expiry check
        is_time_expired = False
        if expiration_timestamp:
            try:
                link_expiry_time = datetime.fromisoformat(expiration_timestamp)
                if click_time >= link_expiry_time:
                    is_time_expired = True
            except ValueError:
                # If somehow invalid, treat it as expired
                is_time_expired = True

        # 2. Click-based expiry check
        is_click_expired = False
        if max_redirects > 0 and current_count >= max_redirects:
            is_click_expired = True

        # If we've reached time expiry or click limit,
        # we permanently redirect to 'exceeded_url'.
        if is_time_expired or is_click_expired:
            # Wipe the original_url from DB (but keep the row).
            conn.execute('''
                UPDATE redirect_links
                SET original_url = ''
                WHERE short_id = ?;
            ''', (short_id,))
            return redirect(dec_exceeded_url, code=301)

        # Not expired: proceed with normal redirect
        if is_bot(user_agent):
            # Bot: do NOT increment or send email
            return redirect(dec_original_url, code=301)
        else:
            new_count = current_count + 1
            new_email_count = row['email_count']

            # Possibly send email, up to 5 times
            if dec_trigger_email and new_email_count < 5:
                send_email_notification(
                    api_key=SENDLAYER_API_KEY,
                    from_email=SENDLAYER_FROM_EMAIL,
                    to_email=dec_trigger_email,
                    short_id=row['short_id'],
                    original_url=dec_original_url,
                    user_agent=user_agent,
                    ip=ip,
                    click_time=click_time.isoformat()
                )
                new_email_count += 1

            # Update usage
            conn.execute('''
                UPDATE redirect_links
                SET current_count = ?, email_count = ?
                WHERE short_id = ?
            ''', (new_count, new_email_count, short_id))

    # Finally, redirect to the original URL
    return redirect(dec_original_url, code=301)


# ----- Main Entrypoint -----
init_db()

if __name__ == '__main__':
    # For local dev
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=True)
