import os
import sqlite3
import re
from flask import Flask, request, redirect, render_template, url_for
import requests

app = Flask(__name__)

DATABASE = 'database.db'

# ----- Basic Bot Detection Setup -----
KNOWN_BOT_PATTERNS = [
    'bot', 'spider', 'crawl', 'slurp', 'facebookexternalhit', 'mediapartners-google'
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
    """Create the table if it doesn't exist."""
    with get_db() as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS redirect_links (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                short_id TEXT UNIQUE NOT NULL,
                original_url TEXT NOT NULL,
                max_redirects INTEGER NOT NULL,
                current_count INTEGER NOT NULL DEFAULT 0,
                trigger_email TEXT,
                trigger_webhook TEXT
            );
        ''')
    print("Database initialized.")

def generate_short_id():
    """Generate a random short identifier."""
    import random
    import string
    return ''.join(random.choices(string.ascii_letters + string.digits, k=6))


# ----- Notification Triggers -----
def send_email_notification(email_address, short_id, original_url):
    """
    Stub for sending an email notification. 
    In production, integrate with an email service like SendGrid, Mailgun, or SES.
    """
    print(f"[DEBUG] Sending email to {email_address}: Link {short_id} was just used to redirect to {original_url}.")


def trigger_webhook(webhook_url, short_id, original_url):
    """
    Stub for triggering a webhook (e.g. IFTTT, Zapier).
    """
    payload = {
        'short_id': short_id,
        'original_url': original_url,
        'event': 'redirect_occurred'
    }
    try:
        response = requests.post(webhook_url, json=payload)
        print(f"[DEBUG] Webhook response status: {response.status_code}")
    except Exception as e:
        print(f"[ERROR] Failed to call webhook: {e}")


# ----- Flask Routes -----

@app.route('/', methods=['GET', 'POST'])
def index():
    """
    Displays a form (using Bootstrap) to create a new redirect link.
    On POST, it handles the creation logic.
    """
    if request.method == 'POST':
        original_url = request.form.get('original_url', '').strip()
        max_redirects = request.form.get('max_redirects', '1')
        trigger_email = request.form.get('trigger_email', '').strip()
        trigger_webhook = request.form.get('trigger_webhook', '').strip()

        # Basic validation
        if not original_url:
            return render_template('index.html', error="Original URL is required.")
        if not re.match(r'^https?://', original_url):
            return render_template('index.html', error="URL must start with http:// or https://")

        try:
            max_redirects = int(max_redirects)
            if max_redirects < 1 or max_redirects > 1000:
                raise ValueError
        except ValueError:
            return render_template('index.html', error="Max redirects must be an integer between 1 and 1000.")

        short_id = generate_short_id()

        # Insert into DB
        with get_db() as conn:
            conn.execute('''
                INSERT INTO redirect_links (short_id, original_url, max_redirects, current_count, trigger_email, trigger_webhook)
                VALUES (?, ?, ?, 0, ?, ?);
            ''', (short_id, original_url, max_redirects, trigger_email, trigger_webhook))

        # Return or show result
        short_url = request.url_root.rstrip('/') + url_for('redirect_handler', short_id=short_id)
        return render_template('index.html', short_url=short_url)

    # GET request: show the form
    return render_template('index.html')


@app.route('/r/<short_id>')
def redirect_handler(short_id):
    """
    When someone accesses /r/<short_id>, we check:
    - If it exists in DB
    - If current_count < max_redirects
    - Check if request is from a bot
    - If valid (and not a bot), increment count & trigger notifications
    - Then 301 redirect to original URL
    - Otherwise, return an 'expired' page
    """
    user_agent = request.headers.get('User-Agent', '')
    with get_db() as conn:
        row = conn.execute('SELECT * FROM redirect_links WHERE short_id = ?;', (short_id,)).fetchone()

        if not row:
            return render_template('expired.html', message="This link does not exist."), 404

        # Check redirect limit
        if row['current_count'] >= row['max_redirects']:
            # Already exceeded limit
            return render_template('expired.html', message="This link has expired."), 200

        # Determine if we should increment and trigger notifications
        if not is_bot(user_agent):
            new_count = row['current_count'] + 1
            conn.execute(
                'UPDATE redirect_links SET current_count = ? WHERE short_id = ?',
                (new_count, short_id)
            )

            # Triggers
            if row['trigger_email']:
                send_email_notification(row['trigger_email'], short_id, row['original_url'])
            if row['trigger_webhook']:
                trigger_webhook(row['trigger_webhook'], short_id, row['original_url'])

    # Do the actual redirect
    return redirect(row['original_url'], code=301)


# ----- Main Entrypoint -----
if __name__ == '__main__':
    # Initialize DB schema
    init_db()

    # Run Flask in debug mode (not for production)
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=True)
