import os
import sqlite3
import re
from datetime import datetime
from flask import Flask, request, redirect, render_template, url_for
import requests

app = Flask(__name__)

DATABASE = 'database.db'

# For SendLayer
SENDLAYER_API_KEY = os.environ.get('SENDLAYER_API_KEY')  # e.g. store in Render env variable
SENDLAYER_FROM_EMAIL = os.environ.get('SENDLAYER_FROM_EMAIL', 'noreply@301er.io')
SENDLAYER_FROM_NAME = os.environ.get("SENDLAYER_FROM_NAME", "301er.com")

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
    """Create or update the table if it doesn't exist, adding any new columns if necessary."""
    with get_db() as conn:
        # Create the base table if needed
        conn.execute('''
            CREATE TABLE IF NOT EXISTS redirect_links (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                short_id TEXT UNIQUE NOT NULL,
                original_url TEXT NOT NULL,
                max_redirects INTEGER NOT NULL,
                current_count INTEGER NOT NULL DEFAULT 0,
                trigger_email TEXT,
                exceeded_url TEXT,
                email_count INTEGER NOT NULL DEFAULT 0
            );
        ''')
    print("Database initialized.")

def generate_short_id():
    """Generate a random short identifier."""
    import random
    import string
    return ''.join(random.choices(string.ascii_letters + string.digits, k=6))


# ----- Notification Triggers -----
import requests

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

    # According to the latest docs, the base URL is console.sendlayer.com/api/v1/
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

    # Notice how "From", "To", "Subject", "ContentType", "HTMLContent", "PlainContent"
    # are capitalized to match the docs exactly.
    payload = {
        "From": {
            # "name": "Optional Sender Name",
            "email": from_email
        },
        "To": [
            {
                # "name": "Optional Recipient Name",
                "email": to_email
            }
        ],
        "Subject": subject,
        "ContentType": "HTML",         # Must match "HTML" or "text" or whichever type you intend.
        "HTMLContent": html_content,
        "PlainContent": plain_content

        # Optional keys you can include:
        # "Tags": ["tag1", "tag2"],
        # "Headers": {
        #     "X-Mailer": "Flask Application"
        # },
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
    Displays a form (using Bootstrap) to create a new redirect link.
    On POST, it handles the creation logic.
    """
    if request.method == 'POST':
        original_url = request.form.get('original_url', '').strip()
        max_redirects = request.form.get('max_redirects', '1')
        trigger_email = request.form.get('trigger_email', '').strip()
        exceeded_url = request.form.get('exceeded_url', '').strip()

        # Basic validation
        if not original_url:
            return render_template('index.html', error="Original URL is required.")
        if not re.match(r'^https?://', original_url, re.IGNORECASE):
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
                INSERT INTO redirect_links
                (short_id, original_url, max_redirects, current_count, trigger_email, exceeded_url, email_count)
                VALUES (?, ?, ?, 0, ?, ?, 0);
            ''', (short_id, original_url, max_redirects, trigger_email, exceeded_url))

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
    - If current_count < max_redirects -> increment, optionally send email (up to 5 times), redirect to original
    - If limit is exceeded -> redirect to 'exceeded_url' if provided, otherwise show 'expired' page
    - Filter out bots by user-agent (no increment or email if bot)
    """
    user_agent = request.headers.get('User-Agent', '')
    ip = request.remote_addr or 'Unknown IP'
    click_time = datetime.utcnow().isoformat()

    with get_db() as conn:
        row = conn.execute('SELECT * FROM redirect_links WHERE short_id = ?;', (short_id,)).fetchone()

        if not row:
            return render_template('expired.html', message="This link does not exist."), 404

        # If we've already reached the limit
        if row['current_count'] >= row['max_redirects']:
            # If there's an exceeded_url, redirect there; else show an expired page
            if row['exceeded_url']:
                return redirect(row['exceeded_url'], code=301)
            else:
                return render_template('expired.html', message="This link has expired."), 200

        # We haven't hit the limit yet
        # Check if it's a bot
        if is_bot(user_agent):
            # Bot: do NOT increment or send email, but still go to original_url?
            # Or skip redirect? You can decide. Let's skip the increment & triggers, but still redirect.
            return redirect(row['original_url'], code=301)
        else:
            new_count = row['current_count'] + 1
            # Also see if we can still send an email (only up to 5 times)
            new_email_count = row['email_count']
            if row['trigger_email'] and row['email_count'] < 5:
                # Send the email
                send_email_notification(
                    api_key=SENDLAYER_API_KEY,
                    from_email=SENDLAYER_FROM_EMAIL,
                    to_email=row['trigger_email'],
                    short_id=row['short_id'],
                    original_url=row['original_url'],
                    user_agent=user_agent,
                    ip=ip,
                    click_time=click_time
                )
                new_email_count += 1

            # Update DB
            conn.execute('''
                UPDATE redirect_links
                SET current_count = ?, email_count = ?
                WHERE short_id = ?
            ''', (new_count, new_email_count, short_id))

    # Finally, redirect to the original URL
    return redirect(row['original_url'], code=301)


# ----- Main Entrypoint -----
# Move init_db() outside of the if __name__ == '__main__' block
# so it's called on Render when Gunicorn starts.
init_db()

if __name__ == '__main__':
    # For local dev
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=True)
