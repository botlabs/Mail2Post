import praw
import requests
import time
import email
import imaplib

#### HOW TO CONFIGURE ####
# 1. Do these steps: https://github.com/botlabs/bestpractices/blob/master/README.md#configuring-bots
# 2. Fill out MAIL_HOST, MAIL_PORT, MAIL_USERNAME, MAIL_PASSWORD fields.
#      This info can be found by googling "imap [your email provider]"
# 3. Fill out SUBREDDIT field.
#
# All emails sent to the account must be of content-type "text/plain."

# Account settings (private)
USERNAME = ''
PASSWORD = ''

# OAuth settings (private)
CLIENT_ID = ''
CLIENT_SECRET = ''
REDIRECT_URI = 'http://127.0.0.1:65010/authorize_callback'
# Configuration Settings
USER_AGENT = "mail2post | /u/YOUR_MAIN_ACCOUNT_USERNAME"
AUTH_TOKENS = ["identity","read", "submit"]
EXPIRY_BUFFER = 60

# Mail settings
MAIL_HOST = ""
MAIL_PORT = 993
MAIL_USERNAME = ""
MAIL_PASSWORD = ""

SUBREDDIT = ""

T_SUBMISSION_HEADER = "[{0}]:#\n\n"

def get_session_data():
    response = requests.post("https://www.reddit.com/api/v1/access_token",
      auth = requests.auth.HTTPBasicAuth(CLIENT_ID, CLIENT_SECRET),
      data = {"grant_type": "password", "username": USERNAME, "password": PASSWORD},
      headers = {"User-Agent": USER_AGENT})
    response_dict = dict(response.json())
    response_dict['retrieved_at'] = time.time()
    return response_dict

def get_praw():
    r = praw.Reddit(USER_AGENT)
    r.set_oauth_app_info(CLIENT_ID, CLIENT_SECRET, REDIRECT_URI)
    session_data = get_session_data()
    r.set_access_credentials(set(AUTH_TOKENS), session_data['access_token'])
    return (r, session_data)

def retrieve(host, port, username, password):
    m = imaplib.IMAP4_SSL(host, port)
    m.login(username, password)
    m.select()
    (typ, data) = m.search(None, 'ALL')
    for num in data[0].split():
        typ, data_part = m.fetch(num, '(RFC822)')
        data = data_part[0][1]
        return email.message_from_string(data.decode("utf-8"))

def already_posted(r, msg_id):
    for post in r.get_redditor(USERNAME).get_submitted(limit=None):
        if post.is_self and T_SUBMISSION_HEADER.format(msg_id) in post.selftext:
            return True

def main(r, session_data):
    EXPIRES_AT = session_data['retrieved_at'] + session_data['expires_in']
    while True:
        if time.time() >= EXPIRES_AT - EXPIRY_BUFFER:
            raise praw.errors.OAuthInvalidToken
        ## Main
        msg = retrieve(MAIL_HOST, MAIL_PORT, MAIL_USERNAME, MAIL_PASSWORD)
        msg_id = msg.get("Message-ID")
        if not already_posted(r, msg_id):
            if msg.get_content_type() != "text/plain":
                print("Failed: Message is not 'text/plain': " + msg_id)
            else:
                title = msg.get("Subject")
                body = T_SUBMISSION_HEADER.format(msg_id) + msg.get_payload()
                r.submit(SUBREDDIT, title, body)
                print("Submitted: " + title)
        time.sleep(30)

if __name__ == "__main__":
    while True:
        try:
            print("Retrieving new OAuth token...")
            main(*get_praw())
        except praw.errors.OAuthInvalidToken:
            print("OAuth token expired.")
        except praw.errors.HTTPException:
            print("HTTP error. Retrying in 10...")
            time.sleep(10)
