import base64
import os
import re
from bs4 import BeautifulSoup
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# Create a directory for attachments
os.makedirs("attachments", exist_ok=True)

# OAuth2 scope
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

# Authenticate and build Gmail API service
flow = InstalledAppFlow.from_client_secrets_file("credentials.json", SCOPES)
creds = flow.run_local_server(port=0)
service = build('gmail', 'v1', credentials=creds)

# Helper to clean email text
def clean_text(text):
    return re.sub(r'\s+', ' ', text).strip()

# Extract all URLs
def extract_links(text):
    return re.findall(r'https?://[^\s<>"]+', text)

# Extract the email body (plain or HTML) recursively
def extract_body(payload):
    if 'parts' in payload:
        for part in payload['parts']:
            if part['mimeType'] == 'text/plain':
                data = part['body'].get('data')
                if data:
                    return base64.urlsafe_b64decode(data.encode('ASCII')).decode('utf-8').strip()
            elif part['mimeType'] == 'text/html':
                data = part['body'].get('data')
                if data:
                    html = base64.urlsafe_b64decode(data.encode('ASCII')).decode('utf-8')
                    soup = BeautifulSoup(html, 'html.parser')
                    return soup.get_text().strip()
            # Recursively check nested parts
            nested = extract_body(part)
            if nested:
                return nested
    else:
        data = payload['body'].get('data')
        if data:
            return base64.urlsafe_b64decode(data.encode('ASCII')).decode('utf-8').strip()
    return ""

# Download and save attachments
def save_attachments(msg_id, parts):
    saved_files = []
    for part in parts:
        filename = part.get("filename")
        body = part.get("body", {})
        if filename and "attachmentId" in body:
            attachment = service.users().messages().attachments().get(
                userId='me',
                messageId=msg_id,
                id=body["attachmentId"]
            ).execute()

            data = base64.urlsafe_b64decode(attachment['data'].encode('ASCII'))
            filepath = os.path.join("attachments", filename)
            with open(filepath, "wb") as f:
                f.write(data)
            saved_files.append(filepath)

        # Recursively handle nested parts
        if "parts" in part:
            saved_files.extend(save_attachments(msg_id, part["parts"]))

    return saved_files

# Fetch latest messages
def fetch_emails(max_results=5):
    emails = []

    try:
        results = service.users().messages().list(userId='me', labelIds=['INBOX'], maxResults=max_results).execute()
        messages = results.get('messages', [])

        for msg in messages:
            msg_data = service.users().messages().get(userId='me', id=msg['id'], format='full').execute()
            headers = msg_data['payload']['headers']

            subject = next((h['value'] for h in headers if h['name'] == 'Subject'), "(No Subject)")
            sender = next((h['value'] for h in headers if h['name'] == 'From'), "(Unknown)")
            date = next((h['value'] for h in headers if h['name'] == 'Date'), "(No Date)")

            body = extract_body(msg_data['payload'])
            body = clean_text(body)
            links = extract_links(body)
            attachments = save_attachments(msg['id'], msg_data['payload'].get('parts', []))

            emails.append({
                "subject": subject,
                "from": sender,
                "date": date,
                "body": body[:1000],  # Limit for LLMs
                "links": links,
                "attachments": attachments
            })

    except HttpError as error:
        print(f"An error occurred: {error}")

    return emails

email_data = fetch_emails()
# for i, email in enumerate(email_data, 1):
#     print(f"\n📩 Email #{i}")
#     print(f"From: {email['from']}")
#     print(f"Subject: {email['subject']}")
#     print(f"Date: {email['date']}")
#     print(f"Body: {email['body'][:200]}...")
#     print(f"Links: {email['links']}")
#     print(f"Attachments saved: {email['attachments']}")

# ✅ Save to JSON
import json
with open("email.json", "w", encoding="utf-8") as f:
    json.dump(email_data, f, indent=4, ensure_ascii=False)

print("\n✅ All emails saved to email.json")