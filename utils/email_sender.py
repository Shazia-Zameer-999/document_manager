import smtplib
from email.message import EmailMessage
import os
from dotenv import load_dotenv

load_dotenv()

SENDER_EMAIL = os.getenv('SENDER_EMAIL')
APP_PASSWORD = os.getenv('APP_PASSWORD')

def send_reset_email(to_email, reset_link):
    msg = EmailMessage()
    msg['Subject'] = 'Reset Your Password'
    msg['From'] = SENDER_EMAIL
    msg['To'] = to_email

    msg.set_content(f"""
Hi,

Click the link below to reset your password:

{reset_link}

If you did not request this, please ignore this email.
""")

    with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
        smtp.login(SENDER_EMAIL, APP_PASSWORD)
        smtp.send_message(msg)