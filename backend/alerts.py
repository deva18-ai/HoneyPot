"""
Optional outbound alerts.

Keep disabled for the first-semester local demo. If your guide approves
an integration, configure it with environment variables and never commit
secrets to Git.
"""
import os

def telegram_enabled():
    return bool(os.getenv("TELEGRAM_BOT_TOKEN") and os.getenv("TELEGRAM_CHAT_ID"))

def email_enabled():
    return bool(os.getenv("SMTP_HOST") and os.getenv("SMTP_USER") and os.getenv("SMTP_PASSWORD"))

def send_high_risk_message(message):
    # Deliberately a no-op unless the team implements and approves an external channel.
    return {"telegram": telegram_enabled(), "email": email_enabled(), "message": message}
