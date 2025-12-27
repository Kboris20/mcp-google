import os
import base64
from typing import List

from fastmcp import FastMCP
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build

SCOPES = [
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/gmail.send",
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/gmail.labels",
]

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
GOOGLE_REFRESH_TOKEN = os.getenv("GOOGLE_REFRESH_TOKEN")
GOOGLE_TOKEN_URI = "https://oauth2.googleapis.com/token"


def get_gmail_service():
    if not (GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET and GOOGLE_REFRESH_TOKEN):
        raise RuntimeError("Variables OAuth manquantes (client_id, client_secret, refresh_token).")
    creds = Credentials(
        None,
        refresh_token=GOOGLE_REFRESH_TOKEN,
        token_uri=GOOGLE_TOKEN_URI,
        client_id=GOOGLE_CLIENT_ID,
        client_secret=GOOGLE_CLIENT_SECRET,
        scopes=SCOPES,
    )
    return build("gmail", "v1", credentials=creds)


mcp = FastMCP("mcp_google")


@mcp.tool
def gmail_list_messages(query: str = "is:unread", max_results: int = 10) -> dict:
    """
    Liste des messages Gmail suivant une requête (ex: 'is:unread').
    Retourne une liste d'IDs.
    """
    service = get_gmail_service()
    res = service.users().messages().list(userId="me", q=query, maxResults=max_results).execute()
    return {"messages": res.get("messages", []), "count": len(res.get("messages", []))}


@mcp.tool
def gmail_get_message_summary(message_id: str) -> dict:
    """
    Récupère un résumé exploitable : sujet, expéditeur, snippet, body tronqué.
    """
    service = get_gmail_service()
    msg = service.users().messages().get(userId="me", id=message_id, format="full").execute()

    headers = msg.get("payload", {}).get("headers", [])
    subject = next((h["value"] for h in headers if h["name"].lower() == "subject"), "")
    from_ = next((h["value"] for h in headers if h["name"].lower() == "from"), "")
    snippet = msg.get("snippet", "")

    body_text = ""
    payload = msg.get("payload", {})
    if payload.get("mimeType", "").startswith("text/"):
        data = payload.get("body", {}).get("data")
        if data:
            body_text = base64.urlsafe_b64decode(data.encode("utf-8")).decode("utf-8", errors="ignore")
    else:
        parts = payload.get("parts", [])
        for part in parts:
            if part.get("mimeType") == "text/plain":
                data = part.get("body", {}).get("data")
                if data:
                    body_text = base64.urlsafe_b64decode(data.encode("utf-8")).decode("utf-8", errors="ignore")
                    break

    if len(body_text) > 2000:
        body_text = body_text[:2000] + "\n...[tronqué]"

    summary_text = f"From: {from_}\nSubject: {subject}\nSnippet: {snippet}\n\nBody:\n{body_text}"

    return {
        "id": message_id,
        "subject": subject,
        "from": from_,
        "snippet": snippet,
        "summary_text": summary_text,
    }


@mcp.tool
def gmail_delete_messages(message_ids: List[str]) -> dict:
    """
    Supprime une liste de messages Gmail.
    """
    service = get_gmail_service()
    deleted, failed = [], []
    for mid in message_ids:
        try:
            service.users().messages().delete(userId="me", id=mid).execute()
            deleted.append(mid)
        except Exception:
            failed.append(mid)
    return {"deleted": deleted, "failed": failed}


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", "8000"))
    mcp.run(transport="http", host="0.0.0.0", port=port, path="/mcp")