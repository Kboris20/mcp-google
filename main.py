import os
import base64
import re
from typing import List, Optional

from fastmcp import FastMCP
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from email.mime.text import MIMEText

# ==================== Config OAuth ====================

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
    """Construit et retourne un client Gmail authentifié."""
    if not (GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET and GOOGLE_REFRESH_TOKEN):
        raise RuntimeError(
            "Variables OAuth manquantes (GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_REFRESH_TOKEN)."
        )
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


# ==================== Utilitaires ====================

def _normalize_label_name(name: str) -> str:
    """Normalise un nom de label pour comparaison."""
    return re.sub(r"\s+", " ", name.strip().lower())


def _extract_text_from_payload(payload: dict, max_length: int = 2000) -> str:
    """Extrait le texte brut d'un payload Gmail (text/plain + multipart)."""
    mime_type = payload.get("mimeType", "")
    body_text = ""

    if mime_type.startswith("text/plain"):
        data = payload.get("body", {}).get("data")
        if data:
            body_text = base64.urlsafe_b64decode(data.encode("utf-8")).decode(
                "utf-8", errors="ignore"
            )
    elif mime_type.startswith("multipart/"):
        for part in payload.get("parts", []):
            if part.get("mimeType") == "text/plain":
                data = part.get("body", {}).get("data")
                if data:
                    body_text = base64.urlsafe_b64decode(data.encode("utf-8")).decode(
                        "utf-8", errors="ignore"
                    )
                    break
            elif part.get("mimeType", "").startswith("multipart/"):
                body_text = _extract_text_from_payload(part, max_length)
                if body_text:
                    break

    if len(body_text) > max_length:
        body_text = body_text[:max_length] + "\n...[texte tronqué]"

    return body_text


# ==================== Tools : Lecture d'emails ====================

@mcp.tool
def gmail_list_messages(
    query: str = "is:unread",
    max_results: int = 10,
    # Paramètres système n8n (ignorés)
    sessionId: Optional[str] = None,
    action: Optional[str] = None,
    chatInput: Optional[str] = None,
    toolCallId: Optional[str] = None,
) -> dict:
    """
    Liste les messages Gmail selon une requête.

    Args:
        query: Requête Gmail (ex: 'is:unread', 'from:xxx', 'subject:urgent').
        max_results: Nombre max (1–100).
    """
    try:
        service = get_gmail_service()
        max_results_clamped = min(max(1, max_results), 100)

        res = service.users().messages().list(
            userId="me", q=query, maxResults=max_results_clamped
        ).execute()
        messages = res.get("messages", [])

        return {
            "success": True,
            "count": len(messages),
            "messages": messages,
            "query_used": query,
        }
    except HttpError as e:
        return {
            "success": False,
            "error": f"Erreur Gmail API: {e}",
            "count": 0,
            "messages": [],
        }


@mcp.tool
def gmail_get_message_summary(
    message_id: str,
    # Paramètres système n8n (ignorés)
    sessionId: Optional[str] = None,
    action: Optional[str] = None,
    chatInput: Optional[str] = None,
    toolCallId: Optional[str] = None,
) -> dict:
    """
    Récupère un résumé détaillé et exploitable d'un message Gmail.

    Args:
        message_id: ID du message Gmail
    
    Returns:
        dict avec: id, subject, from, to, date, snippet, labels, body_preview, summary_text
    """
    try:
        service = get_gmail_service()
        msg = service.users().messages().get(
            userId="me", id=message_id, format="full"
        ).execute()

        headers = msg.get("payload", {}).get("headers", [])
        subject = next(
            (h["value"] for h in headers if h["name"].lower() == "subject"),
            "(sans objet)",
        )
        from_ = next(
            (h["value"] for h in headers if h["name"].lower() == "from"), ""
        )
        to_ = next((h["value"] for h in headers if h["name"].lower() == "to"), "")
        date_ = next(
            (h["value"] for h in headers if h["name"].lower() == "date"), ""
        )

        snippet = msg.get("snippet", "")
        labels = msg.get("labelIds", [])
        payload = msg.get("payload", {})
        body_text = _extract_text_from_payload(payload, max_length=2000)

        summary_text = f"""Email ID: {message_id}
De: {from_}
À: {to_}
Date: {date_}
Sujet: {subject}
Labels: {', '.join(labels)}

Aperçu: {snippet}

Corps du message:
{body_text}
"""

        return {
            "success": True,
            "id": message_id,
            "subject": subject,
            "from": from_,
            "to": to_,
            "date": date_,
            "snippet": snippet,
            "labels": labels,
            "body_preview": body_text[:500],
            "summary_text": summary_text,
        }
    except HttpError as e:
        return {
            "success": False,
            "error": f"Erreur lors de la récupération du message: {e}",
            "id": message_id,
        }


@mcp.tool
def gmail_get_multiple_summaries(
    message_ids: List[str],
    # Paramètres système n8n (ignorés)
    sessionId: Optional[str] = None,
    action: Optional[str] = None,
    chatInput: Optional[str] = None,
    toolCallId: Optional[str] = None,
) -> dict:
    """
    Récupère les résumés de plusieurs messages en une seule fois.
    Optimisé pour traiter des lots d'emails.
    
    Args:
        message_ids: Liste d'IDs de messages Gmail
    
    Returns:
        dict avec 'summaries' (liste de résumés) et 'errors' (liste des échecs)
    """
    summaries = []
    errors = []
    for msg_id in message_ids:
        r = gmail_get_message_summary(msg_id)
        if r.get("success"):
            summaries.append(r)
        else:
            errors.append({"id": msg_id, "error": r.get("error")})
    return {
        "success": True,
        "count": len(summaries),
        "summaries": summaries,
        "errors": errors,
    }


# ==================== Tools : Labels ====================

@mcp.tool
def gmail_list_labels(
    # Paramètres système n8n (ignorés)
    sessionId: Optional[str] = None,
    action: Optional[str] = None,
    chatInput: Optional[str] = None,
    toolCallId: Optional[str] = None,
) -> dict:
    """
    Liste tous les labels Gmail de l'utilisateur.
    
    Returns:
        dict avec 'labels' (liste d'objets {id, name, type})
    """
    try:
        service = get_gmail_service()
        results = service.users().labels().list(userId="me").execute()
        labels = results.get("labels", [])

        user_labels = [
            {"id": lbl["id"], "name": lbl["name"], "type": lbl.get("type", "user")}
            for lbl in labels
        ]

        return {
            "success": True,
            "count": len(user_labels),
            "labels": user_labels,
        }
    except HttpError as e:
        return {"success": False, "error": f"Erreur labels: {e}", "labels": []}


@mcp.tool
def gmail_find_label(
    name: str,
    fuzzy: bool = True,
    # Paramètres système n8n (ignorés)
    sessionId: Optional[str] = None,
    action: Optional[str] = None,
    chatInput: Optional[str] = None,
    toolCallId: Optional[str] = None,
) -> dict:
    """
    Recherche un label par nom (exact ou approximatif).
    Utile pour éviter les doublons avant de créer un nouveau label.
    
    Args:
        name: Nom du label recherché
        fuzzy: Si True, recherche aussi des correspondances approximatives
    
    Returns:
        dict avec match_type ('exact', 'fuzzy', 'none') et label(s) trouvé(s)
    """
    try:
        service = get_gmail_service()
        results = service.users().labels().list(userId="me").execute()
        labels = results.get("labels", [])

        target = _normalize_label_name(name)
        exact_match = None
        fuzzy_candidates = []

        for lbl in labels:
            lbl_name = lbl.get("name", "")
            norm = _normalize_label_name(lbl_name)
            if norm == target:
                exact_match = lbl
                break
            if fuzzy and (target in norm or norm in target):
                fuzzy_candidates.append(lbl)

        if exact_match:
            return {"success": True, "match_type": "exact", "label": exact_match}
        if fuzzy_candidates:
            return {
                "success": True,
                "match_type": "fuzzy",
                "candidates": fuzzy_candidates,
            }
        return {"success": True, "match_type": "none"}
    except HttpError as e:
        return {"success": False, "error": f"Erreur recherche label: {e}"}


@mcp.tool
def gmail_create_label(
    name: str,
    # Paramètres système n8n (ignorés)
    sessionId: Optional[str] = None,
    action: Optional[str] = None,
    chatInput: Optional[str] = None,
    toolCallId: Optional[str] = None,
) -> dict:
    """
    Crée un nouveau label Gmail.
    
    Args:
        name: Nom du nouveau label
    
    Returns:
        dict avec le label créé
    """
    try:
        # vérifier si existe déjà
        existing = gmail_find_label(name, fuzzy=False)
        if existing.get("match_type") == "exact":
            return {
                "success": False,
                "error": f"Le label '{name}' existe déjà.",
                "existing_label": existing.get("label"),
            }

        service = get_gmail_service()
        label_object = {
            "name": name,
            "labelListVisibility": "labelShow",
            "messageListVisibility": "show",
        }
        created = service.users().labels().create(
            userId="me", body=label_object
        ).execute()
        return {"success": True, "label": created}
    except HttpError as e:
        return {"success": False, "error": f"Erreur création label: {e}"}


@mcp.tool
def gmail_delete_label(
    label_id: str,
    # Paramètres système n8n (ignorés)
    sessionId: Optional[str] = None,
    action: Optional[str] = None,
    chatInput: Optional[str] = None,
    toolCallId: Optional[str] = None,
) -> dict:
    """
    Supprime un label Gmail (n'affecte pas les messages, retire juste le label).
    
    Args:
        label_id: ID du label à supprimer
    
    Returns:
        dict confirmant la suppression
    """
    try:
        service = get_gmail_service()
        service.users().labels().delete(userId="me", id=label_id).execute()
        
        return {
            "success": True,
            "message": f"Label {label_id} supprimé avec succès."
        }
    except HttpError as e:
        return {
            "success": False,
            "error": f"Erreur lors de la suppression du label: {e}"
        }


@mcp.tool
def gmail_add_labels_to_messages(
    message_ids: List[str],
    label_names: List[str],
    create_if_missing: bool = True,
    # Paramètres système n8n (ignorés)
    sessionId: Optional[str] = None,
    action: Optional[str] = None,
    chatInput: Optional[str] = None,
    toolCallId: Optional[str] = None,
) -> dict:
    """
    Ajoute un ou plusieurs labels à une liste de messages.
    Peut créer automatiquement les labels s'ils n'existent pas.
    
    Args:
        message_ids: Liste d'IDs de messages
        label_names: Liste de noms de labels à appliquer
        create_if_missing: Si True, crée les labels manquants automatiquement
    
    Returns:
        dict avec le nombre de messages traités et les détails
    """
    try:
        service = get_gmail_service()
        label_ids = []

        for label_name in label_names:
            found = gmail_find_label(label_name, fuzzy=False)
            if found.get("match_type") == "exact":
                label_ids.append(found["label"]["id"])
            elif create_if_missing:
                created = gmail_create_label(label_name)
                if created.get("success"):
                    label_ids.append(created["label"]["id"])
                else:
                    return {
                        "success": False,
                        "error": f"Impossible de créer le label '{label_name}'",
                    }
            else:
                return {
                    "success": False,
                    "error": f"Label '{label_name}' introuvable.",
                }

        succeeded, failed = [], []
        for msg_id in message_ids:
            try:
                service.users().messages().modify(
                    userId="me",
                    id=msg_id,
                    body={"addLabelIds": label_ids},
                ).execute()
                succeeded.append(msg_id)
            except HttpError:
                failed.append(msg_id)

        return {
            "success": True,
            "labels_applied": label_names,
            "messages_succeeded": len(succeeded),
            "messages_failed": len(failed),
            "succeeded_ids": succeeded,
            "failed_ids": failed,
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool
def gmail_remove_labels_from_messages(
    message_ids: List[str],
    label_names: List[str],
    # Paramètres système n8n (ignorés)
    sessionId: Optional[str] = None,
    action: Optional[str] = None,
    chatInput: Optional[str] = None,
    toolCallId: Optional[str] = None,
) -> dict:
    """
    Retire un ou plusieurs labels d'une liste de messages.
    
    Args:
        message_ids: Liste d'IDs de messages
        label_names: Liste de noms de labels à retirer
    
    Returns:
        dict avec le nombre de messages traités
    """
    try:
        service = get_gmail_service()
        label_ids = []

        for label_name in label_names:
            found = gmail_find_label(label_name, fuzzy=False)
            if found.get("match_type") == "exact":
                label_ids.append(found["label"]["id"])
            else:
                return {
                    "success": False,
                    "error": f"Label '{label_name}' introuvable.",
                }

        succeeded, failed = [], []
        for msg_id in message_ids:
            try:
                service.users().messages().modify(
                    userId="me",
                    id=msg_id,
                    body={"removeLabelIds": label_ids},
                ).execute()
                succeeded.append(msg_id)
            except HttpError:
                failed.append(msg_id)

        return {
            "success": True,
            "labels_removed": label_names,
            "messages_succeeded": len(succeeded),
            "messages_failed": len(failed),
        }
    except Exception as e:
        return {"success": False, "error": str(e)}

@mcp.tool
def gmail_add_label(
    message_id: str,
    label_name: str,
    create_if_missing: bool = True,
    # Paramètres système n8n (ignorés)
    sessionId: Optional[str] = None,
    action: Optional[str] = None,
    chatInput: Optional[str] = None,
    toolCallId: Optional[str] = None,
) -> dict:
    """
    Ajoute un libellé à un message Gmail.
    Si le libellé n'existe pas, il peut être créé automatiquement.
    
    Args:
        message_id: ID du message Gmail
        label_name: Nom du libellé à ajouter (ex: "Publicité")
        create_if_missing: Si True, crée le libellé s'il n'existe pas
    
    Returns:
        dict confirmant l'ajout du libellé
    """
    try:
        service = get_gmail_service()
        
        # Trouver ou créer le libellé
        found = gmail_find_label(label_name, fuzzy=False)
        if found.get("match_type") == "exact":
            label_id = found["label"]["id"]
        elif create_if_missing:
            created = gmail_create_label(label_name)
            if created.get("success"):
                label_id = created["label"]["id"]
            else:
                return {
                    "success": False,
                    "error": f"Impossible de créer le libellé '{label_name}'",
                }
        else:
            return {
                "success": False,
                "error": f"Libellé '{label_name}' introuvable.",
            }
        
        # Ajouter le libellé au message
        service.users().messages().modify(
            userId="me",
            id=message_id,
            body={"addLabelIds": [label_id]},
        ).execute()
        
        return {
            "success": True,
            "message_id": message_id,
            "label_added": label_name,
            "label_id": label_id,
        }
    except HttpError as e:
        return {
            "success": False,
            "error": f"Erreur lors de l'ajout du libellé: {e}",
        }


@mcp.tool
def gmail_remove_label(
    message_id: str,
    label_name: str,
    # Paramètres système n8n (ignorés)
    sessionId: Optional[str] = None,
    action: Optional[str] = None,
    chatInput: Optional[str] = None,
    toolCallId: Optional[str] = None,
) -> dict:
    """
    Retire un libellé d'un message Gmail.
    
    Args:
        message_id: ID du message Gmail
        label_name: Nom du libellé à retirer (ex: "INBOX" pour archiver)
    
    Returns:
        dict confirmant le retrait du libellé
    """
    try:
        service = get_gmail_service()
        
        # Trouver le libellé
        found = gmail_find_label(label_name, fuzzy=False)
        if found.get("match_type") != "exact":
            return {
                "success": False,
                "error": f"Libellé '{label_name}' introuvable.",
            }
        
        label_id = found["label"]["id"]
        
        # Retirer le libellé du message
        service.users().messages().modify(
            userId="me",
            id=message_id,
            body={"removeLabelIds": [label_id]},
        ).execute()
        
        return {
            "success": True,
            "message_id": message_id,
            "label_removed": label_name,
            "label_id": label_id,
        }
    except HttpError as e:
        return {
            "success": False,
            "error": f"Erreur lors du retrait du libellé: {e}",
        }


# ==================== Tools : Actions messages ====================

@mcp.tool
def gmail_mark_as_read(
    message_ids: List[str],
    # Paramètres système n8n (ignorés)
    sessionId: Optional[str] = None,
    action: Optional[str] = None,
    chatInput: Optional[str] = None,
    toolCallId: Optional[str] = None,
) -> dict:
    """
    Marque des messages comme lus.
    
    Args:
        message_ids: Liste d'IDs de messages
    
    Returns:
        dict avec le nombre de messages marqués
    """
    try:
        service = get_gmail_service()
        succeeded, failed = [], []
        for msg_id in message_ids:
            try:
                service.users().messages().modify(
                    userId="me",
                    id=msg_id,
                    body={"removeLabelIds": ["UNREAD"]},
                ).execute()
                succeeded.append(msg_id)
            except HttpError:
                failed.append(msg_id)

        return {
            "success": True,
            "marked_as_read": len(succeeded),
            "failed": len(failed),
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool
def gmail_mark_as_unread(
    message_ids: List[str],
    # Paramètres système n8n (ignorés)
    sessionId: Optional[str] = None,
    action: Optional[str] = None,
    chatInput: Optional[str] = None,
    toolCallId: Optional[str] = None,
) -> dict:
    """
    Marque des messages comme non lus.
    
    Args:
        message_ids: Liste d'IDs de messages
    
    Returns:
        dict avec le nombre de messages marqués
    """
    try:
        service = get_gmail_service()
        succeeded, failed = [], []
        for msg_id in message_ids:
            try:
                service.users().messages().modify(
                    userId="me",
                    id=msg_id,
                    body={"addLabelIds": ["UNREAD"]},
                ).execute()
                succeeded.append(msg_id)
            except HttpError:
                failed.append(msg_id)

        return {
            "success": True,
            "marked_as_unread": len(succeeded),
            "failed": len(failed),
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool
def gmail_star_messages(
    message_ids: List[str],
    # Paramètres système n8n (ignorés)
    sessionId: Optional[str] = None,
    action: Optional[str] = None,
    chatInput: Optional[str] = None,
    toolCallId: Optional[str] = None,
) -> dict:
    """
    Ajoute une étoile à des messages.
    
    Args:
        message_ids: Liste d'IDs de messages
    
    Returns:
        dict avec le nombre de messages marqués
    """
    try:
        service = get_gmail_service()
        succeeded, failed = [], []
        for msg_id in message_ids:
            try:
                service.users().messages().modify(
                    userId="me",
                    id=msg_id,
                    body={"addLabelIds": ["STARRED"]},
                ).execute()
                succeeded.append(msg_id)
            except HttpError:
                failed.append(msg_id)

        return {
            "success": True,
            "starred": len(succeeded),
            "failed": len(failed),
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool
def gmail_delete_messages(
    message_ids: List[str],
    permanent: bool = False,
    # Paramètres système n8n (ignorés)
    sessionId: Optional[str] = None,
    action: Optional[str] = None,
    chatInput: Optional[str] = None,
    toolCallId: Optional[str] = None,
) -> dict:
    """
    Supprime des messages Gmail.
    
    Args:
        message_ids: Liste d'IDs de messages à supprimer
        permanent: Si True, suppression définitive. Si False, déplace vers la corbeille.
    
    Returns:
        dict avec le nombre de messages supprimés et les échecs
    """
    try:
        service = get_gmail_service()
        succeeded, failed = [], []
        for msg_id in message_ids:
            try:
                if permanent:
                    service.users().messages().delete(
                        userId="me", id=msg_id
                    ).execute()
                else:
                    service.users().messages().trash(
                        userId="me", id=msg_id
                    ).execute()
                succeeded.append(msg_id)
            except HttpError:
                failed.append(msg_id)

        return {
            "success": True,
            "deleted": len(succeeded),
            "failed": len(failed),
            "permanent": permanent,
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool
def gmail_send_email(
    to: str,
    subject: str,
    body: str,
    cc: Optional[str] = None,
    bcc: Optional[str] = None,
    # Paramètres système n8n (ignorés)
    sessionId: Optional[str] = None,
    action: Optional[str] = None,
    chatInput: Optional[str] = None,
    toolCallId: Optional[str] = None,
) -> dict:
    """
    Envoie un email via Gmail.
    
    Args:
        to: Destinataire (email)
        subject: Sujet de l'email
        body: Corps du message (texte brut)
        cc: Copie (optionnel)
        bcc: Copie cachée (optionnel)
    
    Returns:
        dict avec l'ID du message envoyé
    """
    try:
        service = get_gmail_service()

        message = MIMEText(body)
        message["to"] = to
        message["subject"] = subject
        if cc:
            message["cc"] = cc
        if bcc:
            message["bcc"] = bcc

        raw = base64.urlsafe_b64encode(message.as_bytes()).decode()
        sent = service.users().messages().send(
            userId="me", body={"raw": raw}
        ).execute()

        return {
            "success": True,
            "message_id": sent["id"],
            "to": to,
            "subject": subject,
        }
    except HttpError as e:
        return {"success": False, "error": f"Erreur envoi: {e}"}


# ==================== Lancement serveur ====================

if __name__ == "__main__":
    port = int(os.getenv("PORT", "8000"))
    print(f"🚀 Démarrage du serveur MCP Gmail sur le port {port}")
    mcp.run(transport="http", host="0.0.0.0", port=port, path="/mcp")

