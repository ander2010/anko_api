from typing import Optional
from .notifications import send_user_notification


# 1️⃣ Document uploaded
def notify_document_uploaded(user, filename: str):
    return send_user_notification(
        user=user,
        key="document_uploaded",
        title="Document uploaded",
        body=f'Your document "{filename}" was uploaded and is being processed.',
        level="info",
        data={"type": "document"},
    )


# 2️⃣ Document ready
def notify_document_ready(user, filename: str):
    return send_user_notification(
        user=user,
        key="document_ready",
        title="Document ready",
        body=f'Your document "{filename}" is ready to use.',
        level="success",
        data={"type": "document"},
    )


# 3️⃣ Document processing failed
def notify_document_failed(user, filename: str):
    return send_user_notification(
        user=user,
        key="document_failed",
        title="Document processing failed",
        body=f'There was an error processing "{filename}". Please try again.',
        level="error",
        data={"type": "document"},
    )


# 4️⃣ Quiz (Battery) ready
def notify_battery_ready(user, battery_name: str):
    return send_user_notification(
        user=user,
        key="battery_ready",
        title="Quiz ready",
        body=f'Your quiz "{battery_name}" is ready.',
        level="success",
        data={"type": "battery"},
    )


# 5️⃣ Quiz shared with user
def notify_battery_shared(user, battery_name: str, owner_name: str):
    return send_user_notification(
        user=user,
        key="battery_shared",
        title="Quiz shared with you",
        body=f'{owner_name} shared the quiz "{battery_name}" with you.',
        level="info",
        data={"type": "battery"},
    )


# 6️⃣ Deck shared
def notify_deck_shared(user, deck_name: str, owner_name: str):
    return send_user_notification(
        user=user,
        key="deck_shared",
        title="Deck shared with you",
        body=f'{owner_name} shared the deck "{deck_name}" with you.',
        level="info",
        data={"type": "deck"},
    )


# 7️⃣ Access request received
def notify_access_request(user, requester_name: str, resource_name: str):
    return send_user_notification(
        user=user,
        key="access_request_received",
        title="Access request",
        body=f'{requester_name} requested access to "{resource_name}".',
        level="warning",
        data={"type": "access_request"},
    )


# 8️⃣ Access request approved
def notify_access_request_approved(user, resource_name: str):
    return send_user_notification(
        user=user,
        key="access_request_approved",
        title="Access approved",
        body=f'Your request for "{resource_name}" was approved.',
        level="success",
        data={"type": "access_request"},
    )


# 9️⃣ Invitation accepted
def notify_invite_accepted(user, email: str):
    return send_user_notification(
        user=user,
        key="invite_accepted",
        title="Invitation accepted",
        body=f'The invitation sent to {email} was accepted.',
        level="success",
        data={"type": "invite"},
    )


# 🔟 Subscription expired
def notify_subscription_expired(user):
    return send_user_notification(
        user=user,
        key="subscription_expired",
        title="Subscription expired",
        body="Your subscription has expired. Please renew to continue using premium features.",
        level="warning",
        data={"type": "subscription"},
    )


def notify_deck_created(user, deck_name: str):
    return send_user_notification(
        user=user,
        key="deck_created",
        title="Deck created",
        body=f'Your deck "{deck_name}" was created successfully.',
        level="success",
        data={"type": "deck"},
    )