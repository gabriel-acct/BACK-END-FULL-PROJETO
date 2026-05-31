"""Registro central de auditoria (painel_audit_log)."""

from app.service.payment_logging import client_ip, user_agent
from db.queries_usuario import insert_audit_log


def write_audit(
    actor_username: str,
    action: str,
    target_type: str,
    target_key: str,
    detail: str | None = None,
) -> None:
    insert_audit_log(
        actor_username,
        action,
        target_type,
        target_key,
        detail,
        ip_address=client_ip(),
        user_agent=user_agent(),
    )
