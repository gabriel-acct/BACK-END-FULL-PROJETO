"""Utilitários internos para fechar conexão MySQL."""


def fechar_conexao(conn, cursor) -> None:
    if cursor:
        try:
            cursor.close()
        except Exception:
            pass
    if conn:
        try:
            conn.close()
        except Exception:
            pass
