import os

from load_env import load_project_env

load_project_env()

class ResellerBackend:
    API_URL = os.getenv("API_URL")
    LOGIN = os.getenv("LOGIN")
    PASSWORD = os.getenv("PASSWORD")

class Config:
    # os.getenv devolve str; timedelta(minutes=...) exige int/float
    JWT_EXPIRE_MINUTES = int(os.getenv("JWT_EXPIRE_MINUTES", "480"))  # padrão: 8 horas
    JWT_SECRET = os.getenv("JWT_SECRET")
    JWT_ALG = os.getenv("JWT_ALG", "HS256")

    # Recarga PIX / PushinPay: configurar somente no MySQL
    # (painel_pushinpay_config, painel_recarga_config) via painel admin.
