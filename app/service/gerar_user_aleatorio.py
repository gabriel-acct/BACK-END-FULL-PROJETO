import random
import string
def gerar_user_aleatorio(tamanho: int = 30):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=tamanho))
