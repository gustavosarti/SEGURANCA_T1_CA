from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import datetime
import os
import time

# Configuração inicial: Cria a pasta 'certs' se não existir
OUTPUT_DIR = "certs"
if not os.path.exists(OUTPUT_DIR):
    os.makedirs(OUTPUT_DIR)

# Funções auxiliares para salvar chaves e certificados em arquivo
def save_key(key, filename):
    with open(os.path.join(OUTPUT_DIR, filename), "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

def save_cert(cert, filename):
    with open(os.path.join(OUTPUT_DIR, filename), "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

print("--- INICIANDO TAREFA 1: IMPLEMENTAÇÃO PKI EM PYTHON ---")
time.sleep(1)

# ==============================================================================
# PASSO 1: CA RAIZ (ROOT) - Requisito: Criar CA Raiz autoassinada RSA 4096 bits
# ==============================================================================
print("\n[1/4] CRIAÇÃO DA CA RAIZ...")

# 1.1 Geração da Chave Privada: Usamos RSA com 4096 bits conforme especificado.
root_key = rsa.generate_private_key(
    public_exponent=65537, 
    key_size=4096, 
    backend=default_backend()
)

# 1.2 Definição do Sujeito (Quem é o dono do certificado).
root_subject = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, u"BR"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"UFES"),
    x509.NameAttribute(NameOID.COMMON_NAME, u"Minha Root CA Task 1"), 
])

# 1.3 Criação e Autoassinatura (Self-Signed):
# O emissor (issuer) é igual ao sujeito (subject).
# A extensão BasicConstraints(ca=True) define que este certificado pode assinar outros.
root_cert = x509.CertificateBuilder().subject_name(
    root_subject
).issuer_name(
    root_subject # <--- Autoassinatura: Issuer == Subject
).public_key(
    root_key.public_key()
).serial_number(
    x509.random_serial_number()
).not_valid_before(
    datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1)
).not_valid_after(
    datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=3650)
).add_extension(
    x509.BasicConstraints(ca=True, path_length=None), critical=True,
).sign(root_key, hashes.SHA256(), default_backend()) # Assina com a PRÓPRIA chave

save_key(root_key, "root_ca.key")
save_cert(root_cert, "root_ca.crt")
print("   -> CA Raiz gerada e exportada.")
time.sleep(1)


# ==============================================================================
# PASSO 2: CA INTERMEDIÁRIA - Requisito: Assinada pela Raiz
# ==============================================================================
print("\n[2/4] CRIAÇÃO DA CA INTERMEDIÁRIA...")

# 2.1 Geração da Chave Privada da Intermediária (4096 bits).
inter_key = rsa.generate_private_key(
    public_exponent=65537, 
    key_size=4096, 
    backend=default_backend()
)

# 2.2 Definição do Sujeito da Intermediária.
inter_subject = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, u"BR"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"UFES"),
    x509.NameAttribute(NameOID.COMMON_NAME, u"Minha Intermediate CA Python"),
])

# 2.3 Assinatura pela Raiz:
# Aqui o Issuer é a 'root_subject' (A Raiz).
# A assinatura é feita usando a 'root_key' (Chave da Raiz).
inter_cert = x509.CertificateBuilder().subject_name(
    inter_subject
).issuer_name(
    root_subject # <--- Quem assina é a RAÍZ
).public_key(
    inter_key.public_key()
).serial_number(
    x509.random_serial_number()
).not_valid_before(
    datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1)
).not_valid_after(
    datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1825)
).add_extension(
    x509.BasicConstraints(ca=True, path_length=0), critical=True,
).sign(root_key, hashes.SHA256(), default_backend()) # <--- Assina com chave da ROOT

save_key(inter_key, "inter_ca.key")
save_cert(inter_cert, "inter_ca.crt")
print("   -> CA Intermediária gerada e assinada pela Raiz.")
time.sleep(1)


# ==============================================================================
# PASSO 3: CERTIFICADO DO SERVIDOR - Requisito: Assinado pela Intermediária
# ==============================================================================
print("\n[3/4] EMISSÃO DO CERTIFICADO DO SERVIDOR (LOCALHOST)...")

# 3.1 Geração da Chave do Servidor (2048 bits é padrão para servidores).
server_key = rsa.generate_private_key(
    public_exponent=65537, 
    key_size=2048, 
    backend=default_backend()
)

server_subject = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, u"BR"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"UFES"),
    x509.NameAttribute(NameOID.COMMON_NAME, u"localhost"),
])

# 3.2 Extensão SAN (Subject Alternative Name):
# Obrigatória para navegadores modernos (Chrome/Edge) aceitarem o certificado.
san = x509.SubjectAlternativeName([x509.DNSName(u"localhost")])

# 3.3 Assinatura pela Intermediária:
# O Issuer é a 'inter_subject'.
# A assinatura é feita usando a 'inter_key'.
server_cert = x509.CertificateBuilder().subject_name(
    server_subject
).issuer_name(
    inter_subject # <--- Quem assina é a INTERMEDIÁRIA
).public_key(
    server_key.public_key()
).serial_number(
    x509.random_serial_number()
).not_valid_before(
    datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1)
).not_valid_after(
    datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
).add_extension(
    san, critical=False
).sign(inter_key, hashes.SHA256(), default_backend()) # <--- Assina com chave da INTER

save_key(server_key, "server.key")
save_cert(server_cert, "server.crt")
print("   -> Certificado do Servidor gerado e assinado pela Intermediária.")
time.sleep(1)


# ==============================================================================
# PASSO 4: FULLCHAIN (Para o Nginx)
# ==============================================================================
print("\n[4/4] GERAÇÃO DO FULLCHAIN...")
# O Nginx precisa da cadeia completa (Certificado do Site + Certificado da Intermediária)
# para que o navegador consiga validar o caminho até a Raiz.
with open("certs/server.crt", "rb") as f_server, open("certs/inter_ca.crt", "rb") as f_inter:
    fullchain = f_server.read() + f_inter.read()
    with open("certs/fullchain.crt", "wb") as f_full:
        f_full.write(fullchain)

print("\n--- PROCESSO CONCLUÍDO ---")
print("Certificados disponíveis na pasta 'certs'.")