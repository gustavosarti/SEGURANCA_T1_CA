from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import datetime
import os
# Configuração de pasta
OUTPUT_DIR = "certs"
if not os.path.exists(OUTPUT_DIR):
    os.makedirs(OUTPUT_DIR)

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

# --- 1. CA RAIZ (ROOT) ---
print("Gerando CA Raiz...")
root_key = rsa.generate_private_key(public_exponent=65537, key_size=4096, backend=default_backend())
root_subject = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, u"BR"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"UFES"),
    x509.NameAttribute(NameOID.COMMON_NAME, u"Minha Root CA Python"),
])
root_cert = x509.CertificateBuilder().subject_name(root_subject).issuer_name(root_subject).public_key(
    root_key.public_key()
).serial_number(x509.random_serial_number()).not_valid_before(
    # Válido desde ontem para evitar erros de fuso horário
    datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1)
).not_valid_after(
    datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=3650)
).add_extension(
    x509.BasicConstraints(ca=True, path_length=None), critical=True,
).sign(root_key, hashes.SHA256(), default_backend())

save_key(root_key, "root_ca.key")
save_cert(root_cert, "root_ca.crt") 

# --- 2. CA INTERMEDIÁRIA ---
print("Gerando CA Intermediária...")
inter_key = rsa.generate_private_key(public_exponent=65537, key_size=4096, backend=default_backend())
inter_subject = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, u"BR"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"UFES"),
    x509.NameAttribute(NameOID.COMMON_NAME, u"Minha Intermediate CA"),
])
inter_csr = x509.CertificateSigningRequestBuilder().subject_name(inter_subject).add_extension(
    x509.BasicConstraints(ca=True, path_length=0), critical=True,
).sign(inter_key, hashes.SHA256(), default_backend())

inter_cert = x509.CertificateBuilder().subject_name(
    inter_subject
).issuer_name(
    root_subject
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
).sign(root_key, hashes.SHA256(), default_backend())

save_key(inter_key, "inter_ca.key")
save_cert(inter_cert, "inter_ca.crt") # Uniformizando tudo para .crt

# --- 3. CERTIFICADO DO SERVIDOR (LOCALHOST) ---
print("Gerando Certificado do Servidor...")
server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
server_subject = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, u"BR"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"UFES"),
    x509.NameAttribute(NameOID.COMMON_NAME, u"localhost"),
])

san = x509.SubjectAlternativeName([x509.DNSName(u"localhost")])
server_cert = x509.CertificateBuilder().subject_name(
    server_subject
).issuer_name(
    inter_subject
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
).sign(inter_key, hashes.SHA256(), default_backend())

save_key(server_key, "server.key")
save_cert(server_cert, "server.crt")

# --- GERAÇÃO DO FULLCHAIN ---
# Agora lê os arquivos .crt gerados acima
with open("certs/server.crt", "rb") as f_server, open("certs/inter_ca.crt", "rb") as f_inter:
    fullchain = f_server.read() + f_inter.read()
    with open("certs/fullchain.crt", "wb") as f_full:
        f_full.write(fullchain)

print("Sucesso! Certificados gerados na pasta 'certs'.")
print("Instale o arquivo 'root_ca.crt' nas Autoridades de Certificação Raiz Confiáveis.")