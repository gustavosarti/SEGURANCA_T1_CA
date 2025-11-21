from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import datetime
import os
import time

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

print("--- INICIANDO TAREFA 1: IMPLEMENTAÇÃO PKI EM PYTHON ---")
time.sleep(1)

# --- 1. CA RAIZ (ROOT) ---
print("\n[1/4] CRIAÇÃO DA CA RAIZ (AUTOASSINADA)...")
print("   -> Gerando par de chaves RSA 4096 bits (Requisito 4.1)...") # 
root_key = rsa.generate_private_key(public_exponent=65537, key_size=4096, backend=default_backend())

root_subject = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, u"BR"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"UFES"),
    # IMPORTANTE: Nome distinto para diferenciar da Tarefa 2 no Windows
    x509.NameAttribute(NameOID.COMMON_NAME, u"Minha Root CA Task1"), 
])

print("   -> Criando certificado e realizando autoassinatura...") # 
root_cert = x509.CertificateBuilder().subject_name(root_subject).issuer_name(root_subject).public_key(
    root_key.public_key()
).serial_number(x509.random_serial_number()).not_valid_before(
    datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1)
).not_valid_after(
    datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=3650)
).add_extension(
    x509.BasicConstraints(ca=True, path_length=None), critical=True,
).sign(root_key, hashes.SHA256(), default_backend())

save_key(root_key, "root_ca.key")
save_cert(root_cert, "root_ca.crt")
print("   -> SUCESSO: Arquivos 'root_ca.key' e 'root_ca.crt' exportados.") # [cite: 35]
time.sleep(1)

# --- 2. CA INTERMEDIÁRIA ---
print("\n[2/4] CRIAÇÃO DA CA INTERMEDIÁRIA (ASSINADA PELA RAIZ)...")
print("   -> Gerando par de chaves RSA 4096 bits...") # 
inter_key = rsa.generate_private_key(public_exponent=65537, key_size=4096, backend=default_backend())

inter_subject = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, u"BR"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"UFES"),
    x509.NameAttribute(NameOID.COMMON_NAME, u"Minha Intermediate CA Python"),
])

print("   -> Assinando certificado da Intermediária usando a chave da CA Raiz...") # 
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
save_cert(inter_cert, "inter_ca.crt")
print("   -> SUCESSO: Arquivos 'inter_ca.key' e 'inter_ca.crt' exportados.") # [cite: 37]
time.sleep(1)

# --- 3. CERTIFICADO DO SERVIDOR (LOCALHOST) ---
print("\n[3/4] EMISSÃO DO CERTIFICADO DO SERVIDOR...")
print("   -> Gerando chave privada do servidor...") # [cite: 38]
server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())

server_subject = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, u"BR"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"UFES"),
    x509.NameAttribute(NameOID.COMMON_NAME, u"localhost"),
])

print("   -> Criando CSR e definindo 'localhost' (SAN)...") # 
san = x509.SubjectAlternativeName([x509.DNSName(u"localhost")])

print("   -> Assinando certificado do servidor com a CA Intermediária...") # 
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
print("   -> SUCESSO: Arquivo 'server.crt' exportado.") # [cite: 40]
time.sleep(1)

# --- 4. FULLCHAIN ---
print("\n[4/4] CONFIGURAÇÃO FINAL...")
print("   -> Gerando arquivo 'fullchain.crt' (Server + Intermediate) para o Nginx...")
with open("certs/server.crt", "rb") as f_server, open("certs/inter_ca.crt", "rb") as f_inter:
    fullchain = f_server.read() + f_inter.read()
    with open("certs/fullchain.crt", "wb") as f_full:
        f_full.write(fullchain)

print("\n--- PROCESSO CONCLUÍDO COM SUCESSO ---")
print("PRÓXIMO PASSO: Instale o arquivo 'certs/root_ca.crt' nas Autoridades de Certificação Raiz Confiáveis.") # [cite: 42]