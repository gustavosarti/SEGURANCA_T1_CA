# 📘 Guia de Execução --- PKI Automatizada e Manual

## ⚠️ Antes de Começar (Limpeza)

Sempre que for trocar de tarefa, limpe o ambiente:

``` bash
# Para parar qualquer container rodando
docker rm -f $(docker ps -a -q)
```

------------------------------------------------------------------------

## 🐍 Tarefa 1: PKI Automatizada (Python)

**Pasta:** `T1_Python`

### 1. Instalar dependência (apenas 1ª vez)

``` bash
pip install cryptography
```

### 2. Gerar Certificados (Rodar o Script)

``` bash
cd T1_Python
python pki_script.py
```

### 3. Instalar no Windows (Manual)

-   Abra a pasta `certs`
-   Duplo clique em `root_ca.crt` → **Instalar** → **Raiz Confiável**

### 3.1 Instalar o certificado pelo navegador (Google Chrome)

1.  Abra o Chrome e acesse:\
    `chrome://settings/security`
2.  Role até **Gerenciar certificados**.
3.  Vá até a aba **Autoridades de Certificação**.
4.  Clique em **Importar**.
5.  Selecione o arquivo `root_ca.crt`.
6.  Marque **Confiar nesta CA para identificar sites**.
7.  Confirme.

### 4. Subir Servidor

``` bash
docker compose up -d
```

### 5. Testar

Acesse:

    https://localhost

### 6. Parar

``` bash
docker compose down
```

------------------------------------------------------------------------

## 🔐 Tarefa 2: PKI Manual (OpenSSL)

**Pasta:** `T2_OpenSSL`\
**Terminal recomendado:** Git Bash

### 1. Entrar na pasta de certificados

``` bash
cd T2_OpenSSL/certs
```

### 2. Gerar CA Raiz

``` bash
openssl genrsa -out root_ca.key 4096
openssl req -x509 -new -nodes -key root_ca.key -sha256 -days 3650 -out root_ca.crt -subj "//C=BR/ST=ES/O=UFES/CN=Minha Root CA Task2"
```

### 3. Gerar CA Intermediária

``` bash
openssl genrsa -out inter_ca.key 4096
openssl req -new -key inter_ca.key -out inter_ca.csr -subj "//C=BR/ST=ES/O=UFES/CN=Minha Inter CA Task2"
openssl x509 -req -in inter_ca.csr -CA root_ca.crt -CAkey root_ca.key -CAcreateserial -out inter_ca.crt -days 1825 -sha256 -extfile inter_ext.cnf -extensions v3_ca
```

### 4. Gerar Certificado do Servidor

``` bash
openssl genrsa -out server.key 2048
openssl.req -new -key server.key -out server.csr -subj "//C=BR/ST=ES/O=UFES/CN=localhost"
openssl x509 -req -in server.csr -CA inter_ca.crt -CAkey inter_ca.key -CAcreateserial -out server.crt -days 365 -sha256 -extfile server_ext.cnf -extensions v3_server
```

### 5. Criar Fullchain e Verificar

``` bash
cat server.crt inter_ca.crt > fullchain.crt
openssl.verify -CAfile root_ca.crt -untrusted inter_ca.crt server.crt
```

### 6. Instalar no Windows (Manual)

-   Instale o novo `root_ca.crt` gerado nesta pasta em **Raiz
    Confiável**.

### 6.1 Instalar o certificado pelo navegador (Google Chrome)

1.  Abra o Chrome e acesse:\
    `chrome://settings/security`
2.  Clique em **Gerenciar certificados**.
3.  Vá até a aba **Autoridades de Certificação**.
4.  Clique em **Importar**.
5.  Selecione o arquivo `root_ca.crt`.
6.  Marque **Confiar nesta CA para identificar sites**.
7.  Confirme.

### 7. Subir Servidor

``` bash
cd ..
docker compose up -d
```

### 8. Testar

Acesse:

    https://localhost

(Atualize com **F5**)

### 9. Parar

``` bash
docker compose down
```
