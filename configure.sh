#!/bin/bash

# modify both openssl parameter "subj" in this script before run

pushd src/main/resources/sign/
openssl ecparam -genkey -name prime256v1 -noout -out sign_appleReceiptRequest_privKey.pem
openssl ecparam -genkey -name prime256v1 -noout -out sign_devToken_privKey.pem
openssl req -new -key sign_devToken_privKey.pem -out sign_devToken_certificate.csr -subj "/CN=todo.todo.todo.de"
cat sign_devToken_certificate.csr
openssl x509 -req -in sign_devToken_certificate.csr -signkey sign_devToken_privKey.pem -out sign_devToken_certificate.pem -outform PEM -days 365
cat sign_devToken_certificate.pem
popd

pushd src/main/resources/ca
openssl ecparam -genkey -name prime256v1 -noout -out gms_ca_key.pem
openssl req -new -x509 -key gms_ca_key.pem -out gms_ca.pem -days 3650 -subj "/C=DE/C=DE/ST=Berlin/L=Berlin/O=todo Gmbh/CN=DSR-GMS"
cat gms_ca.pem
popd
