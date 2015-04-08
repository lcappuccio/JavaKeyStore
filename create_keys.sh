#!/bin/sh

# Generate root certificate...
openssl genrsa -des3 -out root_ca.key 2048
openssl req -new -x509 -days 365 -key root_ca.key -extensions v3_ca -out root_ca.crt
openssl x509 -in root_ca.crt -out root_ca.pem -outform PEM
openssl pkcs12 -export -name root_ca -inkey root_ca.key -in root_ca.pem -out root_ca.p12
# ...and import to java key store
keytool -importkeystore -srckeystore root_ca.p12 -srcstoretype PKCS12 -destkeystore truststore.jks
# check that key is imported into keystore
keytool -list -keystore truststore.jks

# Generate client certificate...
openssl genrsa -des3 -out client.key 2048
openssl req -new -x509 -days 365 -key client.key -extensions v3_ca -out client.crt
openssl x509 -in client.crt -out client.pem -outform PEM
# ...and sign it with the root key...
openssl req -new -key client.key -out client.req -sha256 -days 365 -subj "/CN=localhost/O=YOUR_ORGANIZATION/ST=YOUR_STATE/C=YOUR_COUNTRY"
openssl x509 -req -days 365 -sha256 -extensions v3_ca -CA root_ca.crt -CAkey root_ca.key -set_serial 666 -in client.req -out client.pem -outform PEM
openssl pkcs12 -export -name client -inkey client.key -in client.pem -out client.p12
# ...and finally send it to a keystore
keytool -importkeystore -srckeystore client.p12 -srcstoretype PKCS12 -destkeystore client.jks
# check that key is imported into keystore
keytool -list -keystore client.jks