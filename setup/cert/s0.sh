openssl genrsa -aes256 -out ca.key 4096
openssl req -new -x509 -days 3650 -key ca.key -out ca.crt
