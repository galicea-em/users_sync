openssl x509 \
    -req -days 3650 \
    -in client.csr -CA ca.crt -CAkey ca.key -extfile v3ext.txt \
    -set_serial 01 -out client.crt
