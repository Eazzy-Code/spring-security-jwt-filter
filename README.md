# Generating the Private/Public Key Pair

`$ cd src/main/resources`

`$ openssl genpkey -out rsakey.pem -algorithm RSA -pkeyopt rsa_keygen_bits:2048`

`$ openssl pkey -in rsakey.pem -pubout -out rsapubkey.pem`