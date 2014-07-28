#Problem Set 1: Cryptography

Requirements: JDK 1.6+

Compile: $make
Delete .class files: $make clean

##Run: 
   For encryption and signature: 
     * java fcrypt -e destination_public_key_filename sender_private_key_filename input_plaintext_file output_ciphertext_file
   For decryption and signature verification:
     * java fcrypt -d destination_private_key_filename sender_public_key_filename input_ciphertext_file output_plaintext_file
##TEST:
  $make test

##INSTRUCTION:
  This application use AES to encrypt plain text and use RSA to signature and encrypt secrete key. 
  RSA key  pairs are encode with PKCS12, saved as suffix "der"





