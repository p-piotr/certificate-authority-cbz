#!/usr/bin/bash
g++ -O3 -g main.cpp encoding.cpp openssl.cpp decode-key.cpp reusable.cpp sha256.cpp sign.cpp -o main -lgmpxx -lgmp -lssl -lcrypto
#g++ -O3 -g encoding.cpp decode-key.cpp reusable.cpp -o PoC2 -lgmpxx -lgmp 
#g++ -g sign.cpp sha256.cpp encoding.cpp reusable.cpp -o PoC3 -lgmpxx -lgmp 


