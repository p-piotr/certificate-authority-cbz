#!/usr/bin/bash
g++ -g PoC1.cpp encoding.cpp openssl.cpp -o PoC1 -lgmpxx -lgmp  -lssl -lcrypto

