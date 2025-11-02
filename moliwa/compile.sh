#!/usr/bin/bash
g++  -g main.cpp encoding.cpp decoding.cpp input_and_output.cpp PKCSObjects.cpp utils.cpp sha256.cpp sign.cpp myerror.cpp -o main -lgmpxx -lgmp 
#g++ -O3 -g encoding.cpp decode-key.cpp reusable.cpp -o PoC2 -lgmpxx -lgmp 
#g++ -g sign.cpp sha256.cpp encoding.cpp reusable.cpp -o PoC3 -lgmpxx -lgmp 


