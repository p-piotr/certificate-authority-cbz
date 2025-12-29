#!/usr/bin/bash
# this will bascially link the normally built part with the test that's it
objs=$(find ../../../build/obj/ -name "*-debug.o" -not -name "*main*" -printf "%p ")
echo "$objs"
g++ -std=c++23 -I../.. -g -c test_csr_reading.cpp 
g++ -o test test_csr_reading.o $objs -lgmp -lgmpxx -lcrypto


