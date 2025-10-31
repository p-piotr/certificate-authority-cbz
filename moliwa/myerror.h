#ifndef MYERROR_H
#define MYERROR_H

// This file contains custom exception class that inherits after std::exception
// I'm not gonna pretend that this wasn't vibecoded; I had simply no idea how to do this in code on my own
// Main reason for creating my own error class is that I want to seperate my exceptions from the standard ones
// I also want to use nested exceptions to produce more verbose errors

#include <string>
#include <exception>
#include <iostream>

class MyError : public std::exception {
private:
    std::string message;

public:
    explicit MyError(const std::string &msg) : message(msg) {}


    const char* what() const noexcept override {
        return message.c_str();
    }
};

// recursive printer to pretty-print nested exceptions
void print_nested(const std::exception& e, int level = 0);

#endif
