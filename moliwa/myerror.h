#ifndef myerror
#define myerror


#include <string>
#include <exception>

// vibe-coded btw
class MyError : public std::exception {
private:
    std::string message;

public:
    explicit MyError(const std::string &msg) : message(msg) {}


    const char* what() const noexcept override {
        return message.c_str();
    }
};

#endif
