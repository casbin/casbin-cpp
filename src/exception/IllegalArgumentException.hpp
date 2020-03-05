#include <string>

// Exception class for unsupported operations.
class IllegalArgumentException{
    std::string error_message;
    public:
        IllegalArgumentException(std::string error_message){
            this->error_message = error_message;
        }
};