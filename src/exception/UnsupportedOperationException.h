#include <string>

// Exception class for unsupported operations.
class UnsupportedOperationException{
    std::string error_message;
    public:
        UnsupportedOperationException(std::string error_message){
            this->error_message = error_message;
        }
};