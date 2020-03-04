#include <string>

class UnsupportedOperationException{
    std::string error_message;
    public:
        UnsupportedOperationException(std::string error_message){
            this->error_message = error_message;
        }
};