#include <string>

using namespace std;

// Exception class for unsupported operations.
class IllegalArgumentException{
    string error_message;
    public:
        IllegalArgumentException(string error_message){
            this->error_message = error_message;
        }
};