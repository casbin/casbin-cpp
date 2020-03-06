#include <string>

using namespace std;

// Exception class for unsupported operations.
class UnsupportedOperationException{
    string error_message;
    public:
        UnsupportedOperationException(string error_message){
            this->error_message = error_message;
        }
};