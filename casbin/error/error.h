#ifndef CASBIN_CPP_ERROR_ERROR
#define CASBIN_CPP_ERROR_ERROR

#include <string>

using namespace std;

class Error{
    public:
        static Error NIL;
        string err;

        explicit Error(string& error_message):err(error_message) {
        }

        explicit Error(const char* error_message):err(error_message) {

        }

        explicit Error(const string& error_message):err(error_message) {

        }

        const string& toString() const{
            return err;
        }
};

Error Error::NIL = Error("nil");

#endif
