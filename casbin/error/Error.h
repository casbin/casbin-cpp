#ifndef CASBIN_CPP_ERROR_ERROR
#define CASBIN_CPP_ERROR_ERROR

#include <string>

using namespace std;

class Error{
    public:
        static Error NIL;
        string err;

        Error(string error_message){
            err = error_message;
        }

        string toString(){
            return err;
        }
};

Error Error::NIL = Error("nil");

#endif
