#ifndef CASBIN_CPP_ERROR_ERROR
#define CASBIN_CPP_ERROR_ERROR

#include <string>

namespace casbin {

class Error{
    public:
        static Error NIL;
        std::string err;

        Error(std::string error_message){
            err = error_message;
        }

        std::string toString(){
            return err;
        }
};

} // namespace casbin

#endif
