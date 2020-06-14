#ifndef CASBIN_CPP_LOG_LOGGER
#define CASBIN_CPP_LOG_LOGGER

#include <string>

using namespace std;

class Logger{
    protected:
        bool enable;

    public:
    
        //EnableLog controls whether print the message.
        virtual void EnableLog(bool enable);

        //IsEnabled returns if logger is enabled.
        virtual bool IsEnabled();

        //Print formats using the default formats for its operands and logs the message.
        template <typename... Object>
        void Print(Object... objects){
            return;
        }

        //Printf formats according to a format specifier and logs the message.
        template <typename... Object>
        void Printf(string, Object... objects){
            return;
        }
};

#endif