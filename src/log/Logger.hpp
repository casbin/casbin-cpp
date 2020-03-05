#include <string>

class Logger{
    protected:
        bool enable;

    public:
    
        //EnableLog controls whether print the message.
        void EnableLog(bool enable);

        //IsEnabled returns if logger is enabled.
        bool IsEnabled();

        //Print formats using the default formats for its operands and logs the message.
        template <typename... Object>
        void Print(Object... objects);

        //Printf formats according to a format specifier and logs the message.
        template <typename... Object>
        void Printf(std::string, Object... objects);
};
