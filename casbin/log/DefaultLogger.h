#ifndef CASBIN_CPP_LOG_DEFAULT_LOGGER
#define CASBIN_CPP_LOG_DEFAULT_LOGGER

#include "Logger.h"
#include "Log.h"

using namespace std;

class DefaultLogger : public Logger{
    public:

        void EnableLog(bool enable) {
            this->enable = enable;
        }

        bool IsEnabled() {
            return this->enable;
        }

        template <typename... Object>
        void Print(Object... objects){
            if (this->enable){
                Print(objects...);
            }
        }

        template <typename... Object>
        void Print(string format, Object... objects){
            if (this->enable){
                Printf(format, objects...);
            }
        }
};

#endif