#include "Logger.hpp"
#include "Log.hpp"

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
                Print(object...);
            }
        }

        template <typename... Object>
        void Print(std::string format, Object... objects){
            if (this->enable){
                Printf(format, object...);
            }
        }
};