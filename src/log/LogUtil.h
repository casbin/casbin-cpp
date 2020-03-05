#include <string>

#include "DefaultLogger.h"
#include "Logger.h"

class LogUtil{
	private:
		static Logger logger;
	public:

		// SetLogger sets the current logger.
		static void SetLogger(Logger l){
			logger = l;
		}

		// GetLogger returns the current logger.
		static Logger GetLogger() {
			return logger;
		}

		// LogPrint prints the log.
		template <typename... Object>
		static void LogPrint(Object... objects) {
			logger.Print(objects...);
		}

		// LogPrintf prints the log with the format.
		template <typename... Object>
		static void LogPrintf(std::string format, Object... objects) {
			logger.Printf(format, objects...)
		}
};