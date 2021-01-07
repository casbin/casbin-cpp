#ifndef CASBIN_CPP_LOG_LOG_UTIL
#define CASBIN_CPP_LOG_LOG_UTIL

#include "DefaultLogger.h"

using namespace std;

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
		static void LogPrintf(string format, Object... objects) {
			logger.Printf(format, objects...);
		}
};

#endif