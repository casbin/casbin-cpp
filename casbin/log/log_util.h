#pragma once
#include "logger.h"
#include "default_logger.h"

class LogUtil
{
private:
	static Logger logger;
public:
	static void SetLogger(Logger log)
	{
		logger = log;
	}

	static Logger& GetLogger()
	{
		return logger;
	}

	template <typename... Object>
	static void LogPrint(Object... objects)
	{
		logger.Print(objects...);
	}

	template <typename... Object>
	static void LogPrintf(string s, Object... objects)
	{
		logger.Printf(s,objects...);
	}
};