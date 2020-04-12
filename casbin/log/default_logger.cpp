#include "default_logger.h"

void DefaultLogger::SetEnable(bool enabled)
{
	this->enabled = enabled;
}
bool DefaultLogger::IsEnable()
{
	return enabled;
}

template <typename... Object>
void DefaultLogger::Printf(string s, Object... objects)
{
	
}

template <typename... Object>
void DefaultLogger::Print(Object... objects)
{

}