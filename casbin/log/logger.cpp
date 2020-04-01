#include "logger.h"

void Logger::append_to_file(const string& line) const
{
	ofstream fout;
	fout.open(file_name_, ios_base::app);
	fout << line;
	fout.close();
}

auto Logger::print(const string& data) const -> void
{
	char buffer[200];
	auto now = time(nullptr);
	const auto ltm = new tm();
	localtime_s(ltm, &now);
	sprintf_s(buffer, "%d/%d/%d %d:%d:%d %s \r", ltm->tm_mday, 1 + ltm->tm_mon, 1900 + ltm->tm_year, 1 + ltm->tm_hour, 1 + ltm->tm_min, 1 + ltm->tm_sec, data.c_str());
	const string result = buffer;
	append_to_file(result);
}
