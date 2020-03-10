#include "pch.h"
#include "logger.h"

void Logger::appendToFile(string line) {
	ofstream fout;
	fout.open(fileName, ios_base::app);
	fout << line;
	fout.close();
}

void Logger::print(string data) {
	char buffer[200];
	time_t now = time(0);
	tm* ltm = new tm();
	localtime_s(ltm, &now);
	sprintf_s(buffer, "%d/%d/%d %d:%d:%d %s \r", ltm->tm_mday, 1 + ltm->tm_mon, 1900 + ltm->tm_year, 1 + ltm->tm_hour, 1 + ltm->tm_min, 1 + ltm->tm_sec, data.c_str());
	string result = buffer;
	appendToFile(result);
}