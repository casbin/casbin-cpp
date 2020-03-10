#include "pch.h"
#include "csv_adapter.h"


vector<string> CSVAdapter::readLine(string line)
{
	return split(line, ',');
}

void CSVAdapter::readFile(string fileName)
{
	ifstream file(fileName, ios::out);
	if (!file.is_open())
	{
		cerr << "Error: Unable to open CSV file " << fileName << " for reading!" << endl;
		return;
	}

	string line;
	while (getline(file, line))
	{
		data.push_back(readLine(line));
	}

	file.close();
}

void CSVAdapter::writeFile(string fileName)
{
	ofstream fout;
	fout.open(fileName);

	string line = "";
	while (fout)
	{
		for (vector<string> vec : data)
		{
			line = join(vec, ',');
			fout << line << endl;
		}
	}

	// Close the File
	fout.close();
}

void CSVAdapter::display()
{
	for (vector<string> vec : data)
	{
		for (string ele : vec)
		{
			printf("%s ", ele.c_str());
		}
		printf("\n");
	}
}

vector<vector<string>> CSVAdapter::getData()
{
	return data;
}
