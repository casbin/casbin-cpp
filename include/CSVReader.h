#include<vector>
#include<string>

class CSVReader {
    std::vector<std::vector<std::string>> data;
public:
    std::vector<std::string> readLine(std::string);
    void readFile(std::string);
    void display();
    std::vector<std::vector<std::string>> getData();
};