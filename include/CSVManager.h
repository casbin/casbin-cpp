#include<vector>
#include<string>

class CSVManager {
    std::vector<std::vector<std::string>> data;
public:
    std::vector<std::string> readLine(std::string);
    void readFile(std::string);
    void writeFile(std::string);
    void display();
    std::vector<std::vector<std::string>> getData();
};