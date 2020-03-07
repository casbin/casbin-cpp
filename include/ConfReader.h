#include <map>
#include <vector>
#include <string>

using namespace std;
namespace casbin
{
class ConfReader
{
protected:
    map<string, vector<string>> data;

public:
    void readFile(std::string);
    void display();
    vector<string> getSections();
    vector<string> getSectionData(string);
};
} // namespace casbin
