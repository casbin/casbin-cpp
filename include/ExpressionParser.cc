#include <vector>
#include <string>
#include <stack>
#include <iostream>
#include "ExpressionParser.h"
#include "utils.h"

namespace casbin
{
void ExpressionParser::parseString(std::string line)
{
    int start = 0;
    int operatorsNotFound = 0;
    line = line.substr(line.find_first_of('=') + 1, line.size());

    while (start < line.size())
    {
        for (std::string op : knownOperators)
        {
            size_t operatorIndex = line.find(op, start);
            if (operatorIndex != std::string::npos)
            {
                operatorsNotFound = 0;
                std::string sub = line.substr(start, operatorIndex - start);
                start = operatorIndex + op.size();
                operands.push(trim(sub));
                operators.push(op);
            }
            else
                operatorsNotFound++;
        }
        if (operatorsNotFound == knownOperators.size() - 1)
            break;
    }
}

// void ExpressionParser::parseString(std::string line) {
//     for(std::string op: knownOperators) {
//         size_t operatorIndex = line.find(op, 0);
//         parseString(line.substr(0, ))
//     }
// }

void ExpressionParser::display()
{
    while (!operators.empty())
    {
        std::cout << operators.top() << " ";
        operators.pop();
    }

    while (!operands.empty())
    {
        std::cout << operands.top() << " ";
        operands.pop();
    }
}
} // namespace casbin
