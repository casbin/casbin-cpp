#ifndef EXPRESSIONPARSER_H
#define EXPRESSIONPARSER_H

#include <vector>
#include <string>
#include <stack>

/*
This class helps to parse the expression in the matcher using Dijkstra Shunting Yard algorithm and find the final boolean value.
*/

namespace casbin
{
class ExpressionParser
{
    std::stack<std::string> operands;
    std::stack<std::string> operators;
    std::vector<std::string> knownOperators{"==", "&&", "||"};

public:
    void parseString(std::string line);
    void display();
};
} // namespace casbin

#endif