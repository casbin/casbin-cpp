#include "Operator.h"

string AND::operate(string a, string b)
{
    return (a == "true" && b == "true") ? "true" : "false";
}
bool AND::operate(bool a, bool b)
{
    return a && b;
}

string OR::operate(string a, string b)
{
    return (a == "true" || b == "true") ? "true" : "false";
}

bool OR::operate(bool a, bool b)
{
    return a || b;
}

string EQUALS::operate(string a, string b)
{
    return (a == b) ? "true" : "false";
}

bool EQUALS::operate(bool a, bool b)
{
    return a == b;
}