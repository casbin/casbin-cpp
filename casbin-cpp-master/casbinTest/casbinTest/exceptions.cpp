#include "exceptions.h"
using namespace std;

Exception::Exception(string s)
{
    error_info = s;
}
const char* Exception::what() const throw ()
{
    return error_info.data();
}