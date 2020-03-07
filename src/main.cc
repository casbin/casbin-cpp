
#include "../include/ExpressionParser.h"

using namespace std;

main()
{
    ExpressionParser parser;
    parser.parseString("m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act");
    parser.display();
}