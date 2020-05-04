#ifndef FUNCTIONS_H_
#define FUNCTIONS_H_

#ifdef CASBIN_EXPORTS
#define CPPFUNCTION_API __declspec(dllexport)
#else
#define CPPFUNCTION_API __declspec(dllimport)
#endif

#include <list>
#include <string>
#include<functional>

typedef std::list<std::string> args_t;

class Function : public TokenBase {
 public:
  static packToken call(packToken _this, const Function* func,
                        TokenList* args, TokenMap scope);
 public:
  Function() : TokenBase(FUNC) {}
  virtual ~Function() {}

 public:
  virtual const std::string name() const = 0;
  virtual const args_t args() const = 0;
  virtual packToken exec(TokenMap scope) const = 0;
  virtual TokenBase* clone() const = 0;
};

class CPPFUNCTION_API CppFunction : public Function {
 public:
  packToken (*func)(TokenMap);
  args_t _args;
  std::string _name;
  std::function<packToken(TokenMap)> stdFunc;
  bool isStdFunc;

  CppFunction();
  CppFunction(packToken (*func)(TokenMap), const args_t args,
              std::string name = "");
  CppFunction(packToken (*func)(TokenMap), unsigned int nargs,
              const char** args, std::string name = "");
  CppFunction(packToken (*func)(TokenMap), std::string name = "");
  CppFunction(std::function<packToken(TokenMap)> func, const args_t args,
      std::string name = "");
  CppFunction(std::function<packToken(TokenMap)> func, unsigned int nargs,
      const char** args, std::string name = "");
  CppFunction(std::function<packToken(TokenMap)> func, std::string name = "");

  virtual const std::string name() const { return _name; }
  virtual const args_t args() const { return _args; }
  virtual packToken exec(TokenMap scope) const { if (!isStdFunc) return func(scope);  return stdFunc(scope); }

  virtual TokenBase* clone() const {
    return new CppFunction(static_cast<const CppFunction&>(*this));
  }
};

#endif  // FUNCTIONS_H_
