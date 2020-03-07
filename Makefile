ifdef OS
   RM = del
else
   ifeq ($(shell uname), Linux)
      RM = rm -f
   endif
endif

CC = g++
CFLAGS = -std=c++11

all: src/effect/DefaultEffector.h src/effect/Effect.h src/effect/Effector.h src/error/Error.h src/exception/IllegalArgumentException.h src/exception/UnsupportedOperationException.h src/log/DefaultLogger.h src/log/Logger.h src/log/LogUtil.h src/model/Assertion.h src/rbac/DefaultRoleManager.h src/rbac/GroupRoleManager.h src/rbac/RoleManager.h
	$(CC) $(CFLAGS) $?

clean:
	$(RM) src\effect\*.gch src\error\*.gch src\exception\*.gch src\log\*.gch src\model\*.gch src\rbac\*.gch
