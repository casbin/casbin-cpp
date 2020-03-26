ifdef OS
   RM = del
else
   ifeq ($(shell uname), Linux)
      RM = rm -f
   endif
endif

CC = g++
CFLAGS = -std=c++11

all: src/config/Config.h src/config/ConfigInterface.h src/effect/DefaultEffector.h src/effect/Effect.h src/effect/Effector.h src/error/Error.h src/exception/IllegalArgumentException.h src/exception/UnsupportedOperationException.h src/exception/MissingRequiredSections.h src/exception/IOException.h src/log/DefaultLogger.h src/log/Logger.h src/log/LogUtil.h src/model/Assertion.h src/model/Model.h src/model/Policy.h src/persist/Adapter.h src/rbac/DefaultRoleManager.h src/rbac/GroupRoleManager.h src/rbac/RoleManager.h src/util/arrayEquals.h src/util/arrayRemoveDuplicates.h src/util/ends_with.h src/util/escapeAssertion.h src/util/join.h src/util/removeComments.h src/util/split.h src/util/trim.h
	$(CC) $(CFLAGS) $?

clean:
	$(RM) src\config\*.gch src\effect\*.gch src\error\*.gch src\exception\*.gch src\log\*.gch src\model\*.gch src\persist\*.gch src\rbac\*.gch src\util\*.gch
