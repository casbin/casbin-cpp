CC = g++
CFLAGS = -std=c++11
casbin: src/main.cc src/Enforcer.cc
   $(CC) $(CFLAGS) $@.cc -o $@