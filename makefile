#Define C/C++ compiler variables
CXX := g++

#Define compiler flags
OBJ_FLAG := -c
FILE_FLAG :=  -o

#Define directory variables
SRC_DIR := casbin
OBJ_DIR := obj
LIB_DIR := lib

#Define extension variables
SRC_EXT := cpp
OBJ_EXT := o
LIB_EXT := a
INC_EXT := h

#Get source cpp files
SRC_FILES := $(shell find $(SRC_DIR) -type f -name *.$(SRC_EXT))
INC_DIRS := $(shell find $(SRC_DIR) -type d)
INC_FLAG_DIRS := $(addprefix -I /, $(INC_DIRS))

all:
	$(foreach SRC_FILE, $(SRC_FILES),\
		$(CXX) $(OBJ_FLAG) $(FILE_FLAG) $(SRC_FILE:$(SRC_DIR)/%.$(SRC_EXT)=$(OBJ_DIR)/%.$(OBJ_EXT)) $(SRC_FILE);\
	)