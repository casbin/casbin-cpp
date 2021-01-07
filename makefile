# Define C/C++ compiler variables
CXX := g++
AR := ar

# Define compiler flags
OBJ_FLAG := -c
FILE_FLAG := -o
STD_FLAG := -std=c++11
DIS_WARN := -w

# Define archive flags
AR_FLAG := crv
AR_NAME := casbin.a

# Define directory variables
SRC_DIR := casbin
OBJ_DIR := obj
LIB_DIR := lib

# Define extension variables
SRC_EXT := cpp
OBJ_EXT := o
LIB_EXT := a
INC_EXT := h

# Define make directory command variable
MKDIR_P := mkdir -p

# Get source cpp files
SRC_FILES := $(shell find $(SRC_DIR) -type f -name *.$(SRC_EXT))
INC_DIRS := $(shell find $(SRC_DIR) -type d)
INC_FLAG_DIRS := $(addprefix -I /, $(INC_DIRS))
OBJ_DIRS := $(addprefix $(OBJ_DIR)/, $(INC_DIRS))

.PHONY: object
object:
	$(foreach OBJ_DIR, $(OBJ_DIRS),\
		$(MKDIR_P) $(OBJ_DIR);\
	)
	$(foreach SRC_FILE, $(SRC_FILES),\
		set -e;\
		$(CXX) $(DIS_WARN) $(STD_FLAG) $(OBJ_FLAG) $(FILE_FLAG) $(SRC_FILE:$(SRC_DIR)/%.$(SRC_EXT)=$(OBJ_DIR)/$(SRC_DIR)/%.$(OBJ_EXT)) $(SRC_FILE);\
	)

.PHONY: debug
debug:
	$(foreach OBJ_DIR, $(OBJ_DIRS),\
		$(MKDIR_P) $(OBJ_DIR);\
	)
	$(foreach SRC_FILE, $(SRC_FILES),\
		$(CXX) $(STD_FLAG) $(OBJ_FLAG) $(FILE_FLAG) $(SRC_FILE:$(SRC_DIR)/%.$(SRC_EXT)=$(OBJ_DIR)/$(SRC_DIR)/%.$(OBJ_EXT)) $(SRC_FILE);\
	)

#Get object files
OBJ_FILES := $(shell find $(OBJ_DIR) -type f -name *.$(OBJ_EXT))

.PHONY: library
library:
	$(MKDIR_P) $(LIB_DIR)
	$(AR) $(AR_FLAG) $(AR_NAME) $(OBJ_FILES)
	mv $(AR_NAME) $(LIB_DIR)/$(AR_NAME)

.PHONY: clean
clean:
	rm -r $(OBJ_DIR)

.PHONY: build
build:
	rm -rf cmake-build
	mkdir cmake-build
	cd cmake-build ; cmake .. ; make
