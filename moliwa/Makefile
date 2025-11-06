# Compiler & flags
CXX := g++
CXXFLAGS := -g -Wall -std=c++17
# -g			for debugging symbols
# -Wall			enable all warnings
# -std=c++17	use C++17 standard

# Libraries
LIBS := -lgmp -lgmpxx
# link GMP

# to compile with debug messages: make DEBUG=1
ifeq ($(DEBUG),1)
    CXXFLAGS += -DDEBUG
	# define DEBUG macro
endif

# to skip manual input of information: make SKIP_INPUT=1
# can be useful for debugging
ifeq ($(SKIP_INPUT),1)
    CXXFLAGS += -DSKIP_INPUT
	# define SKIP_INPUT macro
endif

# used to disable optimizations
# also can be useful for debugging
ifeq ($(SKIP_OPTIMIZATION),1)
    CXXFLAGS += -O0
	# add -O0 compiler flag
else
    CXXFLAGS += -O2
	# add -O2 compiler flag
endif


# Directories

SRC_DIR := src
# source files (.cpp .h) directory
OBJ_DIR := obj
# object files (.o) directory
BIN := createCSR
# name of the created executable 

# Source & object files
SRCS := $(wildcard $(SRC_DIR)/*.cpp) 							# variable that holds all .cpp files in SRC_DIR
OBJS := $(patsubst $(SRC_DIR)/%.cpp,$(OBJ_DIR)/%.o,$(SRCS)) 	# variable that holds the corresponding .o files in OBJ_DIR for each .cpp in SRCS

# Default target
all: $(BIN)

# Link step
$(BIN): $(OBJS)
	@echo "Linking $^ into $@..."
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIBS)
	@echo ""
# $@ - target here $(BIN)
# $^ - all object files (dependencies)

# Compile step
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cpp | $(OBJ_DIR)
	@echo "Compiling $<..."
	$(CXX) $(CXXFLAGS) -c $< -o $@
	@echo ""
	
# $<  - first prerequisite (here: the source file, e.g. src/foo.cpp)
# $@  - the target (here: the object file, e.g. obj/foo.o)
# '|' - makes $(OBJ_DIR) an order-only prerequisite (ensures the directory exists before the rule runs, but changes to the directory won't mark the target out-of-date)

# Ensure obj directory exists
$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)
	@echo ""
	

# Clean build files
clean:
	@echo "Cleaning project..."
	rm -rf $(OBJ_DIR) $(BIN)

# Run program
run: $(BIN)
	@echo "Running $(BIN)..."
	./$(BIN)

.PHONY: all clean run
# Phony target
# It tells Make that the listed targets are not actual files, but labels for commands.


