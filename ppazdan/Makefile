SRC_DIR=src
SRCS=$(wildcard $(SRC_DIR)/*.cpp)
TARGET_DIR=out
TARGET=$(TARGET_DIR)/poc
DEBUG_TARGET=$(TARGET_DIR)/poc-debug
CXX=g++
CXXFLAGS=-I$(SRC_DIR) -std=c++23
LIBS=-lgmp -lgmpxx -lcrypto

all:
	mkdir -p $(TARGET_DIR)
	$(CXX) $(CXXFLAGS) $(SRCS) $(LIBS) -O3 -o $(TARGET)

debug:
	mkdir -p $(TARGET_DIR)
	$(CXX) $(CXXFLAGS) $(SRCS) $(LIBS) -g -o $(DEBUG_TARGET)

clean:
	rm -f $(TARGET) $(DEBUG_TARGET)
