SRC_DIR=src
SRCS=$(wildcard $(SRC_DIR)/*.cpp)
TARGET_DIR=out
TARGET=$(TARGET_DIR)/poc
DEBUG_TARGET=$(TARGET_DIR)/poc-debug
CXX=g++
CXXFLAGS=-g
LIBS=-lgmp -lgmpxx

all:
	mkdir -p $(TARGET_DIR)
	$(CXX) $(CXXFLAGS) $(SRCS) $(LIBS) -O3 -o $(TARGET)

debug:
	mkdir -p $(TARGET_DIR)
	$(CXX) $(CXXFLAGS) $(SRCS) $(LIBS) -g -o $(DEBUG_TARGET)

clean:
	rm -f $(TARGET) $(DEBUG_TARGET)
