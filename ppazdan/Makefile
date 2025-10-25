SRC_DIR=src
SRCS=$(wildcard $(SRC_DIR)/*.cpp)
TARGET=out/poc
DEBUG_TARGET=out/poc-debug
CXX=g++
CXXFLAGS=-g
LIBS=-lgmp -lgmpxx

all:
	$(CXX) $(CXXFLAGS) $(SRCS) $(LIBS) -o $(TARGET)

debug:
	$(CXX) $(CXXFLAGS) $(SRCS) $(LIBS) -g -o $(DEBUG_TARGET)

clean:
	rm -f $(TARGET) $(DEBUG_TARGET)
