SRC_DIR=src
SRCS=$(wildcard $(SRC_DIR)/*.cpp)
TARGET=out/poc
CXX=g++
CXXFLAGS=-g

all:
	$(CXX) $(CXXFLAGS) $(SRCS) -o $(TARGET)

clean:
	rm -f $(TARGET)
