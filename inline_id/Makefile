CXX := g++
CXXFLAGS := -std=c++17 -O2 -Wall -Wextra -Isrc
LDLIBS := -lpcap

SRC := src/decoders.cpp src/policy.cpp src/flow_table.cpp
MAIN := src/main.cpp
TEST := tests/test_decoders.cpp

.PHONY: all test clean

all: build/inline_id

build:
	mkdir -p build

build/inline_id: $(SRC) $(MAIN) | build
	$(CXX) $(CXXFLAGS) $(SRC) $(MAIN) -o $@ $(LDLIBS)

build/test_decoders: $(SRC) $(TEST) | build
	$(CXX) $(CXXFLAGS) $(SRC) $(TEST) -o $@ $(LDLIBS)

test: build/test_decoders
	./build/test_decoders

clean:
	rm -rf build
