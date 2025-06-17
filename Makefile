# IoTStrike Hardware Security Framework
# Main Makefile for cross-platform compilation

# Compiler settings
CC = gcc
CXX = g++
AS = as
ZIG = zig
CFLAGS = -Wall -Wextra -std=c99 -O2 -fPIC
CXXFLAGS = -Wall -Wextra -std=c++17 -O2 -fPIC
ASFLAGS = -arch x86_64
ZIGFLAGS = -O ReleaseFast
LDFLAGS = -shared
INCLUDES = -Iinclude
LIBS = -L/opt/homebrew/opt/openssl@3/lib -lpcap -lcrypto -lssl -lm -lpthread
LDFLAGS = -shared

# Directories
SRCDIR = src
BUILDDIR = build
INCLUDEDIR = include
LIBDIR = lib

# Source files
C_SOURCES = $(wildcard $(SRCDIR)/*/*.c) $(SRCDIR)/main.c
CXX_SOURCES = $(wildcard $(SRCDIR)/*/*.cpp)
ASM_SOURCES = $(wildcard $(SRCDIR)/*/*.s)
ZIG_SOURCES = $(wildcard $(SRCDIR)/*/*.zig)

# Object files
C_OBJECTS = $(C_SOURCES:$(SRCDIR)/%.c=$(BUILDDIR)/%.o)
CXX_OBJECTS = $(CXX_SOURCES:$(SRCDIR)/%.cpp=$(BUILDDIR)/%.o)
ASM_OBJECTS = $(ASM_SOURCES:$(SRCDIR)/%.s=$(BUILDDIR)/%.o)
ZIG_OBJECTS = $(ZIG_SOURCES:$(SRCDIR)/%.zig=$(BUILDDIR)/%.o)

# Target
TARGET = iotstrike
LIBTARGET = libiotstrike.so

# Platform Detection
ifeq ($(OS),Windows_NT)
    PLATFORM = windows
    EXT = .exe
    LIBS += -lws2_32 -lwsock32
else
    UNAME_S := $(shell uname -s)
    ifeq ($(UNAME_S),Linux)
        PLATFORM = linux
        LIBS += -lrt
    endif
    ifeq ($(UNAME_S),Darwin)
        PLATFORM = macos
        CFLAGS += -I/opt/homebrew/include
        LDFLAGS += -L/opt/homebrew/lib
    endif
    EXT =
endif

# Build rules
.PHONY: all clean install test

all: $(TARGET) $(LIBTARGET)

$(TARGET): $(C_OBJECTS) $(CXX_OBJECTS) $(ASM_OBJECTS) $(ZIG_OBJECTS)
	@echo "Linking $(TARGET)..."
	$(CXX) -o $@ $^ $(LIBS)

$(LIBTARGET): $(C_OBJECTS) $(CXX_OBJECTS) $(ASM_OBJECTS) $(ZIG_OBJECTS)
	@echo "Creating shared library $(LIBTARGET)..."
	$(CXX) $(LDFLAGS) -o $@ $^ $(LIBS)

# C compilation
$(BUILDDIR)/%.o: $(SRCDIR)/%.c
	@mkdir -p $(dir $@)
	@echo "Compiling $<..."
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# C++ compilation
$(BUILDDIR)/%.o: $(SRCDIR)/%.cpp
	@mkdir -p $(dir $@)
	@echo "Compiling $<..."
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c $< -o $@

# Assembly compilation
$(BUILDDIR)/%.o: $(SRCDIR)/%.s
	@mkdir -p $(dir $@)
	@echo "Assembling $<..."
	$(CC) -c $< -o $@

# Zig compilation
$(BUILDDIR)/%.o: src/%.zig
	@mkdir -p $(dir $@)
	@echo "Compiling Zig $<..."
	$(ZIG) build-obj $(ZIGFLAGS) -I$(INCLUDEDIR) -femit-bin=$@ $<

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	rm -rf $(BUILDDIR) $(TARGET) $(LIBTARGET)

# Install
install: $(TARGET) $(LIBTARGET)
	@echo "Installing IoTStrike..."
	install -d /usr/local/bin
	install -d /usr/local/lib
	install -d /usr/local/include/iotstrike
	install $(TARGET) /usr/local/bin/
	install $(LIBTARGET) /usr/local/lib/
	install $(INCLUDEDIR)/*.h /usr/local/include/iotstrike/

# Test targets
test: $(TARGET)
	@echo "Running tests..."
	./$(TARGET) --test

# Hardware tests
hardware-test: $(TARGET)
	@echo "Running hardware tests..."
	$(CC) $(CFLAGS) tools/hardware_test.c -o $(BUILDDIR)/hardware_test $(LIBS)
	./$(BUILDDIR)/hardware_test

# Wireless tests
wireless-test: $(TARGET)
	@echo "Running wireless tests..."
	$(CC) $(CFLAGS) tools/wireless_test.c -o $(BUILDDIR)/wireless_test $(LIBS)
	./$(BUILDDIR)/wireless_test

# Debug build
debug: CFLAGS += -g -DDEBUG
debug: CXXFLAGS += -g -DDEBUG
debug: ZIGFLAGS = -O Debug
debug: $(TARGET)

# Release build
release: CFLAGS += -O3 -DNDEBUG
release: CXXFLAGS += -O3 -DNDEBUG
release: ZIGFLAGS = -O ReleaseFast
release: $(TARGET)

# Code formatting
format:
	@echo "Formatting code..."
	clang-format -i $(C_SOURCES) $(CXX_SOURCES)
	zig fmt $(ZIG_SOURCES)

# Help
help:
	@echo "Available targets:"
	@echo "  all          - Build main executable and library"
	@echo "  clean        - Remove build artifacts"
	@echo "  install      - Install to system"
	@echo "  test         - Run tests"
	@echo "  debug        - Build debug version"
	@echo "  release      - Build optimized version"
	@echo "  format       - Format source code"