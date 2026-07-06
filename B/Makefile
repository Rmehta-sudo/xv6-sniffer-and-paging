# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -D_DEFAULT_SOURCE -D_BSD_SOURCE -Isrc
LDFLAGS = -lpcap

# Directories
SRCDIR = src
OBJDIR = obj
BINDIR = bin

# Find all .c files in the source directory
SOURCES = $(wildcard $(SRCDIR)/*.c)
# Replace the .c extension with .o and put them in the object directory
OBJECTS = $(patsubst $(SRCDIR)/%.c, $(OBJDIR)/%.o, $(SOURCES))
# Add root-level main.c
MAIN_SRC = main.c
MAIN_OBJ = $(OBJDIR)/main.o
OBJECTS += $(MAIN_OBJ)

# The final executable name
EXECUTABLE = $(BINDIR)/cshark

# Default target: build the executable
all: $(EXECUTABLE)

# Rule to link the executable
$(EXECUTABLE): $(OBJECTS)
	@mkdir -p $(BINDIR)
	$(CC) $(OBJECTS) -o $@ $(LDFLAGS)
	@echo "C-Shark compiled successfully. Ready for the hunt."

# Rule to compile source files into object files
$(OBJDIR)/%.o: $(SRCDIR)/%.c
	@mkdir -p $(OBJDIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Rule to compile root-level main.c
$(OBJDIR)/main.o: $(MAIN_SRC)
	@mkdir -p $(OBJDIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Rule to clean up the project
clean:
	@rm -rf $(OBJDIR) $(BINDIR)
	@echo "Cleaning the tank... All clear."

# Phony targets
.PHONY: all clean
