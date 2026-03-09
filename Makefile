CC = gcc
CFLAGS = -Wall -Wextra -Iinclude

SRCDIR = src
OBJDIR = obj
BINDIR = bin
TESTDIR = tests

SRC = $(wildcard $(SRCDIR)/*.c)
OBJ = $(patsubst $(SRCDIR)/%.c, $(OBJDIR)/%.o, $(SRC))
OBJ += $(OBJDIR)/main.o
EXECUTABLE = $(BINDIR)/sha3_example

all: directories $(EXECUTABLE)

directories:
	@mkdir -p $(OBJDIR) $(BINDIR)

$(OBJDIR)/%.o: $(SRCDIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJDIR)/main.o: main.c
	$(CC) $(CFLAGS) -c $< -o $@

$(EXECUTABLE): $(OBJ)
	$(CC) $(CFLAGS) $^ -o $@

clean:
	rm -rf $(OBJDIR) $(BINDIR)

tests: directories $(OBJDIR)/keccak.o $(OBJDIR)/sha3.o
	$(CC) $(CFLAGS) -c $(TESTDIR)/sha3_test.c -o $(OBJDIR)/sha3_test.o
	$(CC) $(CFLAGS) $(OBJDIR)/keccak.o $(OBJDIR)/sha3.o $(OBJDIR)/sha3_test.o -o $(BINDIR)/sha3_test
	@echo "Running SHA-3 tests..."
	$(BINDIR)/sha3_test

.PHONY: all clean tests
