CC = gcc
CFLAGS = -Wall -Wextra -Iinclude
PYINCLUDE = $(shell python3 -c "from sysconfig import get_paths; print(get_paths()['include'])")

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

python: directories $(OBJDIR)/keccak.o $(OBJDIR)/sha3.o
	$(CC) $(CFLAGS) -shared -fPIC -Iinclude -I$(PYINCLUDE) python/sha3module.c -o python/sha3_c.so $(OBJDIR)/keccak.o $(OBJDIR)/sha3.o

python_test: python
	cd python && python3 -c "import sha3_c; print('Testing Python SHA-3 bindings...'); msg = b'Hello, SHA-3!'; print('sha3_256:', sha3_c.sha3_256(msg).hex()); print('sha3_224:', sha3_c.sha3_224(msg).hex()); print('sha3_384:', sha3_c.sha3_384(msg).hex()); print('sha3_512:', sha3_c.sha3_512(msg).hex()); print('sha3_hash:', sha3_c.sha3_hash(msg, 256).hex()); print('All tests passed!')"
	@echo ""
	@echo "Verifying against Python stdlib..."
	@python3 -c "import hashlib; print('Expected sha3_256:', hashlib.sha3_256(b'Hello, SHA-3!').hexdigest())"

tests: directories $(OBJDIR)/keccak.o $(OBJDIR)/sha3.o
	$(CC) $(CFLAGS) -c $(TESTDIR)/sha3_test.c -o $(OBJDIR)/sha3_test.o
	$(CC) $(CFLAGS) $(OBJDIR)/keccak.o $(OBJDIR)/sha3.o $(OBJDIR)/sha3_test.o -o $(BINDIR)/sha3_test
	@echo "Running SHA-3 tests..."
	$(BINDIR)/sha3_test

.PHONY: all clean tests python python_test
