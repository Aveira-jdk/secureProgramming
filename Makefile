CC = gcc
CFLAGS = -Wall -Wextra -Werror -pedantic -fanalyzer -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fPIE -pie -g
ASAN_CFLAGS = -Wall -Wextra -Werror -pedantic -g -O1 -fsanitize=address,undefined
LDFLAGS = -lsodium

SRC_DIR = src
OBJ_DIR = obj
BIN = spm
ASAN_BIN = spm_asan

SRCS = $(wildcard $(SRC_DIR)/*.c)
HDRS = $(wildcard $(SRC_DIR)/*.h)
OBJS = $(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/%.o, $(SRCS))

all: $(BIN)

$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c $(HDRS) | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BIN): $(OBJS)
	$(CC) $(OBJS) -o $(BIN) $(LDFLAGS)

$(ASAN_BIN): $(SRCS) $(HDRS)
	$(CC) $(ASAN_CFLAGS) $(SRCS) -o $(ASAN_BIN) $(LDFLAGS)

test: $(BIN)
	python3 tests/test_spm.py ./$(BIN)

asan: $(ASAN_BIN)
	python3 tests/test_spm.py ./$(ASAN_BIN)

clean:
	rm -rf $(OBJ_DIR) $(BIN) $(ASAN_BIN)

.PHONY: all test asan clean
