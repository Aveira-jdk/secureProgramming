CC = gcc
CFLAGS = -Wall -Wextra -Werror -pedantic -fanalyzer -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fPIE -pie -g
LDFLAGS = -lsodium

SRC_DIR = src
OBJ_DIR = obj
BIN = spm

SRCS = $(wildcard $(SRC_DIR)/*.c)
OBJS = $(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/%.o, $(SRCS))

all: $(BIN)

$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BIN): $(OBJS)
	$(CC) $(OBJS) -o $(BIN) $(LDFLAGS)

clean:
	rm -rf $(OBJ_DIR) $(BIN) vault.bin

.PHONY: all clean
