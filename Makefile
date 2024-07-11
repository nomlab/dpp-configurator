CC = gcc

# コンパイルフラグ
#CFLAGS = -c
CFLAGS = -c -g  -Wno-deprecated-declarations
LDFLAGS = -lcrypto -lssl -lmbedtls -lmbedcrypto -lpcap

# ターゲット
TARGET = dpp-configurator

# オブジェクトファイル
OBJS = crypto.o dpp-configurator.o

# 依存ファイル
#DEPS = requestframe.c authreq.c

# ルール
all: $(TARGET)

%.o: %.c
	$(CC) $(CFLAGS) $<

$(TARGET): $(OBJS)
	$(CC) -o $(TARGET) $(OBJS) $(LDFLAGS)

clean:
	rm -f $(OBJS) $(TARGET)
