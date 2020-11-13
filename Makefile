CC=gcc
OBJS=retmas.c cpu.c inst.c elf.c symbol.c relocation.c jump.c createcpu.c modifyinst.c
BIN=$(HOME)/bin/
TARGET=$(BIN)retmas
TARGET_DEBUG=$(BIN)retmas_debug

all : $(OBJS)
	$(CC) $(OBJS) -o $(TARGET)

debug: $(OBJS)
	$(CC) -g -DDEBUG $(OBJS) -o $(TARGET_DEBUG)

clean:
	rm -f $(TARGET) $(TARGET_DEBUG)
	rm -f *.o
