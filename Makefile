TARGET := cgi_test

CROSS_COMPILE :=
CC = $(CROSS_COMPILE)gcc
LD = $(CROSS_COMPILE)ld

OBJS := cgi_test.o

CFLAGS += -Wall -I./inc

LDFLASGS+=

OUTPUT_DIR = /root/nms/study/cgi/

all:$(TARGET)
$(TARGET):$(OBJS)
	$(CC) $(LDFLAGS) $^ -o $@
	cp $@ $(OUTPUT_DIR)
	
%.O:%.c
	$(CC) $(CFLAGS) -c $^ -o $@
