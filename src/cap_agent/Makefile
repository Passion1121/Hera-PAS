DIR= .
TARGET=agent
CC=gcc
CFLAGS= -g -Wall -O2
CPPFLAGS= -I ${DEV_ROOT}/include
LIBSDIR= -L ${DEV_ROOT}/lib
LIBS= -lpcap
SRCS=$(wildcard *.c)
OBJS=$(patsubst %.c, %.o, $(SRCS))

$(TARGET):$(OBJS)
	$(CC) $(SRCS) $(CPPFLAGS) $(LIBSDIR) $(LIBS) -o $(TARGET)
$(OBJS):%.o:%.c
	$(CC) -c ${CPPFLAGS} $< -o $@

.PHONLY:clean
clean:
	rm -rf *.o $(TARGET)
