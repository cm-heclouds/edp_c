all: edp.exe

CC=gcc
CFLAGS=-I. -g -D_LINUX -lm -lpthread

CLIENT_OBJ = cJSON.o EdpKit.o Main.o

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

edp.exe: $(CLIENT_OBJ)
	gcc -o $@ $^ $(CFLAGS)

clean:
	rm -f edp.exe $(CLIENT_OBJ)
