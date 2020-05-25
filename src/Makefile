CFLAGS += -O2 -Wall -Werror

QoSimodo: QoSimodo.o conntrack.o
	$(CC) $(CFLAGS) -o $@ QoSimodo.c conntrack.c $(LDFLAGS)

clean:
	rm -f QoSimodo *.o
