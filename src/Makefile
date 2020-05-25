CFLAGS += -O2 -Wall -Werror

objects = QoSimodo.o conntrack.o

QoSimodo: $(objects)
	$(CC) $(CFLAGS) -o $@ $(objects) $(LDFLAGS)

QoSimodo.o: QoSimodo.h
conntrack.o: QoSimodo.h

.PHONY: clean
clean:
	rm -f QoSimodo $(objects)
