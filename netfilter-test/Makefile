LDLIBS=-lnetfilter_queue

all: netfilter-test

netfilter-test: main.o ip.o iphdr.o tcphdr.o data.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@ 

clean:
	rm -f netfilter-test *.o