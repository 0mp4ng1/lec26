TARGET=../bin/echo-client
LDLIBS+=-pthread

all: $(TARGET)

$(TARGET): echo-client.o 
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@ 

clean:
	rm -f echo-client *.o
