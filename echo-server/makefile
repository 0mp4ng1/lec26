TARGET=../bin/echo-server
LDLIBS+=-pthread

all: $(TARGET)

$(TARGET): echo-server.o 
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@ 

clean:
	rm -f echo-server *.o
