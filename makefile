.PHONY : echo-client echo-server clean

all: echo-client echo-server

echo-client:
	cd echo-client; make; cd ..

echo-server:
	cd echo-server; make; cd ..

clean:
	cd echo-client; make clean; cd ..
	cd echo-server; make clean; cd ..