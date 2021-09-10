#Makefile
all:	add-nbo

add-nbo:	btol.o main.o
	g++ -o add-nbo btol.o main.o

main.o:	btol.h main.cpp

btol.o:	btol.h btol.cpp

clean:
	rm -f add-nbo
	rm -f *.o
