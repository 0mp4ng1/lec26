#Makefile
all:	add-nbo

add-nbo:	btol.o sum.o main.o
	g++ -o add-nbo btol.o sum.o main.o

main.o:	btol.h sum.h main.cpp

sum.o:	sum.h sum.cpp

btol.o:	btol.h btol.cpp

clean:
	rm -f add-nbo
	rm -f *.o
