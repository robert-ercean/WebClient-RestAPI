CPP=g++
CPPFLAGS=-I.

client: client.cpp requests.cpp helpers.cpp buffer.cpp
	$(CPP) -o client client.cpp requests.cpp helpers.cpp buffer.cpp -Wall

run: client
	./client

clean:
	rm -f *.o client
