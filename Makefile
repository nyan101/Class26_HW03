SendARP: SendARP.o myLocalAddress.o myARPtools.o myLocalAddress.h myARPtools.h
	g++ -std=c++11 -o SendARP SendARP.o myLocalAddress.o myARPtools.o -lpcap

SendARP.o: SendARP.cpp myLocalAddress.h myARPtools.h
	g++ -std=c++11 -c SendARP.cpp

myLocalAddress.o: myLocalAddress.cpp myLocalAddress.h
	g++ -std=c++11 -c myLocalAddress.cpp

myARPtools.o: myARPtools.cpp myARPtools.h myLocalAddress.h
	g++ -std=c++11 -c myARPtools.cpp	

clean:
	rm *.o SendARP
