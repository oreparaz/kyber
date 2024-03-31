all: demo

%.o: %.c Makefile
	$(CC) $(CPPFLAGS) $(CFLAGS) -DKYBER_K=2 -c $< -o $@

demo: demo.c kyber.o 
	$(CC) -DKYBER_K=2 demo.c -o demo kyber.o
	./demo

clean:
	$(RM) -f *.o demo