all:
	cc -I/usr/include/mysql -I/usr/include/postgresql -fPIC -c \
		-o sqlrand_helpers.o sqlrand_helpers.c
	ar -cq libsqlrand.a sqlrand_helpers.o
	cp libsqlrand.a ~/sqlrand-build/Release+Asserts/lib/clang/3.2/lib/linux/
clean:
	rm sqlrand_helpers.o
	rm libsqlrand.a
	rm ~/sqlrand-build/Release+Asserts/lib/clang/3.2/lib/linux/libsqlrand.a
