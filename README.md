sqlrand-llvm
============

An LLVM project that performs sanitization of SQL queries in a given
application, inspired by the SQLrand paper (2004) by Stephen W. Boyd &
Angelos D. Keromytis

Currently supports MySQL and PostgreSQL databases. sqlrand-llvm uses llvm-deps
(https://github.com/thinkmoore/llvm-deps) for its source-sink analysis.

All the SQL keywords of the application that might be used in an SQL statement
are substituted with "random" strings and the mapping is stored. Any legal SQL
statement of the application is thus transformed into a string containing no SQL
keywords. If such a keyword is found before the execution of the statement, the
execution is terminated and a log file is written.

At its current form this project lacks security guarantees (e.x. strings
are not truly randomized etc) and has not been tested extensively. You should
have received a LICENSE copy with this software.


Installation Instructions:
==========================

0)  Depending on your system you might need to install autoconf, g++4.5
	and configure gcc accordingly

1)

    mkdir ~/sqlrand and checkout the llvm source code there

    mv llvm-deps ~/sqlrand/llvm/projects && mv sqlrand-helpers ~/sqlrand/llvm

	mkdir ~/sqlrand-build && cd ~/sqlrand-build

	CC=gcc CXX=g++ ../sqlrand/llvm/configure --enable-optimized

	make -jXX

2) Edit your .profile with the following

	export SS_CC="/home/your_username/sqlrand-build/Release+Asserts/bin/clang -O3 \
	-Xclang -load -Xclang /home/your_username/sqlrand-build/projects/poolalloc/Release+Asserts/lib/LLVMDataStructure.so \
	-Xclang -load -Xclang /home/your_username/sqlrand-build/projects/poolalloc/Release+Asserts/lib/AssistDS.so \
	-Xclang -load -Xclang /home/your_username/sqlrand-build/projects/llvm-deps/Release+Asserts/lib/pointstointerface.so \
	-Xclang -load -Xclang /home/your_username/sqlrand-build/projects/llvm-deps/Release+Asserts/lib/sourcesinkanalysis.so \
	-Xclang -load -Xclang /home/your_username/sqlrand-build/projects/llvm-deps/Release+Asserts/lib/Constraints.so \
	-Xclang -load -Xclang /home/your_username/sqlrand-build/projects/llvm-deps/Release+Asserts/lib/Deps.so \
	-Xclang -load -Xclang /home/your_username/sqlrand-build/projects/llvm-deps/Release+Asserts/lib/SQLRand.so"

and source ~/.profile

3)
	cd ~/sqlrand/llvm/sqlrand_helpers && make


Testing:
========

You can see the IR for any of the test programs by passing -emmit-llvm -S:

E.x.:

	$SS_CC -emit-llvm -S test.c -I/usr/include/mysql -I/usr/include/postgresql

Full:

	$SS_CC test.c -I/usr/include/mysql -I/usr/include/postgresql -lpq -lmysqlclient -L/home/your_username/sqlrand-build/Release+Asserts/lib/clang/3.2/lib/linux	-lsqlrand -o test


Known Issues:
=============
1) To resolve c++config.h errors in compiler-rt, copy to the include directory
of your c++ version from a library that has the respective headers:


	cp /usr/include/x86_64-linux-gnu/c++/4.9/bits/c++config.h /usr/include/c++/4.9/bits

	cp /usr/include/x86_64-linux-gnu/c++/4.9/bits/os_defines.h /usr/include/c++/4.9/bits

	cp /usr/include/x86_64-linux-gnu/c++/4.9/bits/cpu_defines.h /usr/include/c++/4.9/bits
