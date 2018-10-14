#
# Projekt: Sip klient
# Autor:   Michal Melichar
# Datum:   22.11.2015
# 

CC=gcc
CFLAGS=-std=c99 -Wall -pedantic -g

sipklient: sipklient.o
	$(CC) $(CFLAGS) sipklient.c -o sipklient -L/usr/lib -lssl -lcrypto

clean:
	rm -f *~ *.bak
