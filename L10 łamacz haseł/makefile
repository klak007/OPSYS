CC=gcc

#CFLAGS= -Og -std=gnu11 -Wall -Wextra -Wno-unused-parameter -Wno-unused-function
# ogolne flagi kompilacji dla modulow

LDFLAGS= -lpthread -lssl -lcrypto -lncurses
# ogolne flagi konsolidacji programu

DEPS = passwd.h
NAME = passwd

$(NAME): passwd.c  $(DEPS)
	$(CC) $(CFLAGS) passwd.c  -o $(NAME) $(LDFLAGS)

clean:
	rm *.o passwd