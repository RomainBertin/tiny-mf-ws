OUTPUT = bin/tinymfws
SOURCES = $(addprefix src/, main.c server_config.c server.c log.c)
OBJECTS = $(SOURCES:.c=.o)
CFLAGS = -Wall
CC = gcc

all: $(OUTPUT)

$(OUTPUT): $(OBJECTS)
	@mkdir -p bin
	$(CC) $(CFLAGS) -o $@ $^
	@rm -f $(OBJECTS)

src/%.o: src/%.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OUTPUT) $(OBJECTS)
