CC = gcc
CFLAGS = -Wall -Wextra
LDFLAGS = -lrt -lpthread

# Objetivos principales
all: servidor agente anomaly_gen

# Compilar el servidor central
servidor: servidor.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

# Compilar el agente (cliente)
agente: agente.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

# Compilar el generador de anomalias
anomaly_gen: anomaly_gen.c
	$(CC) $(CFLAGS) -o $@ $<

# Limpiar ejecutables
clean:
	rm -f servidor agente anomaly_gen

.PHONY: all clean
