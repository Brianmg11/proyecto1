/*
 * Se define la estructura del paquete y funciones de checksum
 */

#ifndef PROTOCOLO_H
#define PROTOCOLO_H

#include <stdint.h>
#include <string.h>

/* Constantes del protocolo */
#define TAM_MAX_DATOS 1024        /* tamaño maximo de datos por paquete */
#define TIMEOUT_SEG 2             /* segundos de timeout para esperar ACK */
#define MAX_REINTENTOS 15         /* intentos maximos de reenvio */
#define MAX_NOMBRE_ARCHIVO 256    /* longitud maxima del nombre de archivo */

/* Banderas (flags) del paquete */
#define FLAG_SYN 0x01    /* inicio de conexion */
#define FLAG_ACK 0x02    /* acknowledgment */
#define FLAG_FIN 0x04    /* fin de transmision */
#define FLAG_DAT 0x08    /* paquete de datos */

typedef struct {
    uint32_t num_seq; /* numero de secuencia del paquete */
    uint32_t num_ack; /* numero de acknowledgment (en SYN-ACK se usa para el puerto) */
    uint16_t tam_datos; /* cantidad de bytes utiles en el campo datos */
    uint8_t  flags; /* banderas que indican el tipo de paquete */
    uint16_t checksum; /* checksum para detectar corrupcion */
    char nombre_archivo[MAX_NOMBRE_ARCHIVO]; /* nombre del archivo (solo se usa en el paquete SYN) */
    char datos[TAM_MAX_DATOS]; /* datos del archivo */
} __attribute__((packed)) paquete_t;

/*
 * Calcula un checksum simple sumando todos los bytes del paquete.
 * Antes de calcular pone el campo checksum en 0 y luego lo restaura.
 */
static uint16_t calcular_checksum(paquete_t *pkt)
{
    uint16_t checksum_guardado = pkt->checksum;
    pkt->checksum = 0;

    uint32_t suma = 0;
    uint8_t *bytes = (uint8_t *)pkt;
    size_t tam = sizeof(paquete_t);

    for (size_t i = 0; i < tam; i++) {
        suma += bytes[i];
    }

    pkt->checksum = checksum_guardado;
    return (uint16_t)(suma & 0xFFFF);
}

/*
 * Verifica que el checksum del paquete recibido sea correcto.
 * Retorna 1 si es valido, 0 si esta corrupto.
 */
static int verificar_checksum(paquete_t *pkt)
{
    uint16_t recibido = pkt->checksum;
    uint16_t calculado = calcular_checksum(pkt);
    return (recibido == calculado);
}

#endif /* PROTOCOLO_H */
