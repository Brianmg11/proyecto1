/*
 * Agente del sistema SIEMLite Distribuido.
 * Recolecta logs (journalctl) y metricas (free, df, ps) del sistema,
 * y los envia a un servidor central utilizando un protocolo confiable sobre UDP.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <libgen.h>
#include "protocolo.h"

#define MAX_SERVICIOS 10
#define NUM_PRIORIDADES 8
#define MAX_NOMBRE 64
#define MAX_BUFFER 4096

/* Estructura para almacenar resultados locales temporalmente */
typedef struct {
    char nombre[MAX_NOMBRE];
    int contadores[NUM_PRIORIDADES];
} LogsServicio;

typedef struct {
    int mem_pct;
    int disk_pct;
    int procs;
} MetricasSistema;

static volatile sig_atomic_t g_terminar = 0;

static void manejar_senal(int sig) {
    (void)sig;
    g_terminar = 1;
}

/* ================================================================
 *                    COLECCION DE LOGS
 * ================================================================ */

static int extraer_prioridad(const char *linea) {
    const char *ptr;
    ptr = strstr(linea, "\"PRIORITY\":\"");
    if (ptr != NULL) {
        ptr += 12;
        if (*ptr >= '0' && *ptr <= '7') return *ptr - '0';
    }
    ptr = strstr(linea, "\"PRIORITY\" : \"");
    if (ptr != NULL) {
        ptr += 14;
        if (*ptr >= '0' && *ptr <= '7') return *ptr - '0';
    }
    return -1;
}

static void consultar_logs(const char *servicio, int intervalo, LogsServicio *out) {
    int fd_pipe[2];
    memset(out->contadores, 0, sizeof(out->contadores));
    strncpy(out->nombre, servicio, MAX_NOMBRE - 1);

    if (pipe(fd_pipe) == -1) return;

    pid_t pid = fork();
    if (pid == -1) {
        close(fd_pipe[0]);
        close(fd_pipe[1]);
        return;
    }

    if (pid == 0) {
        close(fd_pipe[0]);
        dup2(fd_pipe[1], STDOUT_FILENO);
        
        int nulo = open("/dev/null", O_WRONLY);
        if (nulo >= 0) {
            dup2(nulo, STDERR_FILENO);
            close(nulo);
        }
        close(fd_pipe[1]);

        char desde[64];
        snprintf(desde, sizeof(desde), "%d seconds ago", intervalo);
        execlp("journalctl", "journalctl", "-u", servicio, "--since", desde, "--no-pager", "-o", "json", NULL);
        _exit(EXIT_FAILURE);
    }

    close(fd_pipe[1]);
    FILE *fp = fdopen(fd_pipe[0], "r");
    if (fp != NULL) {
        char linea[MAX_BUFFER];
        while (fgets(linea, sizeof(linea), fp) != NULL) {
            int p = extraer_prioridad(linea);
            if (p >= 0 && p < NUM_PRIORIDADES) {
                out->contadores[p]++;
            }
        }
        fclose(fp);
    } else {
        close(fd_pipe[0]);
    }
    waitpid(pid, NULL, 0);
}

/* ================================================================
 *                    COLECCION DE METRICAS
 * ================================================================ */

static int recolectar_memoria() {
    int fd_pipe[2];
    if (pipe(fd_pipe) == -1) return 0;

    pid_t pid = fork();
    if (pid == 0) {
        close(fd_pipe[0]);
        dup2(fd_pipe[1], STDOUT_FILENO);
        execlp("free", "free", NULL);
        _exit(EXIT_FAILURE);
    }
    close(fd_pipe[1]);
    FILE *fp = fdopen(fd_pipe[0], "r");
    int mem_pct = 0;
    if (fp != NULL) {
        char linea[256];
        int linea_num = 0;
        while (fgets(linea, sizeof(linea), fp) != NULL) {
            if (linea_num == 1) { // Linea "Mem:"
                long total = 0, used = 0;
                sscanf(linea, "Mem: %ld %ld", &total, &used);
                if (total > 0) mem_pct = (int)((used * 100) / total);
                break;
            }
            linea_num++;
        }
        fclose(fp);
    }
    waitpid(pid, NULL, 0);
    return mem_pct;
}

static int recolectar_disco() {
    int fd_pipe[2];
    if (pipe(fd_pipe) == -1) return 0;

    pid_t pid = fork();
    if (pid == 0) {
        close(fd_pipe[0]);
        dup2(fd_pipe[1], STDOUT_FILENO);
        execlp("df", "df", "/", NULL);
        _exit(EXIT_FAILURE);
    }
    close(fd_pipe[1]);
    FILE *fp = fdopen(fd_pipe[0], "r");
    int disk_pct = 0;
    if (fp != NULL) {
        char linea[256];
        int linea_num = 0;
        while (fgets(linea, sizeof(linea), fp) != NULL) {
            if (linea_num == 1) {
                char fs[64];
                long blocks, used, avail;
                char pct_str[16];
                sscanf(linea, "%s %ld %ld %ld %s", fs, &blocks, &used, &avail, pct_str);
                sscanf(pct_str, "%d%%", &disk_pct);
                break;
            }
            linea_num++;
        }
        fclose(fp);
    }
    waitpid(pid, NULL, 0);
    return disk_pct;
}

static int recolectar_procesos() {
    int fd_pipe[2];
    if (pipe(fd_pipe) == -1) return 0;

    pid_t pid = fork();
    if (pid == 0) {
        close(fd_pipe[0]);
        dup2(fd_pipe[1], STDOUT_FILENO);
        execlp("ps", "ps", "-e", NULL);
        _exit(EXIT_FAILURE);
    }
    close(fd_pipe[1]);
    FILE *fp = fdopen(fd_pipe[0], "r");
    int count = 0;
    if (fp != NULL) {
        char linea[256];
        while (fgets(linea, sizeof(linea), fp) != NULL) {
            count++;
        }
        fclose(fp);
    }
    waitpid(pid, NULL, 0);
    if (count > 0) count--; // Restar la cabecera
    return count;
}

static void recolectar_metricas(MetricasSistema *out) {
    out->mem_pct = recolectar_memoria();
    out->disk_pct = recolectar_disco();
    out->procs = recolectar_procesos();
}

/* ================================================================
 *             ENVIO DE ARCHIVO (PROTOCOL STOP & WAIT UDP)
 * ================================================================ */

static int enviar_archivo(const char *host, int puerto, const char *archivo) {
    FILE *fp = fopen(archivo, "rb");
    if (fp == NULL) return 0;
    
    fseek(fp, 0, SEEK_END);
    fseek(fp, 0, SEEK_SET);
    
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        fclose(fp);
        return 0;
    }
    
    struct timeval tv;
    tv.tv_sec = TIMEOUT_SEG;
    tv.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    
    struct sockaddr_in dir_receptor;
    memset(&dir_receptor, 0, sizeof(dir_receptor));
    dir_receptor.sin_family = AF_INET;
    dir_receptor.sin_port = htons(puerto);
    inet_pton(AF_INET, host, &dir_receptor.sin_addr);
    socklen_t tam_dir = sizeof(dir_receptor);
    
    /* FASE 1: SYN */
    paquete_t pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.flags = FLAG_SYN;
    pkt.num_seq = 0;
    
    char copia_nombre[MAX_NOMBRE_ARCHIVO];
    strncpy(copia_nombre, archivo, MAX_NOMBRE_ARCHIVO - 1);
    strncpy(pkt.nombre_archivo, basename(copia_nombre), MAX_NOMBRE_ARCHIVO - 1);
    pkt.checksum = calcular_checksum(&pkt);
    
    int reintentos = 0;
    int conectado = 0;
    int puerto_nuevo = 0;
    
    while (reintentos < MAX_REINTENTOS && !conectado) {
        sendto(sockfd, &pkt, sizeof(pkt), 0, (struct sockaddr *)&dir_receptor, tam_dir);
        paquete_t resp;
        ssize_t n = recvfrom(sockfd, &resp, sizeof(resp), 0, NULL, NULL);
        if (n > 0 && verificar_checksum(&resp) && (resp.flags & (FLAG_SYN | FLAG_ACK)) == (FLAG_SYN | FLAG_ACK)) {
            puerto_nuevo = resp.num_ack;
            conectado = 1;
        } else {
            reintentos++;
        }
    }
    
    if (!conectado) {
        fclose(fp);
        close(sockfd);
        return 0; /* Error conexion */
    }
    
    dir_receptor.sin_port = htons(puerto_nuevo);
    
    /* FASE 2: DATOS */
    uint32_t num_seq = 1;
    int transferencia_ok = 1;
    
    while (!feof(fp)) {
        memset(&pkt, 0, sizeof(pkt));
        size_t leidos = fread(pkt.datos, 1, TAM_MAX_DATOS, fp);
        if (leidos == 0) break;
        
        pkt.flags = FLAG_DAT;
        pkt.num_seq = num_seq;
        pkt.tam_datos = (uint16_t)leidos;
        pkt.checksum = calcular_checksum(&pkt);
        
        reintentos = 0;
        int ack_ok = 0;
        while (reintentos < MAX_REINTENTOS && !ack_ok) {
            sendto(sockfd, &pkt, sizeof(pkt), 0, (struct sockaddr *)&dir_receptor, tam_dir);
            paquete_t resp;
            ssize_t n = recvfrom(sockfd, &resp, sizeof(resp), 0, NULL, NULL);
            if (n > 0 && verificar_checksum(&resp) && (resp.flags & FLAG_ACK) && resp.num_ack == num_seq) {
                ack_ok = 1;
            } else {
                reintentos++;
            }
        }
        if (!ack_ok) {
            transferencia_ok = 0;
            break;
        }
        num_seq++;
    }
    
    /* FASE 3: FIN */
    if (transferencia_ok) {
        memset(&pkt, 0, sizeof(pkt));
        pkt.flags = FLAG_FIN;
        pkt.num_seq = num_seq;
        pkt.checksum = calcular_checksum(&pkt);
        
        reintentos = 0;
        int fin_ok = 0;
        while (reintentos < MAX_REINTENTOS && !fin_ok) {
            sendto(sockfd, &pkt, sizeof(pkt), 0, (struct sockaddr *)&dir_receptor, tam_dir);
            paquete_t resp;
            ssize_t n = recvfrom(sockfd, &resp, sizeof(resp), 0, NULL, NULL);
            if (n > 0 && verificar_checksum(&resp) && (resp.flags & (FLAG_FIN | FLAG_ACK)) == (FLAG_FIN | FLAG_ACK)) {
                fin_ok = 1;
            } else {
                reintentos++;
            }
        }
    }
    
    fclose(fp);
    close(sockfd);
    return transferencia_ok;
}

/* ================================================================
 *                              MAIN
 * ================================================================ */

int main(int argc, char *argv[]) {
    if (argc < 5) {
        fprintf(stderr, "Uso: %s <host_servidor> <puerto_servidor> <intervalo> <servicio_1> [servicio_2 ...]\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *host = argv[1];
    int puerto = atoi(argv[2]);
    int intervalo = atoi(argv[3]);
    
    if (intervalo < 1) intervalo = 10;
    
    int n_servicios = argc - 4;
    char **servicios = &argv[4];

    signal(SIGINT, manejar_senal);
    signal(SIGTERM, manejar_senal);

    char temp_filename[64];
    snprintf(temp_filename, sizeof(temp_filename), "datos_agente_%d.dat", getpid());
    
    printf("=== Agente SIEMLite Iniciado ===\n");
    printf("Servidor: %s:%d\nIntervalo: %d seg\n", host, puerto, intervalo);

    while (!g_terminar) {
        printf("\nRecolectando informacion...\n");
        
        MetricasSistema metricas;
        recolectar_metricas(&metricas);
        
        LogsServicio logs[MAX_SERVICIOS];
        for (int i = 0; i < n_servicios && i < MAX_SERVICIOS; i++) {
            consultar_logs(servicios[i], intervalo, &logs[i]);
        }
        
        /* Escribir a archivo temporal */
        FILE *f = fopen(temp_filename, "w");
        if (f) {
            /* El formato debe ser facil de leer por el servidor */
            fprintf(f, "METRICS\n");
            fprintf(f, "MEM_PCT %d\n", metricas.mem_pct);
            fprintf(f, "DISK_PCT %d\n", metricas.disk_pct);
            fprintf(f, "PROCS %d\n", metricas.procs);
            fprintf(f, "SERVICES %d\n", n_servicios);
            for (int i = 0; i < n_servicios && i < MAX_SERVICIOS; i++) {
                fprintf(f, "SVC %s", logs[i].nombre);
                for (int p = 0; p < NUM_PRIORIDADES; p++) {
                    fprintf(f, " %d", logs[i].contadores[p]);
                }
                fprintf(f, "\n");
            }
            fclose(f);
            
            /* Enviar el archivo */
            if (enviar_archivo(host, puerto, temp_filename)) {
                printf(" -> Datos enviados al servidor exitosamente.\n");
            } else {
                printf(" -> [ERROR] Fallo al enviar datos al servidor.\n");
            }
        }
        
        /* Dormir hasta el proximo intervalo, chequeando g_terminar */
        int restante = intervalo;
        while (restante > 0 && !g_terminar) {
            restante = sleep(restante);
        }
    }
    
    /* Limpiar */
    remove(temp_filename);
    printf("\nAgente finalizado.\n");
    return EXIT_SUCCESS;
}
