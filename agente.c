/*
 * Agente del sistema SIEMLite Distribuido.
 * Recolecta logs (journalctl) y metricas (free, df, ps) del sistema,
 * y los envia a un servidor central utilizando un protocolo confiable sobre UDP.
 *
 * Utiliza memoria compartida y procesos hijos persistentes para el monitoreo
 * continuo de los logs.
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
#include <sys/ipc.h>
#include <sys/shm.h>
#include <semaphore.h>
#include <errno.h>
#include "protocolo.h"

#define MAX_SERVICIOS 10
#define NUM_PRIORIDADES 8
#define MAX_NOMBRE 64
#define MAX_BUFFER 4096
#define SEM_NOMBRE "/siemlite_agente_sem"
#define SHM_LLAVE 0x5349454D

/* Estructura para métricas */
typedef struct {
    int mem_pct;
    int disk_pct;
    int procs;
} MetricasSistema;

/* Estructura para la memoria compartida */
typedef struct {
    int ejecutando;
    struct {
        char nombre[MAX_NOMBRE];
        int contadores[NUM_PRIORIDADES];
    } servicios[MAX_SERVICIOS];
} DatosCompartidosAgente;

static volatile sig_atomic_t g_terminar = 0;
static int g_shm_id = -1;
static DatosCompartidosAgente *g_shm = NULL;
static sem_t *g_sem = NULL;
static pid_t g_pids[MAX_SERVICIOS];
static int g_num_hijos = 0;

static void manejar_senal(int sig) {
    (void)sig;
    g_terminar = 1;
    if (g_shm != NULL) {
        g_shm->ejecutando = 0;
    }
}

/* ================================================================
 *           MEMORIA COMPARTIDA Y SEMAFOROS
 * ================================================================ */

static int crear_recursos_ipc(int n_servicios, char **nombres) {
    size_t tam = sizeof(DatosCompartidosAgente);

    /* Limpiar segmento anterior si existe */
    int id_viejo = shmget(SHM_LLAVE, tam, 0666);
    if (id_viejo != -1) {
        shmctl(id_viejo, IPC_RMID, NULL);
    }

    g_shm_id = shmget(SHM_LLAVE, tam, IPC_CREAT | IPC_EXCL | 0666);
    if (g_shm_id == -1) {
        perror("shmget");
        return -1;
    }

    g_shm = (DatosCompartidosAgente *)shmat(g_shm_id, NULL, 0);
    if (g_shm == (void *)-1) {
        perror("shmat");
        return -1;
    }

    memset(g_shm, 0, tam);
    g_shm->ejecutando = 1;
    for (int i = 0; i < n_servicios; i++) {
        strncpy(g_shm->servicios[i].nombre, nombres[i], MAX_NOMBRE - 1);
    }

    sem_unlink(SEM_NOMBRE);
    g_sem = sem_open(SEM_NOMBRE, O_CREAT | O_EXCL, 0666, 1);
    if (g_sem == SEM_FAILED) {
        perror("sem_open");
        return -1;
    }

    return 0;
}

static void limpiar_recursos(void) {
    for (int i = 0; i < g_num_hijos; i++) {
        if (g_pids[i] > 0) {
            kill(g_pids[i], SIGTERM);
            waitpid(g_pids[i], NULL, 0);
        }
    }
    if (g_shm != NULL) {
        shmdt(g_shm);
        g_shm = NULL;
    }
    if (g_shm_id != -1) {
        shmctl(g_shm_id, IPC_RMID, NULL);
        g_shm_id = -1;
    }
    if (g_sem != NULL) {
        sem_close(g_sem);
        sem_unlink(SEM_NOMBRE);
        g_sem = NULL;
    }
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

static void consultar_logs(int idx, const char *servicio, int intervalo) {
    int fd_pipe[2];

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
    
    int conteo[NUM_PRIORIDADES] = {0};
    
    FILE *fp = fdopen(fd_pipe[0], "r");
    if (fp != NULL) {
        char linea[MAX_BUFFER];
        while (fgets(linea, sizeof(linea), fp) != NULL) {
            int p = extraer_prioridad(linea);
            if (p >= 0 && p < NUM_PRIORIDADES) {
                conteo[p]++;
            }
        }
        fclose(fp);
    } else {
        close(fd_pipe[0]);
    }
    
    waitpid(pid, NULL, 0);
    
    /* Guardar en memoria compartida (acumular) */
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += 2;
    if (sem_timedwait(g_sem, &ts) == 0) {
        for (int p = 0; p < NUM_PRIORIDADES; p++) {
            g_shm->servicios[idx].contadores[p] += conteo[p];
        }
        sem_post(g_sem);
    }
}

static void proceso_hijo_monitor(int idx, const char *servicio, int intervalo) {
    signal(SIGTERM, manejar_senal);
    signal(SIGINT, SIG_DFL);

    while (!g_terminar) {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += 2;
        if (sem_timedwait(g_sem, &ts) == 0) {
            if (!g_shm->ejecutando) {
                sem_post(g_sem);
                break;
            }
            sem_post(g_sem);
        }

        time_t inicio = time(NULL);
        consultar_logs(idx, servicio, intervalo);
        time_t transcurrido = time(NULL) - inicio;

        int dormir = intervalo - (int)transcurrido;
        if (dormir > 0 && !g_terminar) {
            sleep(dormir);
        }
    }

    if (g_shm != NULL) {
        shmdt(g_shm);
    }
    if (g_sem != NULL) {
        sem_close(g_sem);
    }
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

    if (crear_recursos_ipc(n_servicios, servicios) != 0) {
        fprintf(stderr, "Error al crear memoria compartida.\n");
        return EXIT_FAILURE;
    }

    for (int i = 0; i < n_servicios && i < MAX_SERVICIOS; i++) {
        pid_t pid = fork();
        if (pid == -1) {
            perror("fork");
            limpiar_recursos();
            return EXIT_FAILURE;
        }
        if (pid == 0) {
            proceso_hijo_monitor(i, servicios[i], intervalo);
            _exit(EXIT_SUCCESS);
        }
        g_pids[i] = pid;
        g_num_hijos++;
    }

    char temp_filename[64];
    snprintf(temp_filename, sizeof(temp_filename), "datos_agente_%d.dat", getpid());
    
    printf("=== Agente SIEMLite Iniciado ===\n");
    printf("Servidor: %s:%d\nIntervalo: %d seg\nProcesos Hijos Activos: %d\n", host, puerto, intervalo, g_num_hijos);

    while (!g_terminar) {
        printf("\nRecolectando informacion...\n");
        
        MetricasSistema metricas;
        recolectar_metricas(&metricas);
        
        /* Copia local de los datos para no bloquear mucho el semaforo */
        DatosCompartidosAgente copia_shm;
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += 2;
        if (sem_timedwait(g_sem, &ts) == 0) {
            memcpy(&copia_shm, g_shm, sizeof(DatosCompartidosAgente));
            sem_post(g_sem);
        } else {
            memset(&copia_shm, 0, sizeof(DatosCompartidosAgente));
        }
        
        /* Escribir a archivo temporal */
        FILE *f = fopen(temp_filename, "w");
        if (f) {
            fprintf(f, "METRICS\n");
            fprintf(f, "MEM_PCT %d\n", metricas.mem_pct);
            fprintf(f, "DISK_PCT %d\n", metricas.disk_pct);
            fprintf(f, "PROCS %d\n", metricas.procs);
            fprintf(f, "SERVICES %d\n", n_servicios);
            for (int i = 0; i < n_servicios && i < MAX_SERVICIOS; i++) {
                fprintf(f, "SVC %s", copia_shm.servicios[i].nombre);
                for (int p = 0; p < NUM_PRIORIDADES; p++) {
                    fprintf(f, " %d", copia_shm.servicios[i].contadores[p]);
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
        
        /* Dormir hasta el proximo intervalo */
        int restante = intervalo;
        while (restante > 0 && !g_terminar) {
            restante = sleep(restante);
        }
    }
    
    limpiar_recursos();
    remove(temp_filename);
    printf("\nAgente finalizado.\n");
    return EXIT_SUCCESS;
}
