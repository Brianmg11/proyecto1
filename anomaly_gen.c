#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <errno.h>

#define MAX_WORKERS 8

/* Flag global para detener los workers */
static volatile sig_atomic_t g_detener = 0;

/* Datos diferentes para enviar al servicio.*/
static const char *PAYLOADS[] = {
    "INVALID_PROTOCOL_v1\r\n",                     /* Protocolo invalido */
    "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n",   /* HTTP a un no-HTTP */
    "\x00\x01\x02\x03\x04\x05",                    /* Datos binarios */
    "SSH-2.0-AnomalyTest\r\nINVALID_KEX\r\n",      /* SSH con kex invalido */
    "QUIT\r\n",                                     /* Cierre abrupto */
};
#define NUM_PAYLOADS 5

/* Manejador de señales */
static void manejador_senal(int sig) {
    (void)sig;
    g_detener = 1;
}

/* Menu  */
static void mostrar_uso(const char *prog) {
    fprintf(stderr,
        "Uso: %s [-p <puerto>] [-w <workers>] [-d <duracion>] [-m <modo>]\n\n"
        "Parametros:\n"
        "  -p <puerto>    Puerto del servicio objetivo (default: 22)\n"
        "  -w <workers>   Numero de procesos worker (default: 3, max %d)\n"
        "  -d <segundos>  Duracion del estres en segundos (default: 30)\n"
        "  -m <modo>      Modo de operacion:\n"
        "                   1 = Conexiones TCP malformadas (default)\n"
        "                   2 = Intentos SSH fallidos (solo puerto 22)\n"
        "  -h             Mostrar esta ayuda\n\n"
        "Ejemplos:\n"
        "  %s -p 22 -w 3 -d 30          (TCP flood al puerto 22)\n"
        "  %s -p 22 -m 2 -w 2 -d 20    (Auth SSH fallidos)\n\n"
        "Nota: Para generar logs en sshd, puede necesitar ejecutar con sudo sino no funcionaria.\n",
        prog, MAX_WORKERS, prog, prog);
}

/* ================================================================
 *                     MODO 1: TCP FLOOD
 * ================================================================ */

/*
 * Worker que realiza conexiones TCP rapidas a un puerto.
 * Envia datos malhechos para generar errores en el servicio.
 */
static void worker_tcp(const char *host, int puerto, int id_worker) {
    int conexiones = 0;
    int errores = 0;
    int payload_idx = 0;

    printf("[Worker %d] Iniciando TCP flood a %s:%d\n", id_worker, host, puerto);

    while (!g_detener) {
        /* Crear socket TCP */
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) {
            errores++;
            usleep(100000); /* 100ms */
            continue;
        }

        /* Configurar timeout de 2 segundos para no blqquearnos */
        struct timeval tv;
        tv.tv_sec = 2;
        tv.tv_usec = 0;
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        /* Direccion del servicio */
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(puerto);
        inet_pton(AF_INET, host, &addr.sin_addr);

        /* Intentar conexion */
        if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
            /* Conexion exitosa */
            char buf[256];
            read(sock, buf, sizeof(buf));

            /* Enviar payload */
            const char *payload = PAYLOADS[payload_idx % NUM_PAYLOADS];
            write(sock, payload, strlen(payload));
            payload_idx++;

            /* Intentar leer respuesta de error */
            read(sock, buf, sizeof(buf));

            conexiones++;
        } else {
            errores++;
        }

        close(sock);

        /* Esperar entre conexiones (50ms) para no saturar el CPU */
        usleep(50000);
    }

    printf("[Worker %d] Finalizado: %d conexiones, %d errores\n",
           id_worker, conexiones, errores);
}

/* =================================================================
 *              MODO 2: INTENTOS SSH FALLIDOS
 * ================================================================ */

/*
 * Worker que intenta logins SSH con credenciales invalidas.
 */
static void worker_ssh(int id_worker) {
    int intentos = 0;

    printf("[Worker %d] Iniciando intentos SSH fallidos\n", id_worker);

    while (!g_detener) {
        pid_t pid = fork();

        if (pid == -1) {
            perror("fork (ssh)");
            usleep(500000);
            continue;
        }

        if (pid == 0) {
            /* Proceso hijo: ejecutar ssh con credenciales invalidas */

            /* Redirigir toda la salida a /dev/null */
            int nulo = open("/dev/null", O_WRONLY);
            if (nulo >= 0) {
                dup2(nulo, STDOUT_FILENO);
                dup2(nulo, STDERR_FILENO);
                close(nulo);
            }

            /* exec() del comando ssh con opciones que hacen que
             * falle rapidamente y no pregunte nada con interaccion */
            execlp("ssh", "ssh",
                   "-o", "BatchMode=yes",
                   "-o", "StrictHostKeyChecking=no",
                   "-o", "ConnectTimeout=2",
                   "-o", "NumberOfPasswordPrompts=0",
                   "-o", "PreferredAuthentications=password",
                   "-l", "test_anomaly_user",
                   "127.0.0.1",
                   "exit",
                   NULL);

            /* Si exec falla */
            _exit(EXIT_FAILURE);
        }

        /* Padre: esperar al hijo ssh */
        waitpid(pid, NULL, 0);
        intentos++;

        /* Esperar entre intentos (200ms) */
        usleep(200000);
    }

    printf("[Worker %d] Finalizado: %d intentos SSH\n",
           id_worker, intentos);
}

/* ================================================================
 *                         MAIN PRINCIPAL
 * ================================================================ */
int main(int argc, char *argv[]) {
    int puerto = 22;
    int n_workers = 3;
    int duracion = 30;
    int modo = 1;
    int i;

    /* Parsear argumentos */
    int opt;
    while ((opt = getopt(argc, argv, "p:w:d:m:h")) != -1) {
        switch (opt) {
        case 'p':
            puerto = atoi(optarg);
            if (puerto < 1 || puerto > 65535) {
                fprintf(stderr, "Error: puerto invalido\n");
                return EXIT_FAILURE;
            }
            break;
        case 'w':
            n_workers = atoi(optarg);
            if (n_workers < 1) n_workers = 1;
            if (n_workers > MAX_WORKERS) n_workers = MAX_WORKERS;
            break;
        case 'd':
            duracion = atoi(optarg);
            if (duracion < 1) {
                fprintf(stderr, "Error: duracion debe ser >= 1\n");
                return EXIT_FAILURE;
            }
            break;
        case 'm':
            modo = atoi(optarg);
            if (modo < 1 || modo > 2) {
                fprintf(stderr, "Error: modo debe ser 1 o 2\n");
                return EXIT_FAILURE;
            }
            break;
        case 'h':
            mostrar_uso(argv[0]);
            return EXIT_SUCCESS;
        default:
            mostrar_uso(argv[0]);
            return EXIT_FAILURE;
        }
    }

    /* Mostrar configuracion */
    printf("=== Generador de Anomalias para SIEMLite ===\n\n");
    printf("Modo:      %s\n",
           modo == 1 ? "TCP flood (conexiones malformadas)" :
                       "Intentos SSH fallidos");
    printf("Puerto:    %d\n", puerto);
    printf("Workers:   %d\n", n_workers);
    printf("Duracion:  %d segundos\n\n", duracion);

    /* Configurar senales */
    signal(SIGINT, manejador_senal);
    signal(SIGTERM, manejador_senal);

    /* Crear procesos worker con fork() */
    pid_t pids[MAX_WORKERS];

    for (i = 0; i < n_workers; i++) {
        pid_t pid = fork();

        if (pid == -1) {
            perror("fork (worker)");
            /* Matar los workers que ya creamos */
            int j;
            for (j = 0; j < i; j++) {
                kill(pids[j], SIGTERM);
                waitpid(pids[j], NULL, 0);
            }
            return EXIT_FAILURE;
        }

        if (pid == 0) {
            /* Proceso worker */
            signal(SIGTERM, manejador_senal);
            signal(SIGINT, manejador_senal);

            /* Configurar alarma individual para el worker */
            signal(SIGALRM, manejador_senal);
            alarm(duracion);

            /* Ejecutar el modo seleccionado */
            if (modo == 1) {
                worker_tcp("127.0.0.1", puerto, i);
            } else {
                worker_ssh(i);
            }

            _exit(EXIT_SUCCESS);
        }

        pids[i] = pid;
        printf("Worker %d creado (PID: %d)\n", i, pid);
    }

    /* Proceso padre: esperar que termine la duracion */
    printf("\nEjecutando por %d segundos...\n", duracion);
    printf("(Presione Ctrl+C para detener antes)\n\n");

    /* Dormir por la duracion especificada */
    int restante = duracion;
    while (restante > 0 && !g_detener) {
        restante = sleep(restante);
    }

    /* Tiempo terminado: detener todos los workers */
    printf("\nTiempo terminado. Deteniendo workers...\n");
    for (i = 0; i < n_workers; i++) {
        kill(pids[i], SIGTERM);
    }

    /* Esperar a que todos los workers terminen */
    for (i = 0; i < n_workers; i++) {
        waitpid(pids[i], NULL, 0);
    }

    printf("\n=== Estres finalizado ===\n");
    printf("Revise los logs con:\n");
    printf("  journalctl --since '%d seconds ago' --no-pager\n", duracion + 5);

    return EXIT_SUCCESS;
}

