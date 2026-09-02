#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <semaphore.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <errno.h>

/* ================================================================
 *                        CONSTANTES
 * ================================================================ */
#define MAX_SERVICIOS    10   /* Maximo de servicios a monitorear */
#define NUM_PRIORIDADES  8    /* Niveles syslog: emerg(0) a debug(7) */
#define MAX_NOMBRE       64   /* Largo maximo del nombre de servicio */
#define MAX_BUFFER       4096 /* Buffer de lectura del pipe */
#define SEM_NOMBRE       "/siemlite_sem"   /* Nombre del semaforo */
#define SHM_LLAVE        0x5349454D        /* Llave para shmget */

/* Nombres de los niveles de prioridad (RFC 5424) */
static const char *NOM_PRIOR[NUM_PRIORIDADES] = {
    "emerg", "alert", "crit", "err",
    "warning", "notice", "info", "debug"
};

/* Colores ANSI para la terminal */
#define C_RESET  "\033[0m"
#define C_ROJO   "\033[1;31m"
#define C_VERDE  "\033[1;32m"
#define C_AMARI  "\033[1;33m"
#define C_AZUL   "\033[1;34m"
#define C_CYAN   "\033[1;36m"
#define C_BLANC  "\033[1;37m"
#define C_GRIS   "\033[0;90m"
#define LIMPIAR  "\033[2J\033[H"

/* ================================================================
 *                  ESTRUCTURAS DE DATOS
 * ================================================================ */

/* Informacion de un servicio que se esta monitoreando */
typedef struct {
    char nombre[MAX_NOMBRE];           /* Ej: "sshd", "NetworkManager" */
    int contadores[NUM_PRIORIDADES];   /* Conteo de msgs por prioridad */
    int total;                          /* Suma de todos los contadores */
    time_t ultima_act;                  /* Hora de la ultima lectura */
    pid_t pid_hijo;                     /* PID del proceso hijo asignado */
} InfoServicio;

/* Estructura principal que vive en la memoria compartida.
 * Es accedida tanto por el padre (lectura) como por los hijos (escritura).
 * El acceso se protege con un semaforo. */
typedef struct {
    int num_servicios;
    int intervalo;                     /* Tiempo entre actualizaciones (seg) */
    int threshold;                     /* Umbral para disparar alertas */
    int ejecutando;                    /* Flag: 1=activo, 0=terminar */
    InfoServicio servicios[MAX_SERVICIOS];
    int alerta_enviada[MAX_SERVICIOS]; /* Evitar enviar la misma alerta 2 veces */
} DatosCompartidos;

/* ================================================================
 *                    VARIABLES GLOBALES
 * ================================================================ */
static int g_shm_id = -1;              /* ID del segmento de shm */
static DatosCompartidos *g_shm = NULL;  /* Puntero a la memoria compartida */
static sem_t *g_sem = NULL;             /* Semaforo para seccion critica */
static pid_t g_pids[MAX_SERVICIOS];     /* PIDs de los procesos hijos */
static int g_num_hijos = 0;
static volatile sig_atomic_t g_terminar = 0; /* Flag de terminacion */

/* Nombres de servicios (punteros a argv) */
static char *g_nombres_svc[MAX_SERVICIOS];

/* ================================================================
 *                  FUNCIONES AUXILIARES
 * ================================================================ */

/* Imprime no olvidar quitar no esta sirviendo TODO*/
static void mostrar_uso(const char *prog) {
    fprintf(stderr,
        "Uso: %s -s <servicio> -s <servicio> [-t <seg>] [-u <umbral>]\n\n"
        "Parametros:\n"
        "  -s <servicio>   Servicio a monitorear (minimo 2, max %d)\n"
        "  -t <segundos>   Intervalo de actualizacion (default: 10)\n"
        "  -u <umbral>     Umbral para alertas (default: 5)\n"
        "  -h              Mostrar esta ayuda\n\n"
        "Ejemplo:\n"
        "  %s -s sshd -s NetworkManager -t 10 -u 5\n\n"
        "Variables de entorno para WhatsApp (Twilio):\n"
        "  TWILIO_SID          Account SID\n"
        "  TWILIO_AUTH_TOKEN   Auth Token\n"
        "  TWILIO_FROM         Numero origen (whatsapp:+XXXX)\n"
        "  TWILIO_TO           Numero destino (whatsapp:+XXXX)\n",
        prog, MAX_SERVICIOS, prog);
}

/* Manejador de senales. Se llama cuando llega SIGINT o SIGTERM.
 * Solo cambia un flag; el loop principal se encarga de terminar. */
static void manejar_senal(int sig) {
    (void)sig; /* Evitar warning de parametro no usado */
    g_terminar = 1;
    /* Escribir directamente en shm (escritura atomica de int) */
    if (g_shm != NULL) {
        g_shm->ejecutando = 0;
    }
}

/* Retorna el codigo de color ANSI para un nivel de prioridad */
static const char *color_de_prioridad(int p) {
    if (p <= 3) return C_ROJO;   /* emerg, alert, crit, err */
    if (p == 4) return C_AMARI;  /* warning */
    if (p <= 6) return C_VERDE;  /* notice, info */
    return C_AZUL;                /* debug */
}

/* ================================================================
 *           MEMORIA COMPARTIDA Y SEMAFOROS
 * ================================================================ */

/*
 * Crea el segmento de memoria compartida y el semaforo: POSIX.
 * Si existe un segmento anterior (de una ejecucion previa que crasheo),
 * lo elimina antes de crear uno nuevo.
 * Retorna 0 si todo salio bien, -1 si es con error.
 */
static int crear_recursos_ipc(int n_servicios) {
    size_t tam = sizeof(DatosCompartidos);

    /* Limpiar segmento anterior si existe */
    int id_viejo = shmget(SHM_LLAVE, tam, 0666);
    if (id_viejo != -1) {
        shmctl(id_viejo, IPC_RMID, NULL);
    }

    /* Crear nuevo segmento de memoria compartida */
    g_shm_id = shmget(SHM_LLAVE, tam, IPC_CREAT | IPC_EXCL | 0666);
    if (g_shm_id == -1) {
        perror("shmget: no se pudo crear memoria compartida");
        return -1;
    }

    /* Adjuntar la memoria compartida al espacio de este proceso */
    g_shm = (DatosCompartidos *)shmat(g_shm_id, NULL, 0);
    if (g_shm == (void *)-1) {
        perror("shmat: no se pudo adjuntar memoria compartida");
        g_shm = NULL;
        return -1;
    }

    /* Inicializar toda la estructura a ceros */
    memset(g_shm, 0, tam);
    g_shm->num_servicios = n_servicios;
    g_shm->ejecutando = 1;

    /* Crear semaforo nombrado (eliminar el anterior si existe) */
    sem_unlink(SEM_NOMBRE);
    g_sem = sem_open(SEM_NOMBRE, O_CREAT | O_EXCL, 0666, 1);
    if (g_sem == SEM_FAILED) {
        perror("sem_open: no se pudo crear semaforo");
        g_sem = NULL;
        return -1;
    }

    return 0;
}

/*
 * Libera todos los recursos: envia SIGTERM a los hijos, espera que
 * terminen, desmonta la memoria compartida y elimina el semaforo.
 * Se llama al terminar el programa (por Ctrl+C o fin normal).
 */
static void limpiar_recursos(void) {
    int i;

    /* Paso 1: enviar SIGTERM a todos los procesos hijos */
    for (i = 0; i < g_num_hijos; i++) {
        if (g_pids[i] > 0) {
            kill(g_pids[i], SIGTERM);
        }
    }

    /* Paso 2: esperar a que todos los hijos terminen */
    for (i = 0; i < g_num_hijos; i++) {
        if (g_pids[i] > 0) {
            waitpid(g_pids[i], NULL, 0);
            g_pids[i] = 0;
        }
    }

    /* Paso 3: desmontar memoria compartida de este proceso */
    if (g_shm != NULL) {
        shmdt(g_shm);
        g_shm = NULL;
    }

    /* Paso 4: eliminar el segmento de memoria compartida del sistema */
    if (g_shm_id != -1) {
        shmctl(g_shm_id, IPC_RMID, NULL);
        g_shm_id = -1;
    }

    /* Paso 5: cerrar y eliminar el semaforo */
    if (g_sem != NULL) {
        sem_close(g_sem);
        sem_unlink(SEM_NOMBRE);
        g_sem = NULL;
    }
}

/* ================================================================
 *         LECTURA DE LOGS CON journalctl (fork + exec + pipe)
 * ================================================================ */

/*
 * Extrae el nivel de prioridad de una linea JSON de journalctl.
 * journalctl -o json produce lineas como:
 *   {"PRIORITY":"3","MESSAGE":"error message",...}
 *
 * Buscamos el campo "PRIORITY" y extraemos el digito (0-7).
 * No usamos libreria JSON; parseamos el string manualmente.
 */
static int extraer_prioridad(const char *linea) {
    const char *ptr;

    /* Formato compacto: "PRIORITY":"X" */
    ptr = strstr(linea, "\"PRIORITY\":\"");
    if (ptr != NULL) {
        ptr += 12; /* Avanzar despues de "PRIORITY":" */
        if (*ptr >= '0' && *ptr <= '7') {
            return *ptr - '0';
        }
    }

    /* Formato con espacios: "PRIORITY" : "X" */
    ptr = strstr(linea, "\"PRIORITY\" : \"");
    if (ptr != NULL) {
        ptr += 14;
        if (*ptr >= '0' && *ptr <= '7') {
            return *ptr - '0';
        }
    }

    return -1; /* No se encontro el campo */
}

/*
 * Ejecuta journalctl para un servicio dado y cuenta los mensajes
 * clasificandolos por nivel de prioridad.
 *
 * Procedimiento:
 *   1. Crear un pipe para comunicacion
 *   2. fork() para crear un proceso hijo (nieto del padre original)
 *   3. El nieto redirige stdout al pipe y hace exec() de journalctl
 *   4. El hijo lee del pipe linea por linea
 *   5. Parsea el campo PRIORITY de cada linea JSON
 *   6. Cuenta los mensajes por prioridad
 *   7. Actualiza la memoria compartida (seccion critica con semaforo)
 *   8. waitpid() al nieto para evitar procesos zombis
 */
static void consultar_logs(int idx, const char *servicio, int intervalo) {
    int fd_pipe[2];

    /* Crear pipe para leer la salida de journalctl */
    if (pipe(fd_pipe) == -1) {
        perror("pipe");
        return;
    }

    /* fork() para crear el proceso que ejecutara journalctl */
    pid_t pid = fork();

    if (pid == -1) {
        perror("fork (journalctl)");
        close(fd_pipe[0]);
        close(fd_pipe[1]);
        return;
    }

    if (pid == 0) {
        /* ============================================
         * PROCESO NIETO: ejecutar journalctl con exec
         * ============================================ */

        /* Cerrar el extremo de lectura (no lo necesitamos) */
        close(fd_pipe[0]);

        /* Redirigir stdout al extremo de escritura del pipe */
        dup2(fd_pipe[1], STDOUT_FILENO);

        /* Enviar stderr a /dev/null para no contaminar la salida */
        int nulo = open("/dev/null", O_WRONLY);
        if (nulo >= 0) {
            dup2(nulo, STDERR_FILENO);
            close(nulo);
        }
        close(fd_pipe[1]);

        /* Construir el argumento --since para filtrar por tiempo */
        char desde[64];
        snprintf(desde, sizeof(desde), "%d seconds ago", intervalo);

        /*
         * Llamada al sistema exec: reemplaza este proceso por journalctl.
         * Parametros:
         *   -u <servicio>   : filtrar por unidad de systemd
         *   --since         : solo mensajes recientes
         *   --no-pager      : no paginar la salida
         *   -o json         : formato JSON (para parsear PRIORITY)
         */
        execlp("journalctl", "journalctl",
               "-u", servicio,
               "--since", desde,
               "--no-pager",
               "-o", "json",
               NULL);

        /* Si llegamos aqui, exec() fallo */
        perror("execlp journalctl");
        _exit(EXIT_FAILURE);
    }

    /* ============================================
     * PROCESO HIJO: leer salida del pipe y contar
     * ============================================ */

    /* Cerrar el extremo de escritura (no escribimos al pipe) */
    close(fd_pipe[1]);

    /* Contadores temporales (locales, antes de escribir en shm) */
    int conteo[NUM_PRIORIDADES];
    int total = 0;
    int p;
    memset(conteo, 0, sizeof(conteo));

    /* Leer cada linea de la salida de journalctl */
    FILE *fp = fdopen(fd_pipe[0], "r");
    if (fp != NULL) {
        char linea[MAX_BUFFER];
        while (fgets(linea, sizeof(linea), fp) != NULL) {
            p = extraer_prioridad(linea);
            if (p >= 0 && p < NUM_PRIORIDADES) {
                conteo[p]++;
                total++;
            }
        }
        fclose(fp); /* Tambien cierra fd_pipe[0] */
    } else {
        close(fd_pipe[0]);
    }

    /* Esperar al proceso nieto para evitar zombis */
    waitpid(pid, NULL, 0);

    /* ============================================
     * SECCION CRITICA: actualizar memoria compartida
     * Usamos sem_timedwait() para evitar deadlock:
     * si no podemos adquirir el semaforo en 3 segundos,
     * abortamos la escritura en vez de quedarnos bloqueados.
     * ============================================ */
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += 3; /* Timeout de 3 segundos */

    if (sem_timedwait(g_sem, &ts) == 0) {
        /* Semaforo adquirido: acumular contadores */
        for (p = 0; p < NUM_PRIORIDADES; p++) {
            g_shm->servicios[idx].contadores[p] += conteo[p];
        }
        g_shm->servicios[idx].total += total;
        
        /* Solo actualizar la hora si hubo mensajes nuevos */
        if (total > 0) {
            g_shm->servicios[idx].ultima_act = time(NULL);
        }

        /* Liberar semaforo */
        sem_post(g_sem);
    } else if (errno == ETIMEDOUT) {
        /* No pudimos adquirir el semaforo a tiempo.
         * Esto puede indicar un deadlock potencial.
         * Saltamos esta escritura y lo intentamos en el proximo ciclo. */
        fprintf(stderr, "[WARN] Timeout de semaforo en hijo %d\n", idx);
    }
}

/* ================================================================
 *               ALERTAS Y NOTIFICACIONES
 * ================================================================ */

/*
 * Envia una alerta via WhatsApp usando la API de Twilio.
 * Se ejecuta haciendo fork() + exec() de curl.
 *
 * Usamos la tecnica del "doble fork" para evitar zombis:
 *   1. Primer fork: crea un hijo intermedio
 *   2. El hijo intermedio hace otro fork y sale inmediatamente
 *   3. El nieto (que ejecuta curl) queda huerfano
 *   4. init/systemd recoge al nieto cuando termine
 *   5. El padre recoge al hijo intermedio con waitpid (regresa rapido)
 *
 * Esto evita que el proceso padre se bloquee esperando a curl.
 */
static void enviar_whatsapp(const char *servicio, const char *prioridad,
                             int conteo, int umbral) {
    /* Leer credenciales de variables de entorno */
    const char *sid   = getenv("TWILIO_SID");
    const char *token = getenv("TWILIO_AUTH_TOKEN");
    const char *from  = getenv("TWILIO_FROM");
    const char *to    = getenv("TWILIO_TO");

    /* Si falta alguna credencial, no hacer nada */
    if (!sid || !token || !from || !to) {
        return;
    }

    /* Primer fork (hijo intermedio) */
    pid_t pid1 = fork();
    if (pid1 == -1) {
        perror("fork (whatsapp)");
        return;
    }

    if (pid1 == 0) {
        /* Hijo intermedio: fork de nuevo y salir */
        pid_t pid2 = fork();

        if (pid2 == 0) {
            /* Nieto: ejecutar curl para enviar el mensaje */

            /* Redirigir toda la salida a /dev/null */
            int nulo = open("/dev/null", O_WRONLY);
            if (nulo >= 0) {
                dup2(nulo, STDOUT_FILENO);
                dup2(nulo, STDERR_FILENO);
                close(nulo);
            }

            /* Construir argumentos para curl */
            char url[256];
            snprintf(url, sizeof(url),
                "https://api.twilio.com/2010-04-01/Accounts/%s/Messages.json",
                sid);

            char body[512];
            snprintf(body, sizeof(body),
                "Body=ALERTA SIEMLite: Servicio '%s' tiene %d mensajes de "
                "prioridad '%s' (umbral: %d)",
                servicio, conteo, prioridad, umbral);

            char arg_from[128], arg_to[128], creds[256];
            snprintf(arg_from, sizeof(arg_from), "From=%s", from);
            snprintf(arg_to, sizeof(arg_to), "To=%s", to);
            snprintf(creds, sizeof(creds), "%s:%s", sid, token);

            /* exec() de curl */
            execlp("curl", "curl",
                   "-s", "-X", "POST", url,
                   "--data-urlencode", body,
                   "-d", arg_from,
                   "-d", arg_to,
                   "-u", creds,
                   NULL);

            _exit(EXIT_FAILURE);
        }

        /* Hijo intermedio: salir inmediatamente */
        _exit(0);
    }

    /* Padre: recoger al hijo intermedio (retorna inmediatamente) */
    waitpid(pid1, NULL, 0);
}

/*
 * Revisa los contadores de cada servicio contra el umbral.
 * Si algun servicio tiene prioridades criticas (emerg, alert, crit, err)
 * que superan el umbral, muestra la alerta y envia WhatsApp si corresponde.
 *
 * Recibe una copia local de los datos (no accede a shm para leer),
 * pero si accede a shm para actualizar las flags de alerta_enviada.
 */
static void revisar_alertas(DatosCompartidos *copia) {
    int i, p;
    int twilio_ok = (getenv("TWILIO_SID") != NULL);

    for (i = 0; i < copia->num_servicios; i++) {
        int supera_umbral = 0;

        /* Revisar solo prioridades criticas (0=emerg hasta 3=err) */
        for (p = 0; p <= 3; p++) {
            if (copia->servicios[i].contadores[p] >= copia->threshold) {

                /* Mostrar alerta en el dashboard */
                printf("  %s!! %s: %s(%d) supera umbral(%d)",
                       C_ROJO,
                       copia->servicios[i].nombre,
                       NOM_PRIOR[p],
                       copia->servicios[i].contadores[p],
                       copia->threshold);

                /* Enviar WhatsApp solo la primera vez */
                if (!copia->alerta_enviada[i]) {
                    if (twilio_ok) {
                        enviar_whatsapp(
                            copia->servicios[i].nombre,
                            NOM_PRIOR[p],
                            copia->servicios[i].contadores[p],
                            copia->threshold);
                        printf(" -> WhatsApp enviado");
                    }

                    /* Marcar como enviada en memoria compartida */
                    struct timespec ts;
                    clock_gettime(CLOCK_REALTIME, &ts);
                    ts.tv_sec += 1;
                    if (sem_timedwait(g_sem, &ts) == 0) {
                        g_shm->alerta_enviada[i] = 1;
                        sem_post(g_sem);
                    }
                } else {
                    printf(" (ya notificado)");
                }

                printf("%s\n", C_RESET);
                supera_umbral = 1;
            }
        }

        /* Si ya no supera el umbral, resetear la flag para
         * poder enviar otra alerta en el futuro */
        if (!supera_umbral && copia->alerta_enviada[i]) {
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            ts.tv_sec += 1;
            if (sem_timedwait(g_sem, &ts) == 0) {
                g_shm->alerta_enviada[i] = 0;
                sem_post(g_sem);
            }
        }
    }
}

/* ================================================================
 *                   DASHBOARD
 * ================================================================ */

/*
 * Dibuja el dashboard completo en la terminal usando codigos ANSI.
 * Muestra los contadores de cada servicio clasificados por prioridad,
 * con colores para facilitar la lectura.
 *
 * Recibe un puntero a una COPIA LOCAL de los datos (no accede a shm).
 * Esto es para no mantener el semaforo bloqueado mientras dibujamos.
 */
static void dibujar_dashboard(DatosCompartidos *d) {
    int i, p;

    /* Limpiar pantalla y mover cursor al inicio */
    printf(LIMPIAR);

    /* Obtener la hora actual formateada */
    char hora[32];
    time_t ahora = time(NULL);
    struct tm *tm_info = localtime(&ahora);
    strftime(hora, sizeof(hora), "%Y-%m-%d %H:%M:%S", tm_info);

    /* ---- Encabezado ---- */
    printf("\n");
    printf(" %s", C_CYAN);
    printf("================================================================\n");
    printf("%s", C_RESET);
    printf("  %sSIEMLite - Monitor de Logs en Tiempo Real%s\n",
           C_BLANC, C_RESET);
    printf("  %sActualizacion: %s  |  Intervalo: %ds  |  Umbral: %d%s\n",
           C_GRIS, hora, d->intervalo, d->threshold, C_RESET);

    /* Mostrar si Twilio esta configurado */
    if (getenv("TWILIO_SID") != NULL) {
        printf("  %sNotificaciones: Twilio configurado%s\n", C_GRIS, C_RESET);
    } else {
        printf("  %sNotificaciones: Solo local (sin credenciales Twilio)%s\n",
               C_GRIS, C_RESET);
    }

    printf(" %s", C_CYAN);
    printf("================================================================\n");
    printf("%s\n", C_RESET);

    /* ---- Datos de cada servicio ---- */
    for (i = 0; i < d->num_servicios; i++) {
        InfoServicio *s = &d->servicios[i];

        /* Nombre del servicio y PID de su proceso hijo */
        printf("  %s>>%s Servicio: %s%-20s%s  [PID hijo: %d]\n",
               C_CYAN, C_RESET, C_BLANC, s->nombre, C_RESET, s->pid_hijo);

        /* Fila de nombres de prioridad (con colores) */
        printf("    ");
        for (p = 0; p < NUM_PRIORIDADES; p++) {
            printf("%s%-9s%s", color_de_prioridad(p), NOM_PRIOR[p], C_RESET);
        }
        printf("\n");

        /* Fila de valores (contadores) */
        printf("    ");
        for (p = 0; p < NUM_PRIORIDADES; p++) {
            if (s->contadores[p] > 0) {
                /* Resaltar valores mayores a cero con su color */
                printf("%s%-9d%s", color_de_prioridad(p), s->contadores[p],
                       C_RESET);
            } else {
                printf("%s%-9d%s", C_GRIS, 0, C_RESET);
            }
        }
        printf("\n");

        /* Total de mensajes y hora de ultima actualizacion */
        printf("    %sTotal: %d mensajes%s", C_BLANC, s->total, C_RESET);
        if (s->ultima_act > 0) {
            char h[16];
            struct tm *tm_svc = localtime(&s->ultima_act);
            strftime(h, sizeof(h), "%H:%M:%S", tm_svc);
            printf("  %s(leido: %s)%s", C_GRIS, h, C_RESET);
        }
        printf("\n\n");
    }

    /* ---- Seccion de alertas ---- */
    printf(" %s", C_CYAN);
    printf("================================================================\n");
    printf("%s", C_RESET);
    printf("  %sALERTAS:%s\n", C_AMARI, C_RESET);

    /* Revisar si hay alguna alerta activa */
    int hay_alertas = 0;
    for (i = 0; i < d->num_servicios && !hay_alertas; i++) {
        for (p = 0; p <= 3; p++) {
            if (d->servicios[i].contadores[p] >= d->threshold) {
                hay_alertas = 1;
                break;
            }
        }
    }

    if (hay_alertas) {
        /* Mostrar las alertas y enviar notificaciones si aplica */
        revisar_alertas(d);
    } else {
        printf("  %s[OK] Sin alertas activas%s\n", C_VERDE, C_RESET);
    }

    /* ---- Pie del dashboard ---- */
    printf(" %s", C_CYAN);
    printf("================================================================\n");
    printf("%s", C_RESET);
    printf("  %sPresione Ctrl+C para detener el monitoreo%s\n\n", C_GRIS, C_RESET);

    /* Forzar que se muestre todo en pantalla */
    fflush(stdout);
}

/* ================================================================
 *              PROCESO HIJO DE MONITOREO
 * ================================================================ */

/*
 * Funcion principal que ejecuta cada proceso hijo.
 * Cada hijo es responsable de monitorear UN servicio.
 * Periodicamente ejecuta journalctl (fork + exec) y actualiza
 * los contadores en la memoria compartida.
 *
 * El hijo se detiene cuando:
 *   - Recibe SIGTERM del padre
 *   - El flag ejecutando en shm cambia a 0
 */
static void proceso_hijo(int idx, const char *servicio, int intervalo) {
    /* Configurar senales del hijo */
    signal(SIGTERM, manejar_senal);
    signal(SIGINT, SIG_DFL);  /* Dejar que SIGINT sea manejado por default */

    while (!g_terminar) {
        /* Verificar si el padre quiere que terminemos.
         * Leemos el flag ejecutando de la memoria compartida. */
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += 2;

        if (sem_timedwait(g_sem, &ts) == 0) {
            if (!g_shm->ejecutando) {
                sem_post(g_sem);
                break; /* El padre quiere que terminemos */
            }
            sem_post(g_sem);
        }

        /* Consultar journalctl (crea un nieto con fork+exec+pipe) */
        time_t inicio = time(NULL);
        consultar_logs(idx, servicio, intervalo);
        time_t transcurrido = time(NULL) - inicio;

        /* Dormir el tiempo restante del intervalo.
         * Restamos el tiempo que tardo la consulta para mantener
         * el ritmo de actualizacion lo mas estable posible. */
        int dormir = intervalo - (int)transcurrido;
        if (dormir > 0 && !g_terminar) {
            sleep(dormir);
        }
    }

    /* Limpiar recursos del hijo.
     * IMPORTANTE: el hijo solo se desconecta de la shm y cierra
     * el semaforo. NO elimina estos recursos (eso lo hace el padre). */
    if (g_shm != NULL) {
        shmdt(g_shm);
        g_shm = NULL;
    }
    if (g_sem != NULL) {
        sem_close(g_sem);
        g_sem = NULL;
    }
}

/* ================================================================
 *                        MAIN
 * ================================================================ */
int main(int argc, char *argv[]) {
    int n_servicios = 0;
    int intervalo = 10;   /* Valor por defecto: 10 segundos */
    int threshold = 5;    /* Valor por defecto: umbral de 5 */
    int i;

    /* ---- Parsear argumentos de linea de comandos ---- */
    int opt;
    while ((opt = getopt(argc, argv, "s:t:u:h")) != -1) {
        switch (opt) {
        case 's':
            /* Agregar servicio a la lista */
            if (n_servicios >= MAX_SERVICIOS) {
                fprintf(stderr, "Error: maximo %d servicios permitidos\n",
                        MAX_SERVICIOS);
                return EXIT_FAILURE;
            }
            g_nombres_svc[n_servicios] = optarg;
            n_servicios++;
            break;

        case 't':
            /* Intervalo de actualizacion */
            intervalo = atoi(optarg);
            if (intervalo < 1) {
                fprintf(stderr, "Error: el intervalo debe ser >= 1 segundo\n");
                return EXIT_FAILURE;
            }
            break;

        case 'u':
            /* Umbral de alertas */
            threshold = atoi(optarg);
            if (threshold < 1) {
                fprintf(stderr, "Error: el umbral debe ser >= 1\n");
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

    /* Validar que se especificaron al menos 2 servicios */
    if (n_servicios < 2) {
        fprintf(stderr,
                "Error: debe especificar al menos 2 servicios con -s\n\n");
        mostrar_uso(argv[0]);
        return EXIT_FAILURE;
    }

    /* ---- Mostrar configuracion ---- */
    printf("%sSIEMLite v1.0 - Iniciando...%s\n", C_CYAN, C_RESET);
    printf("Servicios a monitorear: ");
    for (i = 0; i < n_servicios; i++) {
        printf("%s%s", g_nombres_svc[i],
               (i < n_servicios - 1) ? ", " : "\n");
    }
    printf("Intervalo: %d seg  |  Umbral de alertas: %d\n\n", intervalo,
           threshold);

    /* ---- Crear memoria compartida y semaforo ---- */
    if (crear_recursos_ipc(n_servicios) != 0) {
        fprintf(stderr, "Error fatal: no se pudieron crear recursos IPC\n");
        return EXIT_FAILURE;
    }

    /* Inicializar datos en la memoria compartida */
    g_shm->intervalo = intervalo;
    g_shm->threshold = threshold;
    for (i = 0; i < n_servicios; i++) {
        strncpy(g_shm->servicios[i].nombre, g_nombres_svc[i],
                MAX_NOMBRE - 1);
        g_shm->servicios[i].nombre[MAX_NOMBRE - 1] = '\0';
    }

    /* ---- Configurar manejo de senales ---- */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = manejar_senal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    /* Ignorar SIGPIPE (puede ocurrir con pipes rotos) */
    signal(SIGPIPE, SIG_IGN);

    /* ---- Crear un proceso hijo por cada servicio ---- */
    for (i = 0; i < n_servicios; i++) {
        pid_t pid = fork();

        if (pid == -1) {
            perror("fork (hijo monitor)");
            limpiar_recursos();
            return EXIT_FAILURE;
        }

        if (pid == 0) {
            /* ====== PROCESO HIJO ======
             * Registrar su propio PID en la memoria compartida
             * y comenzar el loop de monitoreo. */
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            ts.tv_sec += 2;
            if (sem_timedwait(g_sem, &ts) == 0) {
                g_shm->servicios[i].pid_hijo = getpid();
                sem_post(g_sem);
            }

            /* Iniciar monitoreo (esta funcion no retorna hasta
             * que se reciba senal de terminacion) */
            proceso_hijo(i, g_nombres_svc[i], intervalo);
            _exit(EXIT_SUCCESS);
        }

        /* ====== PROCESO PADRE ======
         * Guardar el PID del hijo para poder manejarlo despues */
        g_pids[i] = pid;
        g_num_hijos++;
        printf("  Hijo creado para '%s' (PID: %d)\n", g_nombres_svc[i], pid);
    }

    printf("\nEsperando primera recoleccion de datos (%d seg)...\n",
           intervalo);
    /* Dar tiempo a los hijos para la primera lectura de journalctl */
    sleep(intervalo + 1);

    /* ---- Loop principal del dashboard ---- */
    while (!g_terminar) {
        DatosCompartidos copia;

        /* Seccion critica: copiar datos de la memoria compartida
         * a una variable local. Asi soltamos el semaforo rapido
         * y el dashboard se dibuja sin bloquear a los hijos. */
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += 2;

        if (sem_timedwait(g_sem, &ts) == 0) {
            memcpy(&copia, g_shm, sizeof(DatosCompartidos));
            sem_post(g_sem);
        } else {
            /* No pudimos adquirir el semaforo, reintentar */
            sleep(1);
            continue;
        }

        /* Dibujar el dashboard usando la copia local */
        dibujar_dashboard(&copia);

        /* Mantenimiento preventivo: verificar que los hijos sigan vivos.
         * Si un hijo murio inesperadamente, lo reiniciamos.
         * Esto es una forma de mantenimiento correctivo del sistema. */
        for (i = 0; i < g_num_hijos; i++) {
            int estado;
            pid_t resultado = waitpid(g_pids[i], &estado, WNOHANG);

            if (resultado > 0 && !g_terminar) {
                /* El hijo termino: reiniciarlo */
                printf("  %s[!] Hijo para '%s' termino. Reiniciando...%s\n",
                       C_AMARI, g_shm->servicios[i].nombre, C_RESET);

                pid_t nuevo = fork();
                if (nuevo == 0) {
                    /* Nuevo hijo: registrar PID y comenzar monitoreo */
                    struct timespec ts2;
                    clock_gettime(CLOCK_REALTIME, &ts2);
                    ts2.tv_sec += 2;
                    if (sem_timedwait(g_sem, &ts2) == 0) {
                        g_shm->servicios[i].pid_hijo = getpid();
                        sem_post(g_sem);
                    }
                    proceso_hijo(i, g_nombres_svc[i], intervalo);
                    _exit(EXIT_SUCCESS);
                } else if (nuevo > 0) {
                    g_pids[i] = nuevo;
                }
            }
        }

        /* Esperar antes del proximo ciclo de actualizacion */
        sleep(intervalo);
    }

    /* ---- Terminacion limpia ---- */
    printf("\n%sSIEMLite: Deteniendo monitoreo...%s\n", C_AMARI, C_RESET);
    limpiar_recursos();
    printf("%sRecursos liberados. Hasta luego.%s\n", C_VERDE, C_RESET);

    return EXIT_SUCCESS;
}
