#include <uapi/linux/ptrace.h>

/*
Total = ~276 bytes. Diseñado específicamente 
para no superar el límite estricto de 512 bytes del de eBPF
*/
struct event_t {
    u32 pid;
    char comm[16];
    char filename[128];
    char args[128];
};

BPF_PERF_OUTPUT(events);

TRACEPOINT_PROBE(syscalls, sys_enter_execve) {

    //Inicializa variable ya que programas en el kernel no dejan variables sin inicializar
    //(por seguridad)
    struct event_t event = {};

    event.pid = bpf_get_current_pid_tgid() >> 32; //32 bits más significativos -> PID limpio
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    //Leer ejecutable (128 bytes max)
    bpf_probe_read_user_str(&event.filename, sizeof(event.filename), args->filename);

    //Leer primer argumento si existe (128 bytes max)
    const char **argv = (const char **)args->argv;
    if (argv[1] != NULL) {
        bpf_probe_read_user_str(&event.args, sizeof(event.args), argv[1]);
    }

    events.perf_submit(args, &event, sizeof(event));
    return 0;
}