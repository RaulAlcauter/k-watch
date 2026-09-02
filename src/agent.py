import sys
import json
import argparse
from bcc import BPF
from rules import evaluate_event

def main():
    parser = argparse.ArgumentParser(description="k-watch: eBPF Linux EDR Agent")
    parser.add_argument(
        "--alerts-only",
        action="store_true",
        help="Mostrar únicamente alertas de riesgo MEDIUM, HIGH o CRITICAL"
    )
    args = parser.parse_args()

    # Cargar y leer el archivo C del Kernel
    try:
        with open("src/ebpf_probe.c", "r") as f:
            bpf_text = f.read()
    except FileNotFoundError:
        print("[!] Error: No se encuentra src/ebpf_probe.c. Ejecuta el agente desde la raiz del repositorio.")
        sys.exit(1)

    # Compilacion con eBPF
    b = BPF(text=bpf_text)

    def print_event(cpu, data, size):
        raw_event = b["events"].event(data)
        comm = raw_event.comm.decode('utf-8', 'replace')
        filename = raw_event.filename.decode('utf-8', 'replace')
        cmd_args = raw_event.args.decode('utf-8', 'replace')
        
        # Unimos la ruta y los argumentos para evaluar la linea de comandos completa
        full_command = f"{filename} {cmd_args}".strip()
        
        alert = evaluate_event(raw_event.pid, comm, full_command)

        if alert["risk_level"] in ["HIGH", "CRITICAL"]:
            print(f"\033[91m[{alert['risk_level']}]\033[0m {json.dumps(alert)}")
        elif alert["risk_level"] == "MEDIUM":
            print(f"\033[93m[{alert['risk_level']}]\033[0m {json.dumps(alert)}")
        elif not args.alerts_only:
            print(f"\033[94m[{alert['risk_level']}]\033[0m {json.dumps(alert)}")

    # Vincular al Perf Ring Buffer
    b["events"].open_perf_buffer(print_event)
    print("\033[92m[*] k-watch EDR Agent running...\033[0m Presiona Ctrl+C para salir.\n")

    while True:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            print("\n[*] Deteniendo agente k-watch...")
            sys.exit(0)

if __name__ == "__main__":
    main()