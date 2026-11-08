#!/usr/bin/env python3
"""
Módulo de Laboratorio: Simulación de Escaneo de Puertos Sigiloso (SYN/Connect).
Genera sondeos secuenciales hacia el rango de puertos del Honeywall para evaluar detección.
"""
import sys
import time
import socket

def run_simulation(target_host: str = "127.0.0.1", ports = (2222, 8080, 8443, 33060)):
    print(f"[LAB-SCAN] Iniciando sondeo de puertos defensivos hacia {target_host}...")
    open_ports = []
    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        try:
            res = s.connect_ex((target_host, port))
            if res == 0:
                open_ports.append(port)
                banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
                print(f"[+] Puerto {port}/TCP ABIERTO - Banner: {banner}")
            s.close()
        except Exception as e:
            print(f"[-] Puerto {port}/TCP Error: {e}")
        time.sleep(0.1)
    print(f"[LAB-SCAN] Sondeo finalizado. Puertos activos: {open_ports}")

if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    run_simulation(host)
