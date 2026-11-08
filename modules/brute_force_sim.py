#!/usr/bin/env python3
"""
Módulo de Laboratorio: Simulación de Fuerza Bruta SSH y Verificación de Alertas Inotify.
Emite intentos de autenticación que son procesados por el motor forense.
"""
import sys
import time
import socket

def run_simulation(target_host: str = "127.0.0.1", port: int = 2222):
    print(f"[LAB-BRUTEFORCE] Simulando ráfaga de intentos contra {target_host}:{port}...")
    users = ["root", "admin", "kali", "test"]
    passwords = ["123456", "password", "kali2024", "toor"]

    for user in users:
        for pwd in passwords:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1.0)
                s.connect((target_host, port))
                banner = s.recv(512)
                # Enviar credenciales
                s.send(f"USER {user} PASS {pwd}\r\n".encode("utf-8"))
                resp = s.recv(512)
                s.close()
                print(f"[*] Intento de acceso: {user}:{pwd} -> {resp.strip()[:40]}")
            except Exception as e:
                print(f"[-] Falla en intento {user}: {e}")
            time.sleep(0.15)

if __name__ == "__main__":
    run_simulation()
