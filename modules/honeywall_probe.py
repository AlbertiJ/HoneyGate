#!/usr/bin/env python3
"""
Módulo de Laboratorio: Prueba de Contención Perimetral y Rate-Limiter HoneyGate.
Emite intencionalmente más de 10 peticiones salientes por minuto para verificar
que el Honeywall ejecuta el shutdown(SHUT_RDWR), cierra el socket y aísla la IP.
"""
import sys
import time
import socket

def test_honeywall_containment(target_host: str = "127.0.0.1", port: int = 2222):
    print(f"[PROBE] Conectando a {target_host}:{port} para probar límite de 10 req/min...")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((target_host, port))
        banner = s.recv(512)
        print(f"[PROBE] Conectado. Banner: {banner.decode('utf-8', errors='ignore').strip()}")

        for i in range(1, 16):
            print(f"[PROBE] Enviando petición interactiva #{i}...")
            s.send(f"COMMAND_PROBE_{i}\n".encode("utf-8"))
            try:
                resp = s.recv(512)
                if not resp:
                    print(f"[!] [CONTAINMENT-SUCCESS] El servidor cerró la conexión (EOF recibido en petición #{i}).")
                    break
                print(f"[PROBE] Respuesta recibida #{i}: {resp.strip()[:35]}")
            except (ConnectionResetError, BrokenPipeError, OSError) as e:
                print(f"[!] [CONTAINMENT-TRIGGERED] Socket cerrado forzosamente por Honeywall: {e}")
                break
            time.sleep(0.1)

    except Exception as e:
        print(f"[PROBE] Error de conexión: {e}")
    finally:
        s.close()
        print("[PROBE] Prueba de contención finalizada.")

if __name__ == "__main__":
    test_honeywall_containment()
