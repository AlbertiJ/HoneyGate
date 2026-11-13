#!/usr/bin/env bash
# ==============================================================================
# 🛡️ HoneyGate - Script de Rollback Seguro y Restauración de Checkpoint
# ==============================================================================
# Permite volver de forma inmediata a un commit o tag existente en Git ante
# cualquier anomalía, fallo de integración o prueba fallida.
#
# Uso obligatorio:
#   ./rollback.sh <COMMIT_HASH_O_TAG>
#   ./rollback.sh --hard <COMMIT_HASH_O_TAG>
# ==============================================================================

set -e

usage() {
    echo "Uso: $0 [--hard] <COMMIT_HASH_O_TAG>"
    echo ""
    echo "Argumento obligatorio:"
    echo "  <COMMIT_HASH_O_TAG>   Hash de commit o etiqueta Git destino (ej: git log --oneline -n 5)"
    echo "  --hard                (Opcional) Fuerza git reset --hard al objetivo"
    exit 1
}

FORCE_HARD=false
TARGET=""

if [ "$1" == "--hard" ]; then
    FORCE_HARD=true
    TARGET="${2:-}"
else
    TARGET="${1:-}"
fi

if [ -z "$TARGET" ]; then
    echo "[-] Error: Debe especificar un commit o tag destino."
    usage
fi

echo "======================================================================"
echo "🛡️ HONEYGATE: PROCEDIMIENTO DE ROLLBACK Y RESTAURACIÓN"
echo "======================================================================"
echo "Punto de restauración objetivo: $TARGET"
echo ""

# 1. Asegurar repositorio Git
if [ ! -d ".git" ]; then
    echo "[-] Error: No se detectó directorio .git en esta ubicación."
    echo "Ejecute este script desde la raíz del proyecto HoneyGate."
    exit 1
fi

# 2. Verificar existencia del commit/tag antes de modificar el árbol
if ! git rev-parse --verify "$TARGET^{commit}" >/dev/null 2>&1; then
    echo "[-] Error: El identificador '$TARGET' no existe en el historial de Git."
    exit 1
fi

# 3. Respaldo de seguridad preventivo si hay modificaciones pendientes
if ! git diff-index --quiet HEAD -- 2>/dev/null; then
    STASH_NAME="backup_pre_rollback_$(date +%Y%m%d_%H%M%S)"
    echo "[!] Cambios pendientes detectados en el espacio de trabajo."
    echo "[+] Creando stash de seguridad: $STASH_NAME"
    git stash push -m "$STASH_NAME"
fi

# 4. Aplicar Rollback
if [ "$FORCE_HARD" = true ]; then
    echo "[+] Ejecutando git reset --hard $TARGET ..."
    git reset --hard "$TARGET"
else
    echo "[+] Restaurando archivos al estado de $TARGET..."
    git checkout "$TARGET" -- .
    echo "[+] Archivos sincronizados con éxito a: $TARGET"
fi

echo ""
echo "======================================================================"
echo "[✓] ROLLBACK COMPLETADO CON ÉXITO A: $TARGET"
echo "======================================================================"
echo "Comandos útiles de Git para gestionar el rollback:"
echo " • Ver historial reciente:       git log --oneline -n 5"
echo " • Ver diferencias actuales:     git status"
echo " • Forzar rama main al objetivo: git reset --hard $TARGET"
echo " • Revertir el último commit:    git revert HEAD --no-edit"
echo "======================================================================"
