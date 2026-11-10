#!/usr/bin/env bash
# ==============================================================================
# 🛡️ HoneyGate - Script de Rollback Seguro y Restauración de Checkpoint
# ==============================================================================
# Permite volver de forma inmediata a un estado funcional anterior ante cualquier
# anomalía, fallo de integración o prueba fallida.
#
# Uso:
#   ./rollback.sh                     (Restaura al tag v1.0.0-checkpoint por defecto)
#   ./rollback.sh <COMMIT_HASH_O_TAG> (Restaura al hash o tag especificado)
#   ./rollback.sh --hard              (Fuerza la restauración descartando cambios locales)
# ==============================================================================

set -e

TARGET="${1:-v1.0.0-claude-security}"

if [ "$1" == "--hard" ]; then
    TARGET="${2:-v1.0.0-claude-security}"
    FORCE_HARD=true
else
    FORCE_HARD=false
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

# 2. Respaldo de seguridad preventivo si hay modificaciones pendientes
if ! git diff-index --quiet HEAD -- 2>/dev/null; then
    STASH_NAME="backup_pre_rollback_$(date +%Y%m%d_%H%M%S)"
    echo "[!] Cambios pendientes detectados en el espacio de trabajo."
    echo "[+] Creando stash de seguridad: $STASH_NAME"
    git stash push -m "$STASH_NAME"
fi

# 3. Aplicar Rollback
if [ "$FORCE_HARD" = true ]; then
    echo "[+] Ejecutando git reset --hard $TARGET ..."
    git reset --hard "$TARGET"
else
    echo "[+] Comprobando existencia de tag/commit: $TARGET ..."
    if git rev-parse "$TARGET" >/dev/null 2>&1; then
        echo "[+] Restaurando archivos al estado de $TARGET..."
        git checkout "$TARGET" -- .
        echo "[+] Archivos sincronizados con éxito a: $TARGET"
    else
        echo "[-] Error: El identificador '$TARGET' no existe en el historial de Git."
        exit 1
    fi
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
