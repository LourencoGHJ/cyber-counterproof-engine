"""Operações nftables conservadoras: validar e consultar, nunca aplicar regras."""
from __future__ import annotations
import hashlib, json, shutil, subprocess
from datetime import datetime, timezone
from pathlib import Path

class NftablesError(RuntimeError):
    pass

def _nft():
    path = shutil.which("nft")
    if not path:
        raise NftablesError("Comando nft não encontrado. Instala o pacote nftables.")
    return path


def validate_rules_file(path, timeout=15):
    target = Path(path)

    if not target.is_file():
        raise NftablesError(f"Ficheiro não encontrado: {target}")

    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    command = [_nft(), "--check", "--file", str(target)]

    try:
        p = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise NftablesError(
            f"Validação excedeu {timeout} segundos."
        ) from exc

    stdout = p.stdout.strip()
    stderr = p.stderr.strip()

    permission_error = (
        "Operation not permitted" in stderr
        or "Permission denied" in stderr
        or "must be root" in stderr
    )

    syntax_error = any(
        marker in stderr.lower()
        for marker in (
            "syntax error",
            "unexpected token",
            "unexpected string",
            "unexpected newline",
            "could not parse",
        )
    )

    if p.returncode == 0:
        status = "PASS"
        valid = True
    elif permission_error:
        status = "ERROR"
        valid = None
    elif syntax_error:
        status = "FAIL"
        valid = False
    else:
        status = "ERROR"
        valid = None
    return {
        "operation": "validate_file",
        "status": status,
        "applied": False,
        "command": command,
        "file": str(target),
        "sha256": digest,
        "exit_code": p.returncode,
        "valid": valid,
        "stdout": stdout,
        "stderr": stderr,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "note": (
            "Foi usado nft --check --file; o ficheiro não foi aplicado."
        ),
    }



def inspect_live_ruleset(timeout=15):
    command = [_nft(), "list", "ruleset"]
    try:
        p = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired as exc:
        raise NftablesError(f"Consulta excedeu {timeout} segundos.") from exc
    if p.returncode:
        hint = " Tenta uma consulta com sudo se faltar permissão." if "Operation not permitted" in p.stderr else ""
        raise NftablesError(f"Consulta falhou ({p.returncode}): {p.stderr.strip()}{hint}")
    raw = p.stdout
    return {
        "operation": "inspect_live_ruleset", "read_only": True, "applied": False,
        "command": command, "sha256": hashlib.sha256(raw.encode()).hexdigest(),
        "bytes": len(raw.encode()), "ruleset": raw,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "note": "Consulta apenas de leitura; nenhuma regra foi alterada."
    }

def write_json_report(data, output):
    target = Path(output)
    target.parent.mkdir(parents=True, exist_ok=True)

    target.write_text(
        json.dumps(data, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
