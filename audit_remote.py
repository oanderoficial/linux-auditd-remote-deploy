
#!/usr/bin/env python3
import paramiko
import argparse
import os
import time
import socket
import csv
import shlex
from dotenv import load_dotenv
from pathlib import Path

def load_credentials():
    credentials = []

    data = os.getenv("SSH_CREDENTIALS")

    if not data:
        raise RuntimeError(
            "Variável SSH_CREDENTIALS não encontrada no arquivo .env"
        )

    for item in data.split(","):
        try:
            user, password = item.split(":", 1)

            user = user.strip()
            password = password.strip()

            if not user or not password:
                raise ValueError

            credentials.append({
                "user": user,
                "password": password
            })

        except ValueError:
            raise RuntimeError(
                f"Credencial inválida no .env: {item}"
            )

    if not credentials:
        raise RuntimeError(
            "Nenhuma credencial válida encontrada."
        )

    return credentials

# Lista de credenciais carregada durante a inicialização
CREDENTIALS = []


FILES = [
    {
        "local": "audit_clean.sh",
        "remote_name": "audit_clean.sh",
        "mode": "755",
        "owner": "root:root"
    },
    {
        "local": "customizedaudit.rules",
        "remote_name": "customizedaudit.rules",
        "mode": "644",
        "owner": "root:root"
    }
]

REMOTE_DIR = "/etc/audit/rules.d"
TMP_DIR = "/tmp"




def run_cmd(ssh, cmd, password=None, user=None, timeout=30):
    original_cmd = cmd

    if user != "root":
        cmd = f"sudo -S -p '' sh -c {shlex.quote(cmd)}"

    try:
        stdin, stdout, stderr = ssh.exec_command(
            cmd,
            get_pty=True,
            timeout=timeout
        )

        if user != "root" and password:
            stdin.write(password + "\n")
            stdin.flush()

        channel = stdout.channel
        channel.settimeout(timeout)

        start = time.time()
        out_chunks = []
        err_chunks = []

        while True:
            if channel.recv_ready():
                out_chunks.append(channel.recv(4096).decode(errors="ignore"))

            if channel.recv_stderr_ready():
                err_chunks.append(channel.recv_stderr(4096).decode(errors="ignore"))

            if channel.exit_status_ready():
                break

            if time.time() - start > timeout:
                channel.close()
                return 124, "".join(out_chunks).strip(), f"TIMEOUT no comando: {original_cmd}"

            time.sleep(0.2)

        rc = channel.recv_exit_status()

        out = "".join(out_chunks) + stdout.read().decode(errors="ignore")
        err = "".join(err_chunks) + stderr.read().decode(errors="ignore")

        out = out.strip()
        err = err.strip()

        full_msg = f"{out} {err}".lower()

        if "password has expired" in full_msg or "password change required" in full_msg:
            return 125, out, "Senha expirada ou troca obrigatória sem TTY"

        if "sorry, try again" in full_msg or "incorrect password" in full_msg:
            return 126, out, "Senha sudo inválida"

        return rc, out, err

    except Exception as e:
        return 124, "", f"TIMEOUT/ERRO no comando '{original_cmd}': {e}"


def connect_ssh(host, user, password, port=22, timeout=8):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    ssh.connect(
        hostname=host,
        port=port,
        username=user,
        password=password,
        timeout=timeout,
        banner_timeout=timeout,
        auth_timeout=timeout,
        channel_timeout=timeout,
        look_for_keys=False,
        allow_agent=False
    )

    return ssh


def configure_audit_before_copy(ssh, user, password):
    rc, distro, err = run_cmd(
        ssh,
        "grep '^ID=' /etc/os-release | cut -d= -f2 | tr -d '\"'",
        password,
        user,
        timeout=15
    )

    if rc != 0:
        return "ERROR", f"Falha ao detectar distribuição: {err or distro}"

    distro = distro.strip().lower()

    rc, out, err = run_cmd(
        ssh,
        r"sed -ri 's/^[[:space:]]*q_depth[[:space:]]*=.*/q_depth = 1024/' /etc/audit/auditd.conf",
        password,
        user,
        timeout=20
    )

    if rc != 0:
        return "ERROR", f"Falha ao ajustar q_depth: {err or out}"

    if distro == "ubuntu":
        ubuntu_rules = r"""cat > /etc/audit/rules.d/audit.rules <<'EOF'
## First rule - delete all
-D

## Increase the buffers to survive stress events.
## Make this bigger for busy systems
-b 8192

## This determine how long to wait in burst of events
--backlog_wait_time 60000

## Set failure mode to syslog
-f 1
EOF
"""

        rc, out, err = run_cmd(
            ssh,
            ubuntu_rules,
            password,
            user,
            timeout=30
        )

        if rc != 0:
            return "ERROR", f"Falha ao criar audit.rules Ubuntu: {err or out}"

    else:
        rc, out, err = run_cmd(
            ssh,
            r"test -f /etc/audit/rules.d/audit.rules && sed -ri 's|^([[:space:]]*)-a[[:space:]]+task,never|\1#-a task,never|' /etc/audit/rules.d/audit.rules || true",
            password,
            user,
            timeout=20
        )

        if rc != 0:
            return "ERROR", f"Falha ao comentar -a task,never: {err or out}"

    return "OK", f"Pré-configuração aplicada. distro={distro}"


def copy_files(host, user, password, port):
    ssh = None
    sftp = None

    try:
        ssh = connect_ssh(host, user, password, port)
        sftp = ssh.open_sftp()

        rc, out, err = run_cmd(
            ssh,
            f"test -d {REMOTE_DIR}",
            password,
            user,
            timeout=15
        )

        if rc != 0:
            return "ERROR", f"Diretório {REMOTE_DIR} não existe ou sem acesso: {err or out}"

        status, msg = configure_audit_before_copy(ssh, user, password)

        if status != "OK":
            return status, msg

        for item in FILES:
            local_file = item["local"]
            remote_tmp = f"{TMP_DIR}/{item['remote_name']}"
            remote_final = f"{REMOTE_DIR}/{item['remote_name']}"

            if not os.path.isfile(local_file):
                return "ERROR", f"Arquivo local não encontrado: {local_file}"

            try:
                sftp.put(local_file, remote_tmp)
            except Exception as e:
                return "ERROR", f"Falha ao enviar {local_file} para {remote_tmp}: {e}"

            commands = [
                f"mv {remote_tmp} {remote_final}",
                f"chown {item['owner']} {remote_final}",
                f"chmod {item['mode']} {remote_final}",
                f"ls -l {remote_final}"
            ]

            for cmd in commands:
                rc, out, err = run_cmd(
                    ssh,
                    cmd,
                    password,
                    user,
                    timeout=20
                )

                if rc != 0:
                    return "ERROR", f"Falha no comando '{cmd}': {err or out}"

        audit_commands = [
            "augenrules --load",
            "systemctl restart auditd || service auditd restart",
            "sleep 2",
            "systemctl is-active auditd || service auditd status",
            "auditctl -s",
            "grep '^q_depth' /etc/audit/auditd.conf",
            "grep 'task,never' /etc/audit/rules.d/audit.rules || true",
            "auditctl -l | head -20"
        ]

        for cmd in audit_commands:
            rc, out, err = run_cmd(
                ssh,
                cmd,
                password,
                user,
                timeout=40
            )

            if rc != 0:
                return "ERROR", f"Falha ao executar '{cmd}': {err or out}"

        return "OK", "Pré-configuração aplicada, arquivos copiados, regras carregadas e auditd validado"

    except paramiko.AuthenticationException:
        return "AUTH_FAIL", "Falha de autenticação"

    except paramiko.SSHException as e:
        return "SSH_FAIL", str(e)

    except socket.timeout:
        return "SSH_FAIL", "Timeout na conexão SSH"

    except Exception as e:
        erro = str(e)

        if "EOF during negotiation" in erro:
            return "SSH_FAIL", erro

        return "ERROR", erro

    finally:
        try:
            if sftp:
                sftp.close()
        except Exception:
            pass

        try:
            if ssh:
                ssh.close()
        except Exception:
            pass


def read_hosts(file_path):
    with open(file_path, "r") as f:
        return [
            line.strip()
            for line in f
            if line.strip() and not line.strip().startswith("#")
        ]


def main():
    global CREDENTIALS

    if not Path(".env").exists():
        raise FileNotFoundError(
            "Arquivo .env não encontrado. Crie-o a partir do .env.example."
        )

    load_dotenv(dotenv_path=".env")

    CREDENTIALS = load_credentials()

    print(f"[INFO] {len(CREDENTIALS)} credencial(is) carregada(s) do .env")

    parser = argparse.ArgumentParser(
        description="Copia arquivos de audit para várias VMs, ajusta auditd.conf/audit.rules e recarrega auditd."
    )

    parser.add_argument("-H", "--hosts", required=True, help="Arquivo com lista de hosts")
    parser.add_argument("-p", "--port", default=22, type=int, help="Porta SSH")
    parser.add_argument("-o", "--output", default="resultado_copy_audit.csv", help="Arquivo CSV de saída")

    args = parser.parse_args()
    hosts = read_hosts(args.hosts)

    with open(args.output, "w", newline="", encoding="utf-8") as log:
        writer = csv.writer(log)
        writer.writerow(["host", "user", "status", "message"])

        for host in hosts:
            host_ok = False
            final_status = "FAIL"
            final_msg = "Nenhum usuário conseguiu autenticar ou conectar"
            final_user = "-"

            for cred in CREDENTIALS:
                user = cred["user"]
                password = cred["password"]

                print(f"[INFO] Testando {host} com usuário {user}...")

                status, msg = copy_files(
                    host=host,
                    user=user,
                    password=password,
                    port=args.port
                )

                if status == "OK":
                    print(f"[OK] {host} | user={user} | {msg}")
                    writer.writerow([host, user, "OK", msg])
                    log.flush()
                    host_ok = True
                    break

                elif status == "AUTH_FAIL":
                    print(f"[AUTH_FAIL] {host} | user={user}")
                    final_status = "AUTH_FAIL"
                    final_msg = msg
                    final_user = user
                    continue

                elif status == "SSH_FAIL":
                    print(f"[SSH_FAIL] {host} | user={user} | {msg}")
                    final_status = "SSH_FAIL"
                    final_msg = msg
                    final_user = user
                    break

                else:
                    print(f"[ERROR] {host} | user={user} | {msg}")
                    writer.writerow([host, user, "ERROR", msg])
                    log.flush()
                    host_ok = True
                    break

                time.sleep(0.5)

            if not host_ok:
                print(f"[{final_status}] {host} | user={final_user} | {final_msg}")
                writer.writerow([host, final_user, final_status, final_msg])
                log.flush()


if __name__ == "__main__":
    main()
