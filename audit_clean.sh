#!/bin/bash

case "$1" in
    today|"")
        TS="today"
        TE="now"
        PERIOD="TODAY"
        ;;
    yesterday)
        TS="yesterday"
        TE="today"
        PERIOD="YESTERDAY"
        ;;
    week)
        TS=$(date --date="7 days ago" +%m/%d/%Y)
        TE="now"
        PERIOD="LAST 7 DAYS"
        ;;
    *)
        echo "Uso: $0 [today|yesterday|week]"
        exit 1
        ;;
esac

OUT="/tmp/audit_$(hostname)_$(date +%F).txt"

extract_events() {
    KEY="$1"

    ausearch -k "$KEY" -ts "$TS" -te "$TE" -i 2>/dev/null |
    awk '
    /^----/ {
        print_event()
        reset()
        next
    }

    /type=SYSCALL/ {
        if (match($0,/msg=audit\([^)]+\)/)) datetime=substr($0,RSTART+10,RLENGTH-11)

        if (match($0,/auid=[^ ]+/)) user=substr($0,RSTART+5,RLENGTH-5)

        if (match($0,/exe=[^ ]+/)) {
            exe=substr($0,RSTART+4,RLENGTH-4)
            gsub(/"/,"",exe)
        }
    }

    /type=EXECVE/ {
        cmd=$0
        sub(/^.*argc=[0-9]+ /,"",cmd)
        gsub(/a[0-9]+=/,"",cmd)
    }

    /type=PROCTITLE/ {
        proctitle=$0
        sub(/^.*proctitle=/,"",proctitle)
        if (cmd == "") cmd=proctitle
    }

    END {
        print_event()
    }

    function reset() {
        datetime=""
        user=""
        exe=""
        cmd=""
        proctitle=""
    }

    function print_event() {
        if (datetime == "" || cmd == "") return

        # Ignora eventos do sistema
        if (user == "unset" || user == "SYSTEM") return

        # Ignora processos do sistema / audit / reload de regras
        if (exe ~ /systemd-logind|systemd-tty-ask-password-agent|auditctl|augenrules|auditd|ausearch|mktemp|gawk|awk|grep|cmp/) return

        # Ignora comandos internos de carga das rules
        if (cmd ~ /aurules|audit.rules|rules.d|auditctl|augenrules|auditd|ausearch|audit_clean/) return

        printf "%s | %s | %s | %s\n", datetime, user, exe, cmd
    }'
}

print_section() {
    TITLE="$1"
    KEY="$2"

    echo
    echo "===== $TITLE ====="
    echo "DATA/HORA | USUARIO | EXECUTAVEL | COMANDO"
    echo "------------------------------------------------------------"

    RESULT=$(extract_events "$KEY")

    if [ -z "$RESULT" ]; then
        echo "Sem eventos encontrados para a key: $KEY"
    else
        echo "$RESULT"
    fi
}

{
echo "AUDIT REPORT"
echo "HOST: $(hostname)"
echo "PERIODO: $PERIOD"
echo "GERADO EM: $(date)"
echo

print_section "USER ADMIN" "user_admin"
print_section "GROUP ADMIN" "group_admin"
print_section "PASSWORD" "passwd_changes"
print_section "USER FILE CHANGES" "user_file_changes"
print_section "GROUP FILE CHANGES" "group_file_changes"
print_section "SUDO CHANGES" "sudo_changes"
print_section "LOGIN POLICY" "login_policy"
print_section "PERMISSION CHANGES" "permission_changes"
print_section "OWNERSHIP CHANGES" "ownership_changes"
#print_section "ANSIBLE EXEC" "ansible_exec"
#print_section "ANSIBLE COMMANDS" "ansible_commands"
print_section "ROOT COMMANDS" "root_commands"
#print_section "ANSIBLE TMP" "ansible_tmp"
#print_section "SEMAPHORE" "semaphore_ansible"

} > "$OUT"

echo
echo "Relatório:"
echo "$OUT"
