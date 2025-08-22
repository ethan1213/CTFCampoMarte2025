#!/bin/bash
# AWS CTF DEFENSE SCRIPT v3.0
# SOLO PARA EJECUTAR EN LA INSTANCIA AWS (DEFENSA)
# sudo bash aws_ctf_defense.sh

set -euo pipefail

# Colores
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly BOLD='\033[1m'
readonly NC='\033[0m'

# Variables globales
AWS_REGION=""
INSTANCE_ID=""
PUBLIC_IP=""
PRIVATE_IP=""
MAIN_PORT=""
CTF_PORTS=""

readonly WORK_DIR="/opt/aws-ctf-defense"
readonly LOG_FILE="/var/log/aws-ctf-defense.log"

print_banner() {
    echo -e "${BLUE}${BOLD}"
    cat << 'EOF'
╔══════════════════════════════════════════════════════════════════════════════╗
║                    🛡️  AWS CTF DEFENSE SETUP v3.0                          ║
║                      SOLO PARA INSTANCIA AWS                                ║
║                                                                              ║
║  • Protección automática de servicios                                       ║
║  • Fail2ban ultra-conservador                                               ║
║  • Monitoreo en tiempo real                                                 ║
║  • Health checking compatible                                               ║
║  • Auto-recovery de servicios                                               ║
╚══════════════════════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

log() {
    local message="[$(date +'%Y-%m-%d %H:%M:%S')] ✅ $1"
    echo -e "${GREEN}${message}${NC}" | tee -a "$LOG_FILE"
}

log_warn() {
    local message="[$(date +'%Y-%m-%d %H:%M:%S')] ⚠️  $1"
    echo -e "${YELLOW}${message}${NC}" | tee -a "$LOG_FILE"
}

log_error() {
    local message="[$(date +'%Y-%m-%d %H:%M:%S')] ❌ $1"
    echo -e "${RED}${message}${NC}" | tee -a "$LOG_FILE"
}

log_info() {
    local message="[$(date +'%Y-%m-%d %H:%M:%S')] 📋 $1"
    echo -e "${BLUE}${message}${NC}" | tee -a "$LOG_FILE"
}

check_prerequisites() {
    log_info "Verificando prerrequisitos de defensa..."
    
    if [[ $EUID -ne 0 ]]; then
        log_error "Debe ejecutarse como root: sudo $0"
        exit 1
    fi
    
    if ! curl -s --max-time 5 http://169.254.169.254/latest/meta-data/ >/dev/null 2>&1; then
        log_error "No se detectó instancia AWS - este script es SOLO para la instancia AWS"
        exit 1
    fi
    
    mkdir -p "$WORK_DIR"
    log "Prerrequisitos verificados - Modo DEFENSA"
}

get_aws_metadata() {
    log_info "Obteniendo metadata de AWS..."
    
    local metadata_url="http://169.254.169.254/latest/meta-data"
    local timeout=10
    
    AWS_REGION=$(curl -s --max-time $timeout "${metadata_url}/placement/region" 2>/dev/null || echo "unknown")
    INSTANCE_ID=$(curl -s --max-time $timeout "${metadata_url}/instance-id" 2>/dev/null || echo "unknown")
    PUBLIC_IP=$(curl -s --max-time $timeout "${metadata_url}/public-ipv4" 2>/dev/null || echo "unknown")
    PRIVATE_IP=$(curl -s --max-time $timeout "${metadata_url}/local-ipv4" 2>/dev/null || echo "unknown")
    
    log "AWS Region: $AWS_REGION"
    log "Instance ID: $INSTANCE_ID"
    log "Public IP: $PUBLIC_IP (TARGET para ataques)"
    log "Private IP: $PRIVATE_IP"
    
    cat > "$WORK_DIR/target_info.conf" << EOF
# INFORMACIÓN DEL TARGET (para equipo de ataque)
AWS_REGION="$AWS_REGION"
INSTANCE_ID="$INSTANCE_ID"
TARGET_IP="$PUBLIC_IP"
PRIVATE_IP="$PRIVATE_IP"
EOF
}

detect_ctf_service() {
    log_info "Detectando servicios CTF a proteger..."
    
    local excluded_ports="22 53 111 631"
    local all_ports
    all_ports=$(ss -tlnH 2>/dev/null | awk '{print $4}' | sed 's/.*://' | sort -nu)
    
    CTF_PORTS=""
    for port in $all_ports; do
        if [[ ! " $excluded_ports " =~ " $port " ]]; then
            if [[ $port -gt 1024 ]] || [[ $port -eq 80 ]] || [[ $port -eq 443 ]] || [[ $port -eq 8080 ]]; then
                CTF_PORTS="$CTF_PORTS $port"
            fi
        fi
    done
    
    CTF_PORTS=$(echo $CTF_PORTS | xargs)
    
    if [[ -z "$CTF_PORTS" ]]; then
        log_warn "No se detectaron servicios CTF. Usando puerto 8080 por defecto"
        MAIN_PORT="8080"
    else
        MAIN_PORT=$(echo $CTF_PORTS | awk '{print $1}')
        log "Servicios CTF detectados: $CTF_PORTS"
        log "Puerto principal a proteger: $MAIN_PORT"
    fi
    
    echo "$CTF_PORTS" > "$WORK_DIR/ctf_ports.txt"
    echo "$MAIN_PORT" > "$WORK_DIR/ctf_main_port.txt"
    
    # Información para el equipo de ataque
    cat >> "$WORK_DIR/target_info.conf" << EOF
MAIN_PORT="$MAIN_PORT"
ALL_PORTS="$CTF_PORTS"
EOF
    
    if command -v nc >/dev/null 2>&1 && nc -z localhost "$MAIN_PORT" 2>/dev/null; then
        log "✅ Puerto $MAIN_PORT está activo y será protegido"
    else
        log_warn "Puerto $MAIN_PORT no responde - configurando protección preventiva"
    fi
}

install_defense_packages() {
    log_info "Instalando paquetes de defensa..."
    
    local distro pkg_manager
    
    if command -v apt-get >/dev/null 2>&1; then
        distro="debian"
        pkg_manager="apt"
    elif command -v yum >/dev/null 2>&1; then
        distro="rhel"
        pkg_manager="yum"
    elif command -v dnf >/dev/null 2>&1; then
        distro="rhel"
        pkg_manager="dnf"
    else
        log_error "Distribución no soportada"
        exit 1
    fi
    
    case $pkg_manager in
        "apt")
            export DEBIAN_FRONTEND=noninteractive
            apt-get update -qq
            apt-get install -y fail2ban iptables iptables-persistent rsyslog netcat-openbsd \
                          htop curl wget python3 python3-pip \
                          net-tools iproute2 dnsutils jq
            ;;
        "yum")
            yum update -y -q
            yum install -y epel-release
            yum install -y fail2ban iptables-services rsyslog nc \
                          htop curl wget python3 python3-pip \
                          net-tools iproute bind-utils jq
            systemctl enable iptables
            ;;
        "dnf")
            dnf update -y -q
            dnf install -y fail2ban iptables-services rsyslog nc \
                          htop curl wget python3 python3-pip \
                          net-tools iproute bind-utils jq
            systemctl enable iptables
            ;;
    esac
    
    local critical_commands=("fail2ban-client" "iptables" "nc" "python3" "ss")
    for cmd in "${critical_commands[@]}"; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            log_error "Falló instalación de $cmd"
            exit 1
        fi
    done
    
    log "Paquetes de defensa instalados correctamente"
}

setup_fail2ban_defense() {
    log_info "Configurando fail2ban para defensa CTF..."
    
    local timestamp
    timestamp=$(date +%Y%m%d_%H%M%S)
    if [[ -f /etc/fail2ban/jail.local ]]; then
        cp /etc/fail2ban/jail.local "/etc/fail2ban/jail.local.backup.$timestamp"
    fi
    
    # Configuración defensiva ultra-conservadora
    cat > /etc/fail2ban/jail.local << EOF
# AWS CTF DEFENSE Configuration v3.0
# Ultra-conservador para mantener servicios UP

[DEFAULT]
# CONFIGURACIÓN MUY PERMISIVA PARA CTF
bantime = 300           # Solo 5 minutos
findtime = 180          # 3 minutos de ventana
maxretry = 50           # 50 intentos (muy permisivo)

banaction = iptables-multiport
protocol = tcp
chain = INPUT

# WHITELIST EXTENSIVA - Incluye todo lo posible
ignoreip = 127.0.0.0/8 
           10.0.0.0/8 
           172.16.0.0/12 
           192.168.0.0/16
           169.254.0.0/16
           # Rangos AWS comunes
           52.0.0.0/8 
           54.0.0.0/8
           3.0.0.0/8
           # IP de esta instancia
           $PRIVATE_IP/32
           $PUBLIC_IP/32

loglevel = ERROR
logtarget = /var/log/fail2ban.log

# SSH - Extremadamente conservador
[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log /var/log/secure
maxretry = 100          # Casi imposible de banear SSH
bantime = 180           # Solo 3 minutos
findtime = 300

# CTF Service - Solo para ataques MUY obvios
[ctf-service-defense]
enabled = true
port = $MAIN_PORT,$CTF_PORTS
filter = ctf-defense-conservative
logpath = /var/log/syslog
          /var/log/daemon.log
          /var/log/messages
maxretry = 100          # Extremadamente permisivo
bantime = 120           # Solo 2 minutos
findtime = 120

# DESHABILITAR todo lo que pueda interferir
[apache-auth]
enabled = false

[nginx-http-auth]
enabled = false

[apache-badbots]
enabled = false

[apache-noscript]
enabled = false

[nginx-noscript]
enabled = false

[portscan]
enabled = false

[recidive]
enabled = false

EOF

    # Filtro ultra-conservador para CTF
    cat > /etc/fail2ban/filter.d/ctf-defense-conservative.conf << 'EOF'
[Definition]
# Filtro ULTRA-CONSERVADOR para defensa CTF
# Solo banea ataques extremadamente obvios

failregex = ^.*<HOST>.*MASSIVE.*ATTACK.*DETECTED.*
            ^.*<HOST>.*CONFIRMED.*MALICIOUS.*ACTIVITY.*
            ^.*<HOST>.*BRUTE.*FORCE.*CONFIRMED.*
            ^.*<HOST>.*DDoS.*ATTACK.*CONFIRMED.*

# IGNORAR absolutamente todo lo demás
ignoreregex = .*

[Init]
journalmatch = _SYSTEMD_UNIT=ssh.service + _SYSTEMD_UNIT=sshd.service
EOF

    if ! fail2ban-client -t >/dev/null 2>&1; then
        log_error "Error en configuración fail2ban"
        exit 1
    fi
    
    systemctl enable fail2ban
    systemctl restart fail2ban
    
    local retries=5
    while [[ $retries -gt 0 ]]; do
        if systemctl is-active --quiet fail2ban; then
            log "Fail2ban configurado para defensa CTF"
            break
        fi
        ((retries--))
        sleep 2
    done
    
    if [[ $retries -eq 0 ]]; then
        log_error "Fail2ban no se pudo iniciar"
        exit 1
    fi
}

create_defense_tools() {
    log_info "Creando herramientas de defensa..."
    
    cat > /usr/local/bin/defense-status << 'EOF'
#!/bin/bash
# Defense Status Tool

if [[ -f /opt/aws-ctf-defense/target_info.conf ]]; then
    source /opt/aws-ctf-defense/target_info.conf
else
    TARGET_IP=$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4 2>/dev/null || echo "unknown")
    MAIN_PORT=$(cat /opt/aws-ctf-defense/ctf_main_port.txt 2>/dev/null || echo "8080")
fi

# Colores
G='\033[0;32m' R='\033[0;31m' Y='\033[1;33m' B='\033[0;34m' BOLD='\033[1m' NC='\033[0m'

echo -e "${B}${BOLD}🛡️  CTF DEFENSE STATUS${NC}"
echo "========================="
echo "Target IP: $TARGET_IP"
echo "Main Port: $MAIN_PORT" 
echo "Time: $(date)"
echo

# Servicios
echo -e "${Y}${BOLD}Services Status:${NC}"
if timeout 3 nc -z localhost "$MAIN_PORT" 2>/dev/null; then
    echo -e "  ${G}✅ CTF Service (port $MAIN_PORT): PROTECTED & UP${NC}"
else
    echo -e "  ${R}❌ CTF Service (port $MAIN_PORT): DOWN${NC}"
fi

if timeout 3 nc -z localhost 22 2>/dev/null; then
    echo -e "  ${G}✅ SSH (port 22): UP${NC}"
else
    echo -e "  ${R}❌ SSH (port 22): DOWN${NC}"
fi

# Conectividad externa
echo -e "${Y}${BOLD}External Access:${NC}"
if timeout 10 nc -z "$TARGET_IP" "$MAIN_PORT" 2>/dev/null; then
    echo -e "  ${G}✅ CTF Service accessible from outside${NC}"
else
    echo -e "  ${R}❌ CTF Service NOT accessible (check Security Groups!)${NC}"
fi

# Conexiones activas
echo -e "${Y}${BOLD}Active Connections:${NC}"
local ctf_conn ssh_conn
ctf_conn=$(ss -tn 2>/dev/null | grep ":$MAIN_PORT " | grep ESTAB | wc -l)
ssh_conn=$(ss -tn 2>/dev/null | grep ":22 " | grep ESTAB | wc -l)
echo "  CTF Service: $ctf_conn active connections"
echo "  SSH: $ssh_conn active connections"

# Protección
echo -e "${Y}${BOLD}Defense Status:${NC}"
if systemctl is-active --quiet fail2ban; then
    local banned
    banned=$(fail2ban-client status 2>/dev/null | grep -o "Currently banned:.*[0-9]" | grep -o "[0-9]*" | tail -1)
    echo -e "  ${G}✅ Fail2ban: Active (${banned:-0} IPs banned)${NC}"
else
    echo -e "  ${R}❌ Fail2ban: INACTIVE${NC}"
fi

if systemctl is-active --quiet aws-ctf-defense-monitor; then
    echo -e "  ${G}✅ Defense Monitor: Active${NC}"
else
    echo -e "  ${Y}⚠️  Defense Monitor: Inactive${NC}"
fi

# Recursos
echo -e "${Y}${BOLD}System Resources:${NC}"
local mem_usage disk_usage load_avg
mem_usage=$(free | grep Mem | awk '{printf("%.1f%%", $3/$2 * 100.0)}')
disk_usage=$(df / | tail -1 | awk '{print $5}')
load_avg=$(uptime | awk -F'load average:' '{print $2}' | awk '{print $1}' | sed 's/,//')

echo "  Memory: $mem_usage"
echo "  Disk: $disk_usage" 
echo "  Load: $load_avg"
EOF
    chmod +x /usr/local/bin/defense-status
    
    cat > /usr/local/bin/defense-restart << 'EOF'
#!/bin/bash
# Defense Service Restart

MAIN_PORT=$(cat /opt/aws-ctf-defense/ctf_main_port.txt 2>/dev/null || echo "8080")

echo "🔄 Restarting CTF services for defense..."

# Encontrar proceso del servicio CTF
service_pid=$(ss -tlnp 2>/dev/null | grep ":$MAIN_PORT " | sed 's/.*pid=\([0-9]*\).*/\1/' | head -1)

if [[ -n "$service_pid" && "$service_pid" =~ ^[0-9]+$ ]]; then
    service_name=$(ps -p "$service_pid" -o comm= 2>/dev/null || echo "unknown")
    echo "Found CTF service: $service_name (PID: $service_pid)"
    
    # Reinicio elegante
    systemd_service=$(systemctl list-units --type=service --state=active 2>/dev/null | grep "$service_name" | awk '{print $1}' | head -1)
    
    if [[ -n "$systemd_service" ]]; then
        echo "Restarting via systemctl: $systemd_service"
        systemctl restart "$systemd_service"
    else
        echo "Sending graceful restart signal..."
        kill -HUP "$service_pid" 2>/dev/null || kill -TERM "$service_pid" 2>/dev/null
    fi
    
    sleep 5
    if timeout 3 nc -z localhost "$MAIN_PORT" 2>/dev/null; then
        echo "✅ CTF Service restarted successfully"
    else
        echo "❌ CTF Service restart failed"
    fi
else
    echo "❌ Could not identify CTF service process"
fi
EOF
    chmod +x /usr/local/bin/defense-restart
    
    cat > /usr/local/bin/defense-unban << 'EOF'
#!/bin/bash
# Defense Unban Tool

echo "🔓 Unbanning all IPs for maximum availability..."

if ! systemctl is-active --quiet fail2ban; then
    echo "❌ Fail2ban is not running"
    exit 1
fi

total_unbanned=0
jails=$(fail2ban-client status 2>/dev/null | grep "Jail list" | cut -d: -f2 | tr ',' ' ')

for jail in $jails; do
    jail=$(echo "$jail" | xargs)
    if [[ -n "$jail" ]]; then
        echo "Processing jail: $jail"
        banned_ips=$(fail2ban-client status "$jail" 2>/dev/null | grep "Banned IP list" | cut -d: -f2)
        
        for ip in $banned_ips; do
            ip=$(echo "$ip" | xargs)
            if [[ -n "$ip" && "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                if fail2ban-client set "$jail" unbanip "$ip" 2>/dev/null; then
                    ((total_unbanned++))
                fi
            fi
        done
    fi
done

echo "✅ Unbanned $total_unbanned IPs total"
echo "🎯 Maximum availability restored"
EOF
    chmod +x /usr/local/bin/defense-unban
    
    # Health check para organizadores
    cat > /usr/local/bin/defense-health << 'EOF'
#!/bin/bash
# Defense Health Check (for organizers)

if [[ -f /opt/aws-ctf-defense/target_info.conf ]]; then
    source /opt/aws-ctf-defense/target_info.conf
else
    TARGET_IP=$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4 2>/dev/null || echo "unknown")
    MAIN_PORT=$(cat /opt/aws-ctf-defense/ctf_main_port.txt 2>/dev/null || echo "8080")
fi

echo "🏥 CTF Defense Health Check"
echo "=========================="
echo "Target: $TARGET_IP:$MAIN_PORT"
echo "Time: $(date)"
echo

exit_code=0

# Test CTF service
echo "Testing CTF service connectivity..."
if timeout 10 nc -z "$TARGET_IP" "$MAIN_PORT" 2>/dev/null; then
    echo "✅ CTF Service: ACCESSIBLE"
else
    echo "❌ CTF Service: NOT ACCESSIBLE"
    exit_code=1
fi

# Test SSH
echo "Testing SSH connectivity..."
if timeout 10 nc -z "$TARGET_IP" 22 2>/dev/null; then
    echo "✅ SSH: ACCESSIBLE"
else
    echo "❌ SSH: NOT ACCESSIBLE"
    exit_code=1
fi

# Test responsiveness
echo "Testing service responsiveness..."
success_count=0
for i in {1..3}; do
    if timeout 5 nc -z "$TARGET_IP" "$MAIN_PORT" 2>/dev/null; then
        ((success_count++))
    fi
    sleep 1
done

if [[ $success_count -ge 2 ]]; then
    echo "✅ Service responsiveness: GOOD ($success_count/3)"
else
    echo "❌ Service responsiveness: POOR ($success_count/3)"
    exit_code=1
fi

echo
if [[ $exit_code -eq 0 ]]; then
    echo "🎯 DEFENSE STATUS: HEALTHY - Services are UP and accessible"
else
    echo "⚠️  DEFENSE STATUS: Issues detected - Check configuration"
fi

exit $exit_code
EOF
    chmod +x /usr/local/bin/defense-health
    
    log "Herramientas de defensa creadas:"
    log "  • defense-status - Estado de defensa"
    log "  • defense-restart - Reiniciar servicios"
    log "  • defense-unban - Desbloquear IPs"
    log "  • defense-health - Health check"
}

setup_defense_monitoring() {
    log_info "Configurando monitoreo de defensa..."
    
    cat > /usr/local/bin/aws-ctf-defense-monitor << 'EOF'
#!/bin/bash
# AWS CTF Defense Background Monitor

MONITOR_LOG="/var/log/aws-ctf-defense-monitor.log"
MAIN_PORT=$(cat /opt/aws-ctf-defense/ctf_main_port.txt 2>/dev/null || echo "8080")

log_monitor() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1" >> "$MONITOR_LOG"
}

log_monitor "Defense monitor started for port $MAIN_PORT"

while true; do
    # Check CTF service
    if ! nc -z localhost "$MAIN_PORT" 2>/dev/null; then
        log_monitor "CRITICAL: CTF service on port $MAIN_PORT is DOWN"
        
        # Auto-restart attempt
        /usr/local/bin/defense-restart >/dev/null 2>&1
        sleep 5
        
        if nc -z localhost "$MAIN_PORT" 2>/dev/null; then
            log_monitor "AUTO-RECOVERY: CTF service restarted successfully"
        else
            log_monitor "AUTO-RECOVERY FAILED: CTF service still down"
        fi
    fi
    
    # Check SSH
    if ! nc -z localhost 22 2>/dev/null; then
        log_monitor "CRITICAL: SSH service is DOWN"
    fi
    
    # Check fail2ban
    if ! systemctl is-active --quiet fail2ban; then
        log_monitor "WARNING: fail2ban service is DOWN"
        systemctl restart fail2ban >/dev/null 2>&1
    fi
    
    # Check high ban count (auto-unban if too many)
    if systemctl is-active --quiet fail2ban; then
        banned_count=$(fail2ban-client status 2>/dev/null | grep -o "Currently banned:.*[0-9]" | grep -o "[0-9]*" | tail -1)
        if [[ ${banned_count:-0} -gt 50 ]]; then
            log_monitor "AUTO-UNBAN: Too many banned IPs ($banned_count), unbanning all"
            /usr/local/bin/defense-unban >/dev/null 2>&1
        fi
    fi
    
    # Check resources
    mem_usage=$(free | grep Mem | awk '{printf("%.0f", $3/$2 * 100.0)}')
    if [[ $mem_usage -gt 95 ]]; then
        log_monitor "CRITICAL: Very high memory usage: ${mem_usage}%"
    fi
    
    sleep 30  # Check every 30 seconds
done
EOF
    chmod +x /usr/local/bin/aws-ctf-defense-monitor
    
    # Crear servicio systemd
    cat > /etc/systemd/system/aws-ctf-defense-monitor.service << 'EOF'
[Unit]
Description=AWS CTF Defense Background Monitor
After=network.target fail2ban.service

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/aws-ctf-defense-monitor
Restart=always
RestartSec=10
StandardOutput=null
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable aws-ctf-defense-monitor
    systemctl start aws-ctf-defense-monitor
    
    log "Monitoreo de defensa configurado y activo"
}

create_defense_aliases() {
    log_info "Creando aliases de defensa..."
    
    cat >> /home/ubuntu/.bashrc << 'EOF'

# ==========================================
# AWS CTF DEFENSE Aliases v3.0
# ==========================================

alias def-status='sudo defense-status'
alias def-restart='sudo defense-restart'
alias def-unban='sudo defense-unban'
alias def-health='defense-health'
alias def-logs='sudo tail -f /var/log/aws-ctf-defense-monitor.log'

# Funciones de defensa
def-emergency() {
    echo "🚨 DEFENSE EMERGENCY PROTOCOL"
    echo "=============================="
    echo "1. Unbanning all IPs..."
    def-unban
    echo "2. Restarting services..."
    def-restart
    echo "3. Status check..."
    def-status
    echo "🎯 Defense emergency completed!"
}

def-monitor() {
    while true; do
        clear
        def-status
        echo
        echo "Press [R]estart, [U]nban, [H]ealth, or Ctrl+C to exit"
        if read -t 30 -n 1 input 2>/dev/null; then
            case $input in
                [Rr]) def-restart; read -p "Press Enter..." ;;
                [Uu]) def-unban; read -p "Press Enter..." ;;
                [Hh]) def-health; read -p "Press Enter..." ;;
            esac
        fi
    done
}

def-help() {
    echo "🛡️  CTF Defense Commands:"
    echo "========================"
    echo "  def-status     - Show defense status"
    echo "  def-restart    - Restart CTF services"
    echo "  def-unban      - Unban all IPs"
    echo "  def-health     - Health check"
    echo "  def-monitor    - Real-time monitoring"
    echo "  def-emergency  - Emergency protocol"
    echo "  def-logs       - View monitor logs"
}

# Show target info on login
if [[ -f /opt/aws-ctf-defense/target_info.conf && ! -f ~/.defense_info_shown ]]; then
    echo "🛡️  CTF Defense Mode Active!"
    echo "============================"
    source /opt/aws-ctf-defense/target_info.conf
    echo "Target IP: $TARGET_IP"
    echo "Main Port: $MAIN_PORT"
    echo "Use 'def-help' for commands"
    echo
    touch ~/.defense_info_shown
fi
EOF

    chown ubuntu:ubuntu /home/ubuntu/.bashrc 2>/dev/null || true
    log "Aliases de defensa configurados"
}

generate_target_info() {
    log_info "Generando información del target..."
    
    cat > "$WORK_DIR/TARGET_INFO.txt" << EOF
===============================================
CTF TARGET INFORMATION
===============================================
Date: $(date)
Target IP: $PUBLIC_IP
SSH Port: 22
Main CTF Port: $MAIN_PORT
All CTF Ports: $CTF_PORTS
AWS Region: $AWS_REGION
Instance ID: $INSTANCE_ID

COPY THIS INFORMATION TO YOUR ATTACK MACHINE
===============================================

For your attack scripts, use:
TARGET_IP="$PUBLIC_IP"
MAIN_PORT="$MAIN_PORT"
ALL_PORTS=($CTF_PORTS)

===============================================
EOF

    log "Target information generated in $WORK_DIR/TARGET_INFO.txt"
    echo -e "${YELLOW}${BOLD}"
    echo "=============================================="
    echo "📋 INFORMACIÓN PARA EL EQUIPO DE ATAQUE:"
    echo "=============================================="
    cat "$WORK_DIR/TARGET_INFO.txt"
    echo "=============================================="
    echo -e "${NC}"
}

final_defense_verification() {
    log_info "Verificación final de defensa..."
    
    local errors=0
    
    # Servicios críticos
    local services=("ssh" "fail2ban" "aws-ctf-defense-monitor")
    for service in "${services[@]}"; do
        if systemctl is-active --quiet "$service"; then
            log "✅ Servicio $service: Activo"
        else
            log_error "❌ Servicio $service: Inactivo"
            ((errors++))
        fi
    done
    
    # Puertos
    if timeout 5 nc -z localhost 22 2>/dev/null; then
        log "✅ SSH (puerto 22): Accesible"
    else
        log_error "❌ SSH (puerto 22): No accesible"
        ((errors++))
    fi
    
    if timeout 5 nc -z localhost "$MAIN_PORT" 2>/dev/null; then
        log "✅ Servicio CTF (puerto $MAIN_PORT): Activo"
    else
        log_warn "⚠️  Servicio CTF (puerto $MAIN_PORT): No responde"
    fi
    
    # Conectividad externa
    if timeout 10 nc -z "$PUBLIC_IP" 22 2>/dev/null; then
        log "✅ SSH externo: Accesible"
    else
        log_warn "⚠️  SSH externo: Verificar Security Groups"
    fi
    
    if timeout 10 nc -z "$PUBLIC_IP" "$MAIN_PORT" 2>/dev/null; then
        log "✅ CTF externo: Accesible"
    else
        log_warn "⚠️  CTF externo: Verificar Security Groups"
    fi
    
    # Herramientas
    local tools=("/usr/local/bin/defense-status" "/usr/local/bin/defense-restart" "/usr/local/bin/defense-unban" "/usr/local/bin/defense-health")
    for tool in "${tools[@]}"; do
        if [[ -x "$tool" ]]; then
            log "✅ Herramienta: $(basename "$tool")"
        else
            log_error "❌ Herramienta faltante: $(basename "$tool")"
            ((errors++))
        fi
    done
    
    if [[ $errors -eq 0 ]]; then
        log "🎉 Verificación de defensa: EXITOSA"
    else
        log_warn "⚠️  Verificación: $errors errores encontrados"
    fi
    
    return $errors
}

main() {
    local start_time
    start_time=$(date +%s)
    
    print_banner
    
    mkdir -p "$(dirname "$LOG_FILE")"
    log_info "Iniciando AWS CTF Defense Setup v3.0..."
    
    check_prerequisites
    get_aws_metadata
    detect_ctf_service
    install_defense_packages
    setup_fail2ban_defense
    create_defense_tools
    setup_defense_monitoring
    create_defense_aliases
    generate_target_info
    
    local verification_result
    final_defense_verification
    verification_result=$?
    
    local end_time duration
    end_time=$(date +%s)
    duration=$((end_time - start_time))
    
    echo
    echo -e "${GREEN}${BOLD}🛡️  AWS CTF DEFENSE SETUP COMPLETED!${NC}"
    echo -e "${BLUE}⏱️  Duración: ${duration}s${NC}"
    echo -e "${BLUE}📍 Instance ID: $INSTANCE_ID${NC}"
    echo -e "${BLUE}🌐 Target IP: $PUBLIC_IP${NC}"
    echo -e "${BLUE}🎯 Puerto Principal: $MAIN_PORT${NC}"
    echo
    
    if [[ $verification_result -eq 0 ]]; then
        echo -e "${GREEN}✅ DEFENSA: COMPLETAMENTE OPERATIVA${NC}"
    else
        echo -e "${YELLOW}⚠️  DEFENSA: OPERATIVA CON ADVERTENCIAS${NC}"
    fi
    
    echo
    echo -e "${GREEN}${BOLD}🛡️  DEFENSA CONFIGURADA:${NC}"
    echo "  • Fail2ban ultra-permisivo para CTF"
    echo "  • Auto-recovery de servicios"
    echo "  • Monitoreo en background" 
    echo "  • Health checking compatible"
    echo "  • Auto-unban cuando hay muchos bans"
    echo
    echo -e "${BLUE}${BOLD}📋 COMANDOS DE DEFENSA:${NC}"
    echo "  • ${BOLD}def-status${NC}      - Estado de defensa"
    echo "  • ${BOLD}def-monitor${NC}     - Monitor en tiempo real"
    echo "  • ${BOLD}def-restart${NC}     - Reiniciar servicios CTF"
    echo "  • ${BOLD}def-unban${NC}       - Desbloquear todas las IPs"
    echo "  • ${BOLD}def-emergency${NC}   - Protocolo de emergencia"
    echo "  • ${BOLD}def-health${NC}      - Health check"
    echo "  • ${BOLD}def-help${NC}        - Ayuda completa"
    echo
    echo -e "${YELLOW}${BOLD}⚠️  IMPORTANTE - CONFIGURAR AWS SECURITY GROUPS:${NC}"
    echo -e "${YELLOW}   1. EC2 → Security Groups → [tu-security-group]${NC}"
    echo -e "${YELLOW}   2. Inbound Rules:${NC}"
    echo -e "${YELLOW}      - SSH (22): 0.0.0.0/0${NC}"
    echo -e "${YELLOW}      - CTF ($MAIN_PORT): 0.0.0.0/0${NC}"
    echo -e "${YELLOW}      - ICMP: 0.0.0.0/0${NC}"
    echo
    echo -e "${GREEN}${BOLD}🎯 DEFENSA LISTA - COPIA INFO PARA EQUIPO DE ATAQUE${NC}"
    
    echo -e "\n${BLUE}${BOLD}🏥 Ejecutando health check final...${NC}"
    if /usr/local/bin/defense-health; then
        echo -e "${GREEN}✅ Health check final: PASSED${NC}"
    else
        echo -e "${YELLOW}⚠️  Health check: Verificar Security Groups${NC}"
    fi
    
    echo -e "\n${GREEN}${BOLD}📋 PRÓXIMOS PASOS:${NC}"
    echo "1. Ejecutar: ${BOLD}source ~/.bashrc${NC}"
    echo "2. Configurar Security Groups en AWS Console"
    echo "3. Copiar información del target al equipo de ataque"
    echo "4. Iniciar monitoreo: ${BOLD}def-monitor${NC}"
    echo "5. Verificar: ${BOLD}def-status${NC}"
    
    echo -e "\n${GREEN}${BOLD}📄 Target info guardada en: $WORK_DIR/TARGET_INFO.txt${NC}"
}

# Cleanup en caso de interrupción
cleanup() {
    log_error "Setup de defensa interrumpido. Realizando cleanup..."
    exit 1
}

trap cleanup INT TERM

# Verificar argumentos
case "${1:-}" in
    "help"|"-h"|"--help")
        echo "AWS CTF Defense Setup v3.0"
        echo "=========================="
        echo "SOLO para ejecutar EN LA INSTANCIA AWS"
        echo
        echo "Uso: sudo $0"
        echo
        echo "Este script configura:"
        echo "• Protección fail2ban ultra-permisiva"
        echo "• Monitoreo automático con auto-recovery"  
        echo "• Health checking compatible con organizadores"
        echo "• Herramientas de gestión de defensa"
        exit 0
        ;;
    "--version")
        echo "AWS CTF Defense Setup v3.0"
        exit 0
        ;;
esac

# Ejecutar función principal
main "$@"
