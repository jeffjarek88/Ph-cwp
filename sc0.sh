#!/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
CWD="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
TIME="$(date +%F_%T)"
port=1295
####
#########
echo -n "Ingrese el hostname de la maquina:"
read host1
########
hostnamectl set-hostname $host1
########

echo "### Actualizando Sistema Operativo ###"
yum update -y
yum groupinstall "Base" --skip-broken -y
yum install screen -y
sed -i 's/^SELINUX=.*/SELINUX=disabled/' /etc/sysconfig/selinux
sed -i 's/^SELINUX=.*/SELINUX=disabled/' /etc/selinux/config
/usr/sbin/setenforce 0
iptables-save > /root/firewall.rules


	echo "Reescribiendo /etc/resolv.conf..."

    echo "nameserver 200.73.112.15" > /etc/resolv.conf
    echo "nameserver 200.73.112.16" >> /etc/resolv.conf
	
echo "configurando ssh"

cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak.$TIME

sed -i 's/^X11Forwarding.*/X11Forwarding no/' /etc/ssh/sshd_config
sed -i 's/#UseDNS.*/UseDNS no/' /etc/ssh/sshd_config
sed -i 's/^\(#\|\)AllowTcpForwarding yes/AllowTcpForwarding no/' /etc/ssh/sshd_config
sed -i 's/^\(#\|\)ClientAliveCountMax 3/ClientAliveCountMax 2/' /etc/ssh/sshd_config
sed -i 's/^\(#\|\)LogLevel INFO/LogLevel VERBOSE/' /etc/ssh/sshd_config
sed -i 's/^\(#\|\)Compression delayed/Compression no/' /etc/ssh/sshd_config
sed -i 's/^\(#\|\)MaxAuthTries 6/MaxAuthTries 3/' /etc/ssh/sshd_config
sed -i 's/^\(#\|\)MaxSessions 10/MaxSessions 2/' /etc/ssh/sshd_config
sed -i 's/^\(#\|\)TCPKeepAlive yes/TCPKeepAlive no/' /etc/ssh/sshd_config
sed -i 's/^\(#\|\)AllowAgentForwarding yes/AllowAgentForwarding no/' /etc/ssh/sshd_config
sed -i 's/^\(#\|\)LoginGraceTime 2m/LoginGraceTime 20/' /etc/ssh/sshd_config

echo "Cambiando puerto SSH..."

echo "Cambiando puerto SSH default 22 a $port "
sed -i "s/^\(#\|\)Port.*/Port $port/" /etc/ssh/sshd_config

echo "reinicio de servicio"
systemctl restart sshd

# SI TIENE SOLO IPTABLES
if [ -f /etc/sysconfig/iptables ]; then
	sed -i 's/dport 22 /dport $port /' /etc/sysconfig/iptables
	service iptables restart 2>/dev/null
fi

# SI TIENE FIREWALLD
if systemctl is-enabled firewalld | grep "^enabled$" > /dev/null; then
	if systemctl is-active firewalld | grep "^inactive$" > /dev/null; then
		service firewalld restart
	fi
	firewall-cmd --permanent --add-port=$port/tcp > /dev/null
	firewall-offline-cmd --add-port=$port/tcp > /dev/null
	firewall-cmd --reload 
fi

echo "### Configurando FSCK ####"
grubby --update-kernel=ALL --args=fsck.repair=yes
grep "fsck.repair" /etc/default/grub > /dev/null || sed 's/^GRUB_CMDLINE_LINUX="/&fsck.repair=yes /' /etc/default/grub


echo "#### Configurando SSD (de poseer) ####"
for DEVFULL in /dev/sg? /dev/sd?; do
	DEV=$(echo "$DEVFULL" | cut -d'/' -f3)
        if [ -f "/sys/block/$DEV/queue/rotational" ]; then
        	TYPE=$(grep "0" /sys/block/$DEV/queue/rotational > /dev/null && echo "SSD" || echo "HDD")
		if [ "$TYPE" = "SSD" ]; then
			systemctl start fstrim.timer
			systemctl enable fstrim.timer

		fi
        fi
done

echo "### corregir el bug de centos 7 ###"
echo "### Cambiando runlevel a 3 ###" # Trajo algunos problemas con CentOS 7.7: https://bugs.centos.org/view.php?id=16440

systemctl isolate runlevel3.target
systemctl set-default runlevel3.target

echo "################################"
echo "### endurecimiento de CentOS ###"
echo "################################"

echo "#### removiendo paquetes innesesario ####"

echo "Eliminando el compilador GCC"
yum -y remove gcc*

echo "Eliminando servicios heredados"
yum -y remove postfix rsh-server rsh ypserv tftp tftp-server talk talk-server telnet-server xinetd

echo  " Configuración de Daemon umask "
cp /etc/init.d/functions /etc/init.d/functions.bak

echo  " Desactivando servicios innecesarios "
servicelist=(dhcpd avahi-daemon cups nfslock rpcgssd rpcbind rpcidmapd rpcsvcgssd)
for i in ${servicelist[@]}; do
  [ $(systemctl disable $i 2> /dev/null) ] || echo "$i is Disabled"
done


echo  "### Deshabilitar sistemas de archivos heredados ###"

cat << EOF > /etc/modprobe.d/CIS.conf 
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install squahfs /bin/true
install udf /bin/true
install dccp /bin/true
install sctp /bin/true
install rds /bin/true
install tipc /bin/true
EOF

echo "### Actualización del algoritmo de hash de contraseña a SHA512 ###"
authconfig --passalgo=sha512 --update

echo "Setting core dump security limits..."
echo '* hard core 0' > /etc/security/limits.conf

echo "Generating additional logs..."
echo 'auth,user.* /var/log/user' >> /etc/rsyslog.conf
echo 'kern.* /var/log/kern.log' >> /etc/rsyslog.conf
echo 'daemon.* /var/log/daemon.log' >> /etc/rsyslog.conf
echo 'syslog.* /var/log/syslog' >> /etc/rsyslog.conf
echo 'lpr,news,uucp,local0,local1,local2,local3,local4,local5,local6.* /var/log/unused.log' >> /etc/rsyslog.conf
touch /var/log/user /var/log/kern.log /var/log/daemon.log /var/log/syslog /var/log/unused.log
chmod og-rwx /var/log/user /var/log/kern.log /var/log/daemon.log /var/log/syslog /var/log/unused.log
chown root:root /var/log/user /var/log/kern.log /var/log/daemon.log /var/log/syslog /var/log/unused.log

echo "### Habilitando el servicio auditd ###"
systemctl enable auditd

echo "### Configurando el tamaño del almacenamiento del registro de auditoría ###"
cp -a /etc/audit/auditd.conf /etc/audit/auditd.conf.bak.$TIME
sed -i 's/^space_left_action.*$/space_left_action = SYSLOG/' /etc/audit/auditd.conf
sed -i 's/^action_mail_acct.*$/action_mail_acct = root/' /etc/audit/auditd.conf
sed -i 's/^admin_space_left_action.*$/admin_space_left_action = SYSLOG/' /etc/audit/auditd.conf


echo "### Configuración de umask predeterminado para usuarios ###"
line_num=$(grep -n "^[[:space:]]*umask" /etc/bashrc | head -1 | cut -d: -f1)
sed -i ${line_num}s/002/027/ /etc/bashrc
line_num=$(grep -n "^[[:space:]]*umask" /etc/profile | head -1 | cut -d: -f1)
sed -i ${line_num}s/002/027/ /etc/profile

echo "### Verificación de permisos de archivos del sistema ###"
chmod 644 /etc/passwd
chmod 000 /etc/shadow
chmod 000 /etc/gshadow
chmod 644 /etc/group
chown root:root /etc/passwd
chown root:root /etc/shadow
chown root:root /etc/gshadow
chown root:root /etc/group

echo "### Modificando parametros de red ###"

cp /etc/sysctl.conf /etc/sysctl.conf.bak.$TIME

cat << EOF > /etc/sysctl.conf 
net.ipv4.ip_forward=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.default.accept_source_route=0
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.all.secure_redirects=0
net.ipv4.conf.default.secure_redirects=0
net.ipv4.conf.all.log_martians=1
net.ipv4.conf.default.log_martians=1
net.ipv4.route.flush=1
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.icmp_ignore_bogus_error_responses=1
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1
net.ipv4.tcp_syncookies=1
net.ipv6.conf.all.accept_ra=0
net.ipv6.conf.default.accept_ra=0
net.ipv6.conf.all.accept_redirects=0
net.ipv6.conf.default.accept_redirects=0
EOF

sysctl -p

echo "### Corregir permisos grub.cfg ###"
chmod 600 /boot/grub2/gru*.cfg

sleep 10
clear
echo "#######################################"
echo "### ajuste y Seguridad en el kernel ###"
echo "#######################################"

# Cambie los siguientes parámetros cuando una alta tasa de solicitudes de conexión entrantes provoque fallas en la conexión #
echo "100000" > /proc/sys/net/core/netdev_max_backlog
# Tamaño de la cola de escucha para aceptar nuevas conexiones TCP (predeterminado: 128) #
echo "4096" > /proc/sys/net/core/somaxconn
# Número máximo de sockets en TIME-WAIT que se mantendrán simultáneamente (predeterminado: 180000) #
echo "600000" > /proc/sys/net/ipv4/tcp_max_tw_buckets
# establece el búfer de recepción de socket máximo para todos los protocolos (en bytes) #
echo "16777216" > /proc/sys/net/core/rmem_max
echo "16777216" > /proc/sys/net/core/rmem_default
# establece el búfer de envío de socket máximo para todos los protocolos (en bytes) #
echo "16777216" > /proc/sys/net/core/wmem_max
echo "16777216" > /proc/sys/net/core/wmem_default
# Establecer límites de búfer TCP de autoajuste de Linux #
echo "4096 87380 16777216" > /proc/sys/net/ipv4/tcp_rmem
echo "4096 87380 16777216" > /proc/sys/net/ipv4/tcp_wmem
echo "0" > /proc/sys/net/ipv4/tcp_sack
echo "0" > /proc/sys/net/ipv4/tcp_dsack
# De manera predeterminada, TCP guarda varias métricas de conexión en la memoria caché de la ruta cuando se cierra la conexión, de modo que las conexiones establecidas en un futuro próximo puedan usarlas para establecer las condiciones iniciales. Por lo general, esto aumenta el rendimiento general, pero a veces puede causar una degradación del rendimiento. Si se establece, TCP no almacenará en caché las métricas al cerrar las conexiones.
echo "1" > /proc/sys/net/ipv4/tcp_no_metrics_save
# Cuántas veces volver a intentar antes de eliminar una conexión TCP viva
echo "5" > /proc/sys/net/ipv4/tcp_retries2
# Con qué frecuencia enviar paquetes keepalive de TCP para mantener viva una conexión si actualmente no se utiliza. Este valor solo se usa cuando keepalive está habilitado
echo "120" > /proc/sys/net/ipv4/tcp_keepalive_time
# Cuánto tiempo esperar una respuesta en cada sonda keepalive. En otras palabras, este valor es extremadamente importante cuando intentas calcular cuánto tiempo pasará antes de que tu conexión muera como una muerte viva.
echo "30" > /proc/sys/net/ipv4/tcp_keepalive_intvl
# Determina el número de sondas antes del tiempo de espera
echo "3" > /proc/sys/net/ipv4/tcp_keepalive_probes
# Cuánto tiempo mantener los enchufes en el estado FIN-WAIT-2 si fue usted quien cerró el enchufe (predeterminado: 60)
echo "30" > /proc/sys/net/ipv4/tcp_fin_timeout
# A veces, la reordenación de paquetes en una red puede interpretarse como pérdida de paquetes y, por lo tanto, aumentar el valor de este parámetro debería mejorar el rendimiento (el valor predeterminado es "3")
echo "15" > /proc/sys/net/ipv4/tcp_reordering
echo "cubic" > /proc/sys/net/ipv4/tcp_congestion_control
# Este valor varía según la memoria total del sistema. Úselo sabiamente en diferentes situaciones
echo "262144" > /proc/sys/net/ipv4/tcp_max_orphans

# Deshabilitar volcados de núcleo
echo "0" > /proc/sys/fs/suid_dumpable
# Habilitar ExecShield
echo "1" > /proc/sys/kernel/randomize_va_space

echo "### Parámetros de red para una mejor seguridad ###"
# Deshabilitar el reenvío de paquetes (si esta máquina no es un enrutador)
echo "0" > /proc/sys/net/ipv4/ip_forward
echo "0" > /proc/sys/net/ipv4/conf/all/send_redirects
echo "0" > /proc/sys/net/ipv4/conf/default/send_redirects
# Habilite tcp_syncookies para aceptar conexiones legítimas ante un ataque de inundación SYN
echo "1" > /proc/sys/net/ipv4/tcp_syncookies
# Desactívelo para deshabilitar las características del protocolo IPv4 que se consideran que tienen pocos usos legítimos y que son fáciles de abusar
echo "0" > /proc/sys/net/ipv4/conf/all/accept_source_route
echo "0" > /proc/sys/net/ipv4/conf/default/accept_source_route
echo "0" > /proc/sys/net/ipv4/conf/all/accept_redirects
echo "0" > /proc/sys/net/ipv4/conf/default/accept_redirects
echo "0" > /proc/sys/net/ipv4/conf/all/secure_redirects
echo "0" > /proc/sys/net/ipv4/conf/default/secure_redirects
# Registre paquetes sospechosos (esto debe desactivarse si el sistema sufre demasiados registros)
echo "1" > /proc/sys/net/ipv4/conf/all/log_martians
# Proteger de ataques ICMP
echo "1" > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts
# Habilite la validación de fuente recomendada por RFC (no debe usarse en máquinas que son enrutadores para redes muy complicadas)
echo "1" > /proc/sys/net/ipv4/conf/all/rp_filter
echo "1" > /proc/sys/net/ipv4/conf/default/rp_filter
# Aumente el rango de puertos IPv4 para aceptar más conexiones
echo  "5000 65535" > /proc/sys/net/ipv4/ip_local_port_range

# Deshabilitar IPV6
echo "1" > /proc/sys/net/ipv6/conf/all/disable_ipv6
echo "1" > /proc/sys/net/ipv6/conf/default/disable_ipv6
# # 
# ### Ajuste del sistema de archivos
# Aumentar el límite del descriptor de archivo del sistema
echo "7930900" > /proc/sys/fs/file-max
# Permitir más PID
echo "65536" > /proc/sys/kernel/pid_max
# Use hasta 95% de RAM (5% gratis)
echo "5" > /proc/sys/vm/swappiness
##
echo "20" > /proc/sys/vm/dirty_background_ratio
##
echo  "25" > /proc/sys/vm/dirty_ratio


echo "Sincronizando fecha con pool.ntp.org..."
ntpdate 0.pool.ntp.org 1.pool.ntp.org 2.pool.ntp.org 3.pool.ntp.org 0.south-america.pool.ntp.org
if [ -f /usr/share/zoneinfo/America/Santiago ]; then
        echo "Seteando timezone a America/Santiago..."
        mv /etc/localtime /etc/localtime.old
        ln -s /usr/share/zoneinfo/America/Santiago /etc/localtime
fi

echo "Seteando fecha del BIOS..."
hwclock -r

sh $CWD/sc1.sh

echo "Fin del script, se reiniciara el servidor"

init 6