#!/bin/bash
# JohnFordTV's XRay Premium Script
# © Github.com/johndesu090
# Official Repository: https://github.com/johndesu090/
# For Updates, Suggestions, and Bug Reports, Join to my Messenger Groupchat(VPS Owners): https://m.me/join/AbbHxIHfrY9SmoBO
# For Donations, Im accepting prepaid loads or GCash transactions:
# Smart: 09206200840
# Facebook: https://fb.me/johndesu090

#====================================================
#	System Request:Debian 9+/Ubuntu 18.04+/Centos 7+
#	Author:	JohnFordTV
#	Dscription: Xray ws+tls onekey Management
#	Version: 2.0
#	email: exodia090@gmail.com
#	Official document: www.xray.com
#====================================================

#############################
#############################
# Variables (Can be changed depends on your preferred values)

PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

cd "$(
    cd "$(dirname "$0")" || exit
    pwd
)" || exit

#fonts color
Green="\033[32m"
Red="\033[31m"
#Yellow="\033[33m"
GreenBG="\033[42;37m"
RedBG="\033[41;37m"
YellowBG="\033[43;37m"
Font="\033[0m"

#notification information
# Info="${Green}[Information]${Font}"
OK="${Green}[OK]${Font}"
Error="${Red}[Error]${Font}"
Warning="${Red}[Warning]${Font}"

# Version
shell_version="1.2.3.9"
shell_mode="None"
version_cmp="/tmp/version_cmp.tmp"
xray_conf_dir="/usr/local/etc/xray"
nginx_conf_dir="/etc/nginx/conf/conf.d"
xray_conf="${xray_conf_dir}/config.json"
nginx_conf="${nginx_conf_dir}/xray.conf"
nginx_dir="/etc/nginx"
web_dir="/home/wwwroot"
nginx_openssl_src="/usr/local/src"
xray_bin_dir="/usr/local/bin/xray"
johnfordtv_xray_dir="/usr/bin/johnfordtv-xray"
xray_info_file="$HOME/xray_info.inf"
xray_qr_config_file="/usr/local/vmess_qr.json"
nginx_systemd_file="/etc/systemd/system/nginx.service"
xray_systemd_file="/etc/systemd/system/xray.service"
xray_systemd_file2="/etc/systemd/system/xray@.service"
xray_systemd_filed="/etc/systemd/system/xray.service.d"
xray_systemd_filed2="/etc/systemd/system/xray@.service.d"
xray_access_log="/var/log/xray/access.log"
xray_error_log="/var/log/xray/error.log"
amce_sh_file="/root/.acme.sh/acme.sh"
ssl_update_file="${johnfordtv_xray_dir}/ssl_update.sh"
johnfordtv_commend_file="/usr/local/bin/johnfordtv"
nginx_version="1.18.0"
openssl_version="1.1.1j"
jemalloc_version="5.2.1"
old_config_status="off"
# v2ray_plugin_version="$(wget -qO- "https://github.com/shadowsocks/v2ray-plugin/tags" | grep -E "/shadowsocks/v2ray-plugin/releases/tag/" | head -1 | sed -r 's/.*tag\/v(.+)\">.*/\1/')"

#############################
#############################
## All function used for this script
#############################
## WARNING: Do not modify or edit anything
## if you did'nt know what to do.
## This part is too sensitive.
#############################
#############################

# Move the old version configuration information to adapt to the version less than 1.1.0 
[[ -f "/etc/xray/vmess_qr.json" ]] && mv /etc/xray/vmess_qr.json $xray_qr_config_file

# Simple random number 
random_num=$((RANDOM % 12 + 4))
# Generate camouflage path 
camouflage="/$(head -n 10 /dev/urandom | md5sum | head -c ${random_num})/"

THREAD=$(grep 'processor' /proc/cpuinfo | sort -u | wc -l)

source '/etc/os-release'

# Extract the English name of the distribution system from VERSION, in order to add the corresponding Nginx apt source under debian/ubuntu 
VERSION=$(echo "${VERSION}" | awk -F "[()]" '{print $2}')

check_system() {

	read -p "Enter Script Password: " pwd
		if test $pwd == "@xray2021"; then
	echo "Password Accepted!"
else
	echo "Password Incorrect!"
		rm v2r*
		sleep 2
	exit
		fi
		
    if [[ "${ID}" == "centos" && ${VERSION_ID} -ge 7 ]]; then
        echo -e "${OK} ${GreenBG} The current system is Centos ${VERSION_ID} ${VERSION} ${Font}"
        INS="yum"
    elif [[ "${ID}" == "debian" && ${VERSION_ID} -ge 8 ]]; then
        echo -e "${OK} ${GreenBG} The current system is Debian  ${VERSION_ID} ${VERSION} ${Font}"
        INS="apt"
        $INS update
        ## Add Nginx apt source 
    elif [[ "${ID}" == "ubuntu" && $(echo "${VERSION_ID}" | cut -d '.' -f1) -ge 16 ]]; then
        echo -e "${OK} ${GreenBG} The current system is Ubuntu ${VERSION_ID} ${UBUNTU_CODENAME} ${Font}"
        INS="apt"
        rm /var/lib/dpkg/lock
        dpkg --configure -a
        rm /var/lib/apt/lists/lock
        rm /var/cache/apt/archives/lock
        $INS update
    else
        echo -e "${Error} ${RedBG} The current system is ${ID} ${VERSION_ID} is not in the list of supported systems, installation is interrupted ${Font}"
        exit 1
    fi

    $INS install dbus

    systemctl stop firewalld
    systemctl disable firewalld
    echo -e "${OK} ${GreenBG} firewalld terminated ${Font}"

    systemctl stop ufw
    systemctl disable ufw
    echo -e "${OK} ${GreenBG} ufw terminated ${Font}"
}

is_root() {
    if [ 0 == $UID ]; then
        echo -e "${OK} ${GreenBG} The current user is the root user, enter the installation process ${Font}"
        sleep 3
    else
        echo -e "${Error} ${RedBG} The current user is not the root user, please switch to the root user and re-execute the script ${Font}"
        exit 1
    fi
}

judge() {
    if [[ 0 -eq $? ]]; then
        echo -e "${OK} ${GreenBG} $1 Compelete${Font}"
        sleep 1
    else
        echo -e "${Error} ${RedBG} $1 Failed${Font}"
        exit 1
    fi
}

banner_install() {
 # Install BashRC Banner
apt-get install figlet
apt-get install cowsay fortune-mod -y
ln -s /usr/games/cowsay /bin
ln -s /usr/games/fortune /bin
echo "clear" >> .bashrc
echo 'echo -e ""' >> .bashrc
echo 'echo -e ""' >> .bashrc
echo 'cowsay -f dragon "WELCOME MY BOSS." | lolcat' >> .bashrc
echo 'figlet -k JOHNFORDTV' >> .bashrc
echo 'echo -e ""' >> .bashrc
echo 'echo -e "     =========================================================" | lolcat' >> .bashrc
echo 'echo -e "     *                  WELCOME TO XRay SERVER               *" | lolcat' >> .bashrc
echo 'echo -e "     =========================================================" | lolcat' >> .bashrc
echo 'echo -e "     *                 Autoscript By JohnFordTV              *" | lolcat' >> .bashrc
echo 'echo -e "     *                  Debian 9, 10 & Ubuntu18              *" | lolcat' >> .bashrc
echo 'echo -e "     *                   Facebook: johndesu090               *" | lolcat' >> .bashrc
echo 'echo -e "     =========================================================" | lolcat' >> .bashrc
echo 'echo -e "     *             For Donations [GCASH] 09206200840         *"' >> .bashrc
echo 'echo -e "     =========================================================" | lolcat' >> .bashrc
echo 'echo -e "     Command [XRay Menu]: xmenu" | lolcat' >> .bashrc
echo 'echo -e ""' >> .bashrc

}

chrony_install() {
    ${INS} -y install chrony
    judge "Install chrony time synchronization service "

    timedatectl set-ntp true

    if [[ "${ID}" == "centos" ]]; then
        systemctl enable chronyd && systemctl restart chronyd
    else
        systemctl enable chrony && systemctl restart chrony
    fi

    judge "chronyd start"

    timedatectl set-timezone Asia/Shanghai

    echo -e "${OK} ${GreenBG} Waiting time synchronization ${Font}"
    sleep 10

    chronyc sourcestats -v
    chronyc tracking -v
    date
    read -rp "Please confirm whether the time is accurate, the error range is ±3 minutes(Y/N): " chrony_install
    [[ -z ${chrony_install} ]] && chrony_install="Y"
    case $chrony_install in
    [yY][eE][sS] | [yY])
        echo -e "${GreenBG} Continue to install ${Font}"
        sleep 2
        ;;
    *)
        echo -e "${RedBG} Installation terminated ${Font}"
        exit 2
        ;;
    esac
}

dependency_install() {
    ${INS} install wget curl unzip nginx net-tools git lsof ruby -y
	gem install lolcat

    if [[ "${ID}" == "centos" ]]; then
        ${INS} -y install iputils
    else
        ${INS} -y install iputils-ping
    fi
    judge "installing iputils-ping"

    if [[ "${ID}" == "centos" ]]; then
        ${INS} -y install crontabs
    else
        ${INS} -y install cron
    fi
    judge "installing crontab"

    if [[ "${ID}" == "centos" ]]; then
        touch /var/spool/cron/root && chmod 600 /var/spool/cron/root
        systemctl start crond && systemctl enable crond
    else
        touch /var/spool/cron/crontabs/root && chmod 600 /var/spool/cron/crontabs/root
        systemctl start cron && systemctl enable cron

    fi
    judge "crontab self-starting configuration "

    ${INS} -y install bc
    judge "installing bc"

    ${INS} -y install unzip
    judge "installing unzip"

    ${INS} -y install qrencode
    judge "installing qrencode"

    ${INS} -y install curl
    judge "start curl"

    if [[ "${ID}" == "centos" ]]; then
        ${INS} -y groupinstall "Development tools"
    else
        ${INS} -y install build-essential
    fi
    judge "Compilation Toolkit Installation"

    if [[ "${ID}" == "centos" ]]; then
        ${INS} -y install pcre pcre-devel zlib-devel epel-release
    else
        ${INS} -y install libpcre3 libpcre3-dev zlib1g-dev dbus
    fi

    #    ${INS} -y install rng-tools
    #    judge "rng-tools start"

    ${INS} -y install haveged
    #    judge "haveged start"

    #    sed -i -r '/^HRNGDEVICE/d;/#HRNGDEVICE=\/dev\/null/a HRNGDEVICE=/dev/urandom' /etc/default/rng-tools

    if [[ "${ID}" == "centos" ]]; then
        #       systemctl start rngd && systemctl enable rngd
        #       judge "rng-tools start"
        systemctl start haveged && systemctl enable haveged
        #       judge "haveged start"
    else
        #       systemctl start rng-tools && systemctl enable rng-tools
        #       judge "rng-tools start"
        systemctl start haveged && systemctl enable haveged
        #       judge "haveged start"
    fi
}

basic_optimization() {
    # Maximum number of open files 
    sed -i '/^\*\ *soft\ *nofile\ *[[:digit:]]*/d' /etc/security/limits.conf
    sed -i '/^\*\ *hard\ *nofile\ *[[:digit:]]*/d' /etc/security/limits.conf
    echo '* soft nofile 65536' >>/etc/security/limits.conf
    echo '* hard nofile 65536' >>/etc/security/limits.conf

    # Disable Selinux
    if [[ "${ID}" == "centos" ]]; then
        sed -i 's/^SELINUX=.*/SELINUX=disabled/' /etc/selinux/config
        setenforce 0
    fi

}

port_alterid_set() {
    if [[ "on" != "$old_config_status" ]]; then
        read -rp "Please enter the connection port（default:443）:" port
        [[ -z ${port} ]] && port="443"
        read -rp "Please enter alterID (default:0 only allows numbers):" alterID
        [[ -z ${alterID} ]] && alterID="0"
    fi
}

port_set() {

 # Changed to Automatically set the port to 443
 port="443"

}

stop_service() {
    systemctl stop nginx
    systemctl stop xray
    echo -e "${OK} ${GreenBG} Stop existing service ${Font}"
}

alterid_set() {
    if [[ "on" != "$old_config_status" ]]; then
        read -rp "Please enter alterID (default:0 only allows numbers):" alterID
        [[ -z ${alterID} ]] && alterID="0"
    fi
}

modify_path() {
    if [[ "on" == "$old_config_status" ]]; then
        camouflage="$(grep '\"path\"' $xray_qr_config_file | awk -F '"' '{print $4}')"
    fi
    if [[ "$shell_mode" != "xtls" ]]; then
        sed -i "/\"path\"/c \\\t\\t\"path\":\"${camouflage}\"" ${xray_conf}
    else
        echo -e "${Warning} ${YellowBG} xtls does not support path ${Font}"
    fi
    judge "Xray camouflage path modification"
}

modify_alterid() {
    if [[ $(grep -ic 'VLESS' ${xray_conf}) == 0 ]]; then
        if [[ "on" == "$old_config_status" ]]; then
            alterID="$(grep '\"aid\"' $xray_qr_config_file | awk -F '"' '{print $4}')"
        fi
        sed -i "/\"alterId\"/c \\\t\\t\\t\\t\"alterId\":${alterID}" ${xray_conf}
        judge "Xray alterid modification"
        [ -f ${xray_qr_config_file} ] && sed -i "/\"aid\"/c \\  \"aid\": \"${alterID}\"," ${xray_qr_config_file}
        echo -e "${OK} ${GreenBG} alterID:${alterID} ${Font}"
    else
        echo -e "${Warning} ${YellowBG} VLESS does not support modifying alterid ${Font}"
    fi
}
modify_inbound_port() {
    if [[ "on" == "$old_config_status" ]]; then
        port="$(info_extraction '\"port\"')"
    fi
    if [[ "$shell_mode" != "xtls" ]]; then
        PORT=$((RANDOM + 10000))
        #        sed -i "/\"port\"/c  \    \"port\":${PORT}," ${xray_conf}
        sed -i "8c\\\t\\t\"port\":${PORT}," ${xray_conf}
    else
        #        sed -i "/\"port\"/c  \    \"port\":${port}," ${xray_conf}
        sed -i "8c\\\t\\t\"port\":${port}," ${xray_conf}
    fi
    judge "Xray inbound_port modification"
}

modify_UUID() {
    [ -z "$UUID" ] && UUID=$(cat /proc/sys/kernel/random/uuid)
    if [[ "on" == "$old_config_status" ]]; then
        UUID="$(info_extraction '\"id\"')"
    fi
    sed -i "/\"id\"/c \\\t\\t\\t\\t\"id\":\"${UUID}\"," ${xray_conf}
    judge "Xray UUID modification"
    [ -f ${xray_qr_config_file} ] && sed -i "/\"id\"/c \\  \"id\": \"${UUID}\"," ${xray_qr_config_file}
    echo -e "${OK} ${GreenBG} UUID:${UUID} ${Font}"
}

modify_nginx_port() {
    if [[ "on" == "$old_config_status" ]]; then
        port="$(info_extraction '\"port\"')"
    fi
    sed -i "/ssl http2;$/c \\\tlisten ${port} ssl http2;" ${nginx_conf}
    sed -i "4c \\\t\\tlisten [::]:${port} ssl http2;" ${nginx_conf}
    judge "Xray port modification"
    [ -f ${xray_qr_config_file} ] && sed -i "/\"port\"/c \\  \"port\": \"${port}\"," ${xray_qr_config_file}
    echo -e "${OK} ${GreenBG} Port number: ${port} ${Font}"
}

modify_nginx_other() {
    sed -i "/server_name/c \\\t\\tserver_name ${domain};" ${nginx_conf}
    if [[ "$shell_mode" != "xtls" ]]; then
        sed -i "/location/c \\\tlocation ${camouflage}" ${nginx_conf}
        sed -i "/proxy_pass/c \\\tproxy_pass http://127.0.0.1:${PORT};" ${nginx_conf}
    fi
    sed -i "/return/c \\\t\\treturn 301 https://${domain}\$request_uri;" ${nginx_conf}
    sed -i "/returc/c \\\t\\treturn 302 https://www.voxer.com;" ${nginx_conf}
    sed -i "/locatioc/c \\\t\\tlocation \/" ${nginx_conf}
    #sed -i "/#gzip  on;/c \\\t#gzip  on;\\n\\tserver_tokens off;" ${nginx_dir}/conf/nginx.conf
    #sed -i "/\\tserver_tokens off;\\n\\tserver_tokens off;/c \\\tserver_tokens off;" ${nginx_dir}/conf/nginx.conf
    sed -i "s/        server_name  localhost;/\t\tserver_name  localhost;\n\n\t\tif (\$host = '${local_ip}'){\n\t\t\treturn 302 https:\/\/www.voxer.com\/individuals;\n\t\t}\n/" ${nginx_dir}/conf/nginx.conf
    #sed -i "27i \\\tproxy_intercept_errors on;"  ${nginx_dir}/conf/nginx.conf
}

web_camouflage() {
    ##Please note that this conflicts with the default path of the LNMP script. Do not use this script in an environment where LNMP is installed, otherwise you will be responsible for the consequences 
    rm -rf /home/wwwroot
    mkdir -p /home/wwwroot
    cd /home/wwwroot || exit
    #git clone https://github.com/wulabing/3DCEList.git
    judge "web site camouflage"
}
xray_privilege_escalation() {
    if [[ -n "$(grep "User=nobody" ${xray_systemd_file})" ]]; then
        #echo -e "${OK} ${GreenBG} Insufficient Xray permissions are detected, and Xray permissions will be increased to root ${Font}"
        echo -e "${OK} ${GreenBG} Xray's permission control is detected, start the wiping program ${Font}"
        systemctl stop xray
        #sed -i "s/User=nobody/User=root/" ${xray_systemd_file}
        chmod -fR a+rw /var/log/xray/
        chown -fR nobody:nobody /var/log/xray/
        chown -f nobody:nobody /data/xray.crt
        chown -f nobody:nobody /data/xray.key
        systemctl daemon-reload
        systemctl start xray
        sleep 1
    fi
}

xray_install() {
    if [[ -d /root/xray ]]; then
        rm -rf /root/xray
    fi
    if [[ -d /usr/local/etc/xray ]]; then
        rm -rf /usr/local/etc/xray
    fi
    if [[ -d /usr/local/share/xray ]]; then
        rm -rf /usr/local/share/xray
    fi
    mkdir -p /root/xray
    cd /root/xray || exit
    wget -N --no-check-certificate https://raw.githubusercontent.com/johndesu090/Project-XRay/master/vless/xrayinstall.sh
    #wget -N --no-check-certificate https://raw.githubusercontent.com/XTLS/Xray-install/main/install-dat-release.sh

    ## wget http://install.direct/go.sh
	
	# Add XMENU to system to provide UUID menu
	wget -O /usr/local/sbin/xmenu https://raw.githubusercontent.com/johndesu090/Project-XRay/master/dev/xmenu
	chmod +x /usr/local/sbin/xmenu

    ##if [[ -f xrayinstall.sh ]] && [[ -f install-dat-release.sh ]]; then
    if [[ -f xrayinstall.sh ]]; then
        rm -rf ${xray_systemd_file}
        rm -rf ${xray_systemd_file2}
        rm -rf ${xray_systemd_filed}
        rm -rf ${xray_systemd_filed2}
        systemctl daemon-reload
        bash xrayinstall.sh --force
        #bash install-dat-release.sh --force
        judge "Install Xray"
        sleep 1
        xray_privilege_escalation
    else
        echo -e "${Error} ${RedBG} Xray installation file download failed, please check if the download address is available ${Font}"
        exit 4
    fi
    # Clear temporary files 
    rm -rf /root/xray
}

xray_update() {
    #mkdir -p /root/xray
    #cd /root/xray || exit
    #wget -N --no-check-certificate https://raw.githubusercontent.com/XTLS/Xray-install/main/install-release.sh
    #wget -N --no-check-certificate https://raw.githubusercontent.com/XTLS/Xray-install/main/install-dat-release.sh
    if [[ -d /usr/local/etc/xray ]]; then
        #echo -e "${OK} ${GreenBG} Restore the original permissions of xray ${Font}"
        systemctl stop xray
        #sed -i "s/User=root/User=nobody/" ${xray_systemd_file}
        #systemctl daemon-reload
        #systemctl start xray
        sleep 1
        bash <(curl -L -s https://raw.githubusercontent.com/johndesu090/Project-XRay/master/vless/xrayinstall.sh)
        sleep 1
        xray_privilege_escalation
    else
        echo -e "${GreenBG} If the update is invalid, it is recommended to uninstall and then install it directly! ${Font}"
        systemctl stop xray
        #systemctl disable xray.service --now
        #mv -f /etc/xray/ /usr/local/etc/
        #rm -rf /usr/bin/xray/
        #rm -rf /etc/systemd/system/xray.service
        #rm -rf /lib/systemd/system/xray@.service
        #rm -rf /etc/init.d/xray
        #systemctl daemon-reload
        sleep 1
        bash <(curl -L -s https://raw.githubusercontent.com/johndesu090/Project-XRay/master/vless/xrayinstall.sh)
        sleep 1
        xray_privilege_escalation
    fi
    # Clear temporary files 
    ##rm -rf /root/xray
}

nginx_exist_check() {
    if [[ -f "/etc/nginx/sbin/nginx" ]]; then
        if [[ -d ${nginx_dir}/conf/conf.d ]]; then
            rm -rf ${nginx_dir}/conf/conf.d/*
        else
            mkdir ${nginx_dir}/conf/conf.d
        fi
        echo -e "${OK} ${GreenBG} Nginx already exists, skip the compilation and installation process ${Font}"
        sleep 2
    elif [[ -d "/usr/local/nginx/" ]]; then
        echo -e "${OK} ${GreenBG} Nginx installed by other packages is detected. If you continue to install it, it will cause conflicts. Please install after handling. ${Font}"
        exit 1
    else
        nginx_install
    fi
}

nginx_install() {
    #    if [[ -d "/etc/nginx" ]];then
    #        rm -rf /etc/nginx
    #    fi

    wget -nc --no-check-certificate http://nginx.org/download/nginx-${nginx_version}.tar.gz -P ${nginx_openssl_src}
    judge "Nginx download"
    wget -nc --no-check-certificate https://www.openssl.org/source/openssl-${openssl_version}.tar.gz -P ${nginx_openssl_src}
    judge "openssl download"
    wget -nc --no-check-certificate https://github.com/jemalloc/jemalloc/releases/download/${jemalloc_version}/jemalloc-${jemalloc_version}.tar.bz2 -P ${nginx_openssl_src}
    judge "jemalloc download"

    cd ${nginx_openssl_src} || exit

    [[ -d nginx-"$nginx_version" ]] && rm -rf nginx-"$nginx_version"
    tar -zxvf nginx-"$nginx_version".tar.gz

    [[ -d openssl-"$openssl_version" ]] && rm -rf openssl-"$openssl_version"
    tar -zxvf openssl-"$openssl_version".tar.gz

    [[ -d jemalloc-"${jemalloc_version}" ]] && rm -rf jemalloc-"${jemalloc_version}"
    tar -xvf jemalloc-"${jemalloc_version}".tar.bz2

    [[ -d "$nginx_dir" ]] && rm -rf ${nginx_dir}

    echo -e "${OK} ${GreenBG} About to start compiling and installing jemalloc ${Font}"
    sleep 2

    cd jemalloc-${jemalloc_version} || exit
    ./configure
    judge "Compile check"
    make -j "${THREAD}" && make install
    judge "jemalloc compile and install"
    echo '/usr/local/lib' >/etc/ld.so.conf.d/local.conf
    ldconfig

    echo -e "${OK} ${GreenBG} Compilation and installation of Nginx will begin soon, the process will take a little longer, please be patient ${Font}"
    sleep 4

    cd ../nginx-${nginx_version} || exit

    # Add http_sub_module to replace keywords with reverse proxy 
    ./configure --prefix="${nginx_dir}" \
    --with-http_ssl_module \
    --with-http_gzip_static_module \
    --with-http_stub_status_module \
    --with-pcre \
    --with-http_realip_module \
    --with-http_flv_module \
    --with-http_mp4_module \
    --with-http_realip_module \
    --with-http_secure_link_module \
    --with-http_sub_module \
    --with-http_v2_module \
    --with-cc-opt='-O3' \
    --with-ld-opt="-ljemalloc" \
    --with-openssl=../openssl-"$openssl_version"
    judge "Compile check"
    make -j "${THREAD}" && make install
    judge "Nginx compile and install"

    # Modify the basic configuration 
    sed -i 's/#user  nobody;/user  root;/' ${nginx_dir}/conf/nginx.conf
    sed -i 's/worker_processes  1;/worker_processes  4;/' ${nginx_dir}/conf/nginx.conf
    sed -i 's/    worker_connections  1024;/    worker_connections  4096;/' ${nginx_dir}/conf/nginx.conf
    sed -i '$i include conf.d/*.conf;' ${nginx_dir}/conf/nginx.conf

    # Delete temporary files 
    rm -rf ../nginx-"${nginx_version}"
    rm -rf ../openssl-"${openssl_version}"
    rm -rf ../nginx-"${nginx_version}".tar.gz
    rm -rf ../openssl-"${openssl_version}".tar.gz

    # Add a configuration folder to adapt to the old script
    mkdir ${nginx_dir}/conf/conf.d
}

ssl_install() {
    if [[ "${ID}" == "centos" ]]; then
        ${INS} install socat nc -y
    else
        ${INS} install socat netcat -y
    fi
    judge "Install SSL certificate generation script dependency"

    curl https://get.acme.sh | sh
    judge "Install the SSL certificate generation script"
}

domain_check() {
    read -rp "Please enter your domain name information (ex: johnfordtv.com):" domain
    echo "Please select public IP as IPv4 or IPv6"
    echo "1: IPv4 (default)"
    echo "2: IPv6 (not recommended)"
    read -rp "Please enter：" ip_version
    [[ -z ${ip_version} ]] && ip_version=1
    echo -e "${OK} ${GreenBG} Obtaining public IP information, please wait patiently ${Font}"
    if [[ $ip_version == 1 ]]; then
        local_ip=$(curl https://api-ipv4.ip.sb/ip)
        domain_ip=$(ping -4 "${domain}" -c 1 | sed '1{s/[^(]*(//;s/).*//;q}')
    elif [[ $ip_version == 2 ]]; then
        local_ip=$(curl https://api-ipv6.ip.sb/ip)
        domain_ip=$(ping -6 "${domain}" -c 1 | sed '1{s/[^(]*(//;s/).*//;q}')
    else
        local_ip=$(curl https://api-ipv4.ip.sb/ip)
        domain_ip=$(ping -4 "${domain}" -c 1 | sed '1{s/[^(]*(//;s/).*//;q}')
    fi
    echo -e "Domain name dns resolve IP：${domain_ip}"
    echo -e "Local IP:${local_ip}"
    sleep 2
    if [[ ${local_ip} == ${domain_ip} ]]; then
        echo -e "${OK} ${GreenBG} Domain name dns resolution IP matches the local IP ${Font}"
        sleep 2
    else
        echo -e "${Error} ${RedBG} Please make sure that the correct A/AAAA record is added to the domain name, otherwise XRay cannot be used normally ${Font}"
        echo -e "${Error} ${RedBG} The DNS resolution IP of the domain name does not match the local IP. Do you want to continue the installation?（y/n）${Font}" && read -r install
        case $install in
        [yY][eE][sS] | [yY])
            echo -e "${GreenBG} Continue to install ${Font}"
            sleep 2
            ;;
        *)
            echo -e "${RedBG} Installation terminated ${Font}"
            exit 2
            ;;
        esac
    fi
}

port_exist_check() {
    if [[ 0 -eq $(lsof -i:"$1" | grep -i -c "listen") ]]; then
        echo -e "${OK} ${GreenBG} $1 port is not occupied ${Font}"
        sleep 1
    else
        echo -e "${Error} ${RedBG}It is detected that the $1 port is occupied, the following is the occupation information of the $1 port ${Font}"
        lsof -i:"$1"
        echo -e "${OK} ${GreenBG} After 5s, it will try to kill the occupied process automatically ${Font}"
        sleep 5
        lsof -i:"$1" | awk '{print $2}' | grep -v "PID" | xargs kill -9
        echo -e "${OK} ${GreenBG} kill complete ${Font}"
        sleep 1
    fi
}

acme() {
    if "$HOME"/.acme.sh/acme.sh --issue -d "${domain}" --standalone -k ec-256 --force --test; then
        echo -e "${OK} ${GreenBG} The SSL certificate test issuance is successful, and the official issuance begins ${Font}"
        rm -rf "$HOME/.acme.sh/${domain}_ecc"
        sleep 2
    else
        echo -e "${Error} ${RedBG} SSL certificate test issuance failed ${Font}"
        rm -rf "$HOME/.acme.sh/${domain}_ecc"
        exit 1
    fi

    if "$HOME"/.acme.sh/acme.sh --issue -d "${domain}" --standalone -k ec-256 --force; then
        echo -e "${OK} ${GreenBG} SSL certificate generated successfully ${Font}"
        sleep 2
        mkdir /data
        if "$HOME"/.acme.sh/acme.sh --installcert -d "${domain}" --fullchainpath /data/xray.crt --keypath /data/xray.key --ecc --force; then
            chmod -f a+rw /data/xray.crt
            chmod -f a+rw /data/xray.key
            chown -f nobody:nobody /data/xray.crt
            chown -f nobody:nobody /data/xray.key
            echo -e "${OK} ${GreenBG} Certificate configuration is successful ${Font}"
            sleep 2
        fi
    else
        echo -e "${Error} ${RedBG} SSL certificate generation failed ${Font}"
        rm -rf "$HOME/.acme.sh/${domain}_ecc"
        exit 1
    fi
}

xray_conf_add_tls() {
    cd ${xray_conf_dir} || exit
    wget --no-check-certificate https://raw.githubusercontent.com/johndesu090/Project-XRay/master/tls/config.json -O config.json
    modify_path
    modify_alterid
    modify_inbound_port
    modify_UUID
}

xray_conf_add_xtls() {
    cd ${xray_conf_dir} || exit
    wget --no-check-certificate https://raw.githubusercontent.com/johndesu090/Project-XRay/main/xtls/config.json -O config.json
    modify_path
    modify_alterid
    modify_inbound_port
    modify_UUID
}

old_config_exist_check() {
    if [[ -f $xray_qr_config_file ]]; then
        echo -e "${OK} ${GreenBG} The old configuration file is detected, whether to read the old file configuration [Y/N]? ${Font}"
        read -r ssl_delete
        case $ssl_delete in
        [yY][eE][sS] | [yY])
            echo -e "${OK} ${GreenBG} Old configuration has been retained ${Font}"
            old_config_status="on"
            port=$(info_extraction '\"port\"')
            ;;
        *)
            rm -rf $xray_qr_config_file
            echo -e "${OK} ${GreenBG} Old configuration deleted ${Font}"
            ;;
        esac
    fi
}

nginx_conf_add() {
    touch ${nginx_conf_dir}/xray.conf
    cat >${nginx_conf_dir}/xray.conf <<EOF
    server_tokens off;
    server {
        listen 443 ssl http2;
        listen [::]:443 ssl http2;
        ssl_certificate       /data/xray.crt;
        ssl_certificate_key   /data/xray.key;
        ssl_protocols         TLSv1.3;
        ssl_ciphers           TLS13-AES-128-GCM-SHA256:TLS13-AES-256-GCM-SHA384:TLS13-CHACHA20-POLY1305-SHA256:TLS13-AES-128-CCM-8-SHA256:TLS13-AES-128-CCM-SHA256:EECDH+CHACHA20:EECDH+CHACHA20-draft:EECDH+ECDSA+AES128:EECDH+aRSA+AES128:RSA+AES128:EECDH+ECDSA+AES256:EECDH+aRSA+AES256:RSA+AES256:EECDH+ECDSA+3DES:EECDH+aRSA+3DES:RSA+3DES:!MD5;
        server_name           serveraddr.com;
        index index.html index.htm;
        #root  /home/wwwroot/3DCEList;
        root /400.html;
        error_page 400 https://css-tricks.com/thispagedoesntexist;
        # Config for 0-RTT in TLSv1.3
        ssl_early_data on;
        ssl_stapling on;
        ssl_stapling_verify on;
        add_header Strict-Transport-Security "max-age=31536000";

        location /ray/
        {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:10000;
        proxy_http_version 1.1;
        proxy_connect_timeout 180s;
        proxy_send_timeout 180s;
        proxy_read_timeout 1800s;
        proxy_buffering off;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;

        # Config for 0-RTT in TLSv1.3
        proxy_set_header Early-Data \$ssl_early_data;
        }
        locatioc
        {
        returc
        }
    }
    server {
        listen 80;
        listen [::]:80;
        server_name serveraddr.com;
        return 301 https://use.shadowsocksr.win\$request_uri;
    }
EOF

    modify_nginx_port
    modify_nginx_other
    judge "Nginx configuration modification"
}

nginx_conf_add_xtls() {
    touch ${nginx_conf_dir}/xray.conf
    cat >${nginx_conf_dir}/xray.conf <<EOF
    server_tokens off;
    server {
        listen 127.0.0.1:8080 proxy_protocol;
        server_name serveraddr.com;
        set_real_ip_from 127.0.0.1;
        real_ip_header    X-Forwarded-For;
        real_ip_recursive on;
        add_header Strict-Transport-Security "max-age=63072000" always;
        locatioc
        {
        returc
        }
    }
    server {
        listen 80;
        listen [::]:80;
        server_name serveraddr.com;
        return 301 https://use.shadowsocksr.win\$request_uri;
    }
EOF

    modify_nginx_other
    judge "Nginx configuration modification"
}

start_process_systemd() {
    systemctl daemon-reload
    systemctl restart nginx
    judge "Nginx start up"
    systemctl restart xray
    judge "Xray start up"
}

enable_process_systemd() {
    systemctl enable xray
    judge "Set xray to start automatically after booting"
    systemctl enable nginx
    judge "Set Nginx to start automatically after booting"
}

stop_process_systemd() {
    if [[ "$shell_mode" != "xtls" ]]; then
        systemctl stop nginx
    fi
    systemctl stop xray
}
nginx_process_disabled() {
    [ -f $nginx_systemd_file ] && systemctl stop nginx && systemctl disable nginx
}

#debian 系 9 10 适配
#rc_local_initialization(){
#    if [[ -f /etc/rc.local ]];then
#        chmod +x /etc/rc.local
#    else
#        touch /etc/rc.local && chmod +x /etc/rc.local
#        echo "#!/bin/bash" >> /etc/rc.local
#        systemctl start rc-local
#    fi
#
#    judge "rc.local 配置"
#}

acme_cron_update() {
    wget -N -P /usr/bin/johnfordtv-xray --no-check-certificate "https://raw.githubusercontent.com/johndesu090/Project-XRay/master/tls/ssl_update.sh"
    if [[ $(crontab -l | grep -c "ssl_update.sh") -lt 1 ]]; then
        if [[ "${ID}" == "centos" ]]; then
            #        sed -i "/acme.sh/c 0 3 * * 0 \"/root/.acme.sh\"/acme.sh --cron --home \"/root/.acme.sh\" \
            #        &> /dev/null" /var/spool/cron/root
            sed -i "/acme.sh/c 0 3 * * 0 bash ${ssl_update_file}" /var/spool/cron/root
        else
            #        sed -i "/acme.sh/c 0 3 * * 0 \"/root/.acme.sh\"/acme.sh --cron --home \"/root/.acme.sh\" \
            #        &> /dev/null" /var/spool/cron/crontabs/root
            sed -i "/acme.sh/c 0 3 * * 0 bash ${ssl_update_file}" /var/spool/cron/crontabs/root
        fi
    fi
    judge "cron scheduled task update"
}

vmess_qr_config_tls_ws() {
    cat >$xray_qr_config_file <<-EOF
{
  "v": "2",
  "ps": "${domain}",
  "add": "${domain}",
  "port": "${port}",
  "id": "${UUID}",
  "aid": "${alterID}",
  "net": "ws",
  "type": "none",
  "host": "${domain}",
  "path": "${camouflage}",
  "tls": "tls"
}
EOF
}

vmess_qr_config_xtls() {
    cat >$xray_qr_config_file <<-EOF
{
  "v": "2",
  "ps": "${domain}",
  "add": "${domain}",
  "port": "${port}",
  "id": "${UUID}",
  "aid": "${alterID}",
  "net": "tcp",
  "type": "none",
  "host": "${domain}",
  "tls": "xtls"
}
EOF
}

vmess_qr_link_image() {
    vmess_link="vmess://$(base64 -w 0 $xray_qr_config_file)"
    echo -e "${OK} ${GreenBG} VLESS currently does not have a sharing link specification. Please manually copy and paste the configuration information to the client ${Font}"

}

vmess_quan_link_image() {
    echo "$(info_extraction '\"ps\"') = vmess, $(info_extraction '\"add\"'), \
    $(info_extraction '\"port\"'), chacha20-ietf-poly1305, "\"$(info_extraction '\"id\"')\"", over-tls=true, \
    certificate=1, obfs=ws, obfs-path="\"$(info_extraction '\"path\"')\"", " >/tmp/vmess_quan.tmp
    vmess_link="vmess://$(base64 -w 0 /tmp/vmess_quan.tmp)"
    echo -e "${OK} ${GreenBG} VLESS currently does not have a sharing link specification. Please manually copy and paste the configuration information to the client ${Font}"

}

vmess_link_image_choice() {
    echo "Please select the generated link type"
    echo "1: V2RayNG/V2RayN"
    #echo "2: quantumult"
    read -rp "Please enter：" link_version
    [[ -z ${link_version} ]] && link_version=1
    if [[ $link_version == 1 ]]; then
        vmess_qr_link_image
    #elif [[ $link_version == 2 ]]; then
    #    vmess_quan_link_image
    else
        vmess_qr_link_image
    fi
}

info_extraction() {
    grep "$1" $xray_qr_config_file | awk -F '"' '{print $4}'
}

basic_information() {
    {
        if [[ "$shell_mode" != "xtls" ]]; then
            echo -e "${OK} ${GreenBG} Xray+ws+tls installed successfully ${Font}"
        else
            echo -e "${OK} ${GreenBG} Xray+Nginx installed successfully ${Font}"
        fi
        echo -e "${Red} Xray configuration information${Font}"
        echo -e "${Red} Address（address）:${Font} $(info_extraction '\"add\"') "
        echo -e "${Red} Port（port）：${Font} $(info_extraction '\"port\"') "
        echo -e "${Red} User id（UUID）：${Font} $(info_extraction '\"id\"')"

        if [[ $(grep -ic 'VLESS' ${xray_conf}) == 0 ]]; then
            echo -e "${Red} Extra id（alterId）：${Font} $(info_extraction '\"aid\"')"
        fi

        echo -e "${Red} Encryption（encryption）：${Font} none "
        echo -e "${Red} Transfer Protocol（network）：${Font} $(info_extraction '\"net\"') "
        echo -e "${Red} Camouflage type（type）：${Font} none "
        if [[ "$shell_mode" != "xtls" ]]; then
            echo -e "${Red} Path (don't drop/):${Font} $(info_extraction '\"path\"') "
            echo -e "${Red} Underlying transmission security：${Font} tls "
        else
            echo -e "${Red} Flow Control (flow)：${Font} xtls-rprx-direct "
            echo -e "${Red} Underlying transmission security：${Font} xtls "
        fi
    } >"${xray_info_file}"
}

show_information() {
    cat "${xray_info_file}"
}

ssl_judge_and_install() {
    if [[ -f "/data/xray.key" || -f "/data/xray.crt" ]]; then
        echo "/data The certificate file in the directory already exists"
        echo -e "${OK} ${GreenBG} Delete or Not [Y/N]? ${Font}"
        read -r ssl_delete
        case $ssl_delete in
        [yY][eE][sS] | [yY])
            delete_tls_key_and_crt
            rm -rf /data/*
            echo -e "${OK} ${GreenBG} Deleted ${Font}"
            ;;
        *) ;;

        esac
    fi

    if [[ -f "/data/xray.key" || -f "/data/xray.crt" ]]; then
        echo "The certificate file already exists"
    elif [[ -f "$HOME/.acme.sh/${domain}_ecc/${domain}.key" && -f "$HOME/.acme.sh/${domain}_ecc/${domain}.cer" ]]; then
        echo "The certificate file already exists"
        "$HOME"/.acme.sh/acme.sh --installcert -d "${domain}" --fullchainpath /data/xray.crt --keypath /data/xray.key --ecc
        judge "Certificate application"
    else
        ssl_install
        acme
    fi
}

nginx_systemd() {
    cat >$nginx_systemd_file <<EOF
[Unit]
Description=The NGINX HTTP and reverse proxy server
After=syslog.target network.target remote-fs.target nss-lookup.target

[Service]
Type=forking
PIDFile=/etc/nginx/logs/nginx.pid
ExecStartPre=/etc/nginx/sbin/nginx -t
ExecStart=/etc/nginx/sbin/nginx -c ${nginx_dir}/conf/nginx.conf
ExecReload=/etc/nginx/sbin/nginx -s reload
ExecStop=/bin/kill -s QUIT \$MAINPID
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

    judge "Nginx systemd ServerFile added"
    systemctl daemon-reload
}

tls_type() {
    if [[ -f "/etc/nginx/sbin/nginx" ]] && [[ -f "$nginx_conf" ]] && [[ "$shell_mode" == "ws" ]]; then
        echo "Please select a supported TLS version （default:2）:"
        echo "It is recommended to choose TLS1.2 and TLS1.3 compatibility mode"
        echo "1: TLS1.1 TLS1.2 and TLS1.3（Compatibility mode）"
        echo "2: TLS1.2 and TLS1.3 (Compatibility mode)"
        echo "3: TLS1.3 only"
        read -rp "Please enter：" tls_version
        [[ -z ${tls_version} ]] && tls_version=2
        if [[ $tls_version == 3 ]]; then
            sed -i 's/ssl_protocols.*/ssl_protocols         TLSv1.3;/' $nginx_conf
            echo -e "${OK} ${GreenBG} Switched to TLS1.3 only ${Font}"
        elif [[ $tls_version == 1 ]]; then
            sed -i 's/ssl_protocols.*/ssl_protocols         TLSv1.1 TLSv1.2 TLSv1.3;/' $nginx_conf
            echo -e "${OK} ${GreenBG} Switched to TLS1.1 TLS1.2 and TLS1.3 ${Font}"
        else
            sed -i 's/ssl_protocols.*/ssl_protocols         TLSv1.2 TLSv1.3;/' $nginx_conf
            echo -e "${OK} ${GreenBG} Switched to TLS1.2 and TLS1.3 ${Font}"
        fi
        systemctl restart nginx
        judge "Nginx restart"
    else
        echo -e "${Error} ${RedBG} Nginx or the configuration file does not exist or the currently installed version is xtls, please execute it after installing the script correctly${Font}"
    fi
}

show_access_log() {
    [ -f ${xray_access_log} ] && tail -f ${xray_access_log} || echo -e "${RedBG}log file does not exist ${Font}"
}

show_error_log() {
    [ -f ${xray_error_log} ] && tail -f ${xray_error_log} || echo -e "${RedBG}log file does not exist ${Font}"
}

ssl_update_manuel() {
    [ -f ${amce_sh_file} ] && "/root/.acme.sh"/acme.sh --cron --home "/root/.acme.sh" || echo -e "${RedBG}The certificate issuance tool does not exist, please confirm whether you have used your own certificate${Font}"
    domain="$(info_extraction '\"add\"')"
    "$HOME"/.acme.sh/acme.sh --installcert -d "${domain}" --fullchainpath /data/xray.crt --keypath /data/xray.key --ecc
}

bbr_boost_sh() {
    [ -f "tcp.sh" ] && rm -rf ./tcp.sh
    wget -N --no-check-certificate "https://raw.githubusercontent.com/ylx2016/Linux-NetSpeed/master/tcp.sh" && chmod +x tcp.sh && ./tcp.sh
}

mtproxy_sh() {
    wget -N --no-check-certificate "https://github.com/whunt1/onekeymakemtg/raw/master/mtproxy_go.sh" && chmod +x mtproxy_go.sh && bash mtproxy_go.sh
}

uninstall_all() {
    stop_process_systemd
    systemctl disable xray
    [[ -f $nginx_systemd_file ]] && rm -f $nginx_systemd_file
    [[ -f $xray_systemd_file ]] && rm -f $xray_systemd_file
    [[ -f $xray_systemd_file2 ]] && rm -f $xray_systemd_file2
    [[ -d $xray_systemd_filed ]] && rm -f $xray_systemd_filed
    [[ -d $xray_systemd_filed2 ]] && rm -f $xray_systemd_filed2
    [[ -f $xray_bin_dir ]] && rm -rf $xray_bin_dir
    if [[ -d $nginx_dir ]]; then
        echo -e "${OK} ${Green} Uninstall Nginx [Y/N]? ${Font}"
        read -r uninstall_nginx
        case $uninstall_nginx in
        [yY][eE][sS] | [yY])
            rm -rf $nginx_dir
            echo -e "${OK} ${Green} Nginx uninstalled ${Font}"
            ;;
        *) ;;

        esac
    fi
    [[ -d $xray_conf_dir ]] && rm -rf $xray_conf_dir
    [[ -d $web_dir ]] && rm -rf $web_dir
    systemctl daemon-reload
    echo -e "${OK} ${GreenBG}Has been uninstalled, the SSL certificate file has been retained ${Font}"
}

delete_tls_key_and_crt() {
    [[ -f $HOME/.acme.sh/acme.sh ]] && /root/.acme.sh/acme.sh uninstall >/dev/null 2>&1
    [[ -d $HOME/.acme.sh ]] && rm -rf "$HOME/.acme.sh"
    echo -e "${OK} ${GreenBG}The remaining certificate files have been emptied ${Font}"
}

judge_mode() {
    if [ -f $xray_bin_dir ]; then
        if grep -q "ws" $xray_qr_config_file; then
            shell_mode="ws"
        elif grep -q "xtls" $xray_qr_config_file; then
            shell_mode="xtls"
        fi
    fi
}

install_xray_ws_tls() {
    is_root
    check_system
    banner_install
    dependency_install
    basic_optimization
    domain_check
    old_config_exist_check
    port_set
    stop_service
    xray_install
    port_exist_check 80
    port_exist_check "${port}"
    nginx_exist_check
    xray_conf_add_tls
    nginx_conf_add
    web_camouflage
    ssl_judge_and_install
    nginx_systemd
    vmess_qr_config_tls_ws
    basic_information
    vmess_link_image_choice
    tls_type
    start_process_systemd
    enable_process_systemd
    acme_cron_update
	show_information
}

install_v2_xtls() {
    is_root
    check_system
    banner_install
    dependency_install
    basic_optimization
    domain_check
    old_config_exist_check
    port_set
    stop_service
    xray_install
    port_exist_check 80
    port_exist_check "${port}"
    nginx_exist_check
    nginx_conf_add_xtls
    xray_conf_add_xtls
    ssl_judge_and_install
    nginx_systemd
    vmess_qr_config_xtls
    basic_information
    vmess_qr_link_image
    start_process_systemd
    enable_process_systemd
    acme_cron_update
	show_information
}

update_sh() {
    ol_version=$(curl -L -s https://raw.githubusercontent.com/johndesu090/Project-XRay/master/install.sh | grep "shell_version=" | head -1 | awk -F '=|"' '{print $3}')
    echo "$ol_version" >$version_cmp
    echo "$shell_version" >>$version_cmp
    if [[ "$shell_version" < "$(sort -rV $version_cmp | head -1)" ]]; then
        echo -e "${OK} ${GreenBG} There is a new version, update[Y/N]? ${Font}"
        read -r update_confirm
        case $update_confirm in
        [yY][eE][sS] | [yY])
            rm -f ${johnfordtv_commend_file}
            wget -N --no-check-certificate -P ${johnfordtv_xray_dir} https://raw.githubusercontent.com/johndesu090/Project-XRay/master/install.sh && chmod +x ${johnfordtv_xray_dir}/install.sh
            ln -s ${johnfordtv_xray_dir}/install.sh ${johnfordtv_commend_file}
            echo -e "${OK} ${GreenBG} Update completed${Font}"
            exit 0
            ;;
        *) ;;

        esac
    else
        echo -e "${OK} ${GreenBG} The current version is the latest version ${Font}"
    fi

}

maintain() {
    echo -e "${RedBG}This option is temporarily unavailable${Font}"
    echo -e "${RedBG}$1${Font}"
    exit 0
}

list() {
    case $1 in
    tls_modify)
        tls_type
        ;;
    uninstall)
        uninstall_all
        ;;
    crontab_modify)
        acme_cron_update
        ;;
    boost)
        bbr_boost_sh
        ;;
    *)
        menu
        ;;
    esac
}

johnfordtv_commend() {
    #Add management commands
    if [ -L "${johnfordtv_commend_file}" ]; then
        echo -e "${Green}Welcome to ${Red}JohnFordTV${Font} XRay management script\n${Font}"
    else
        if [ -L "/usr/local/bin/johnfordtv" ]; then
            rm -f /usr/local/bin/johnfordtv
        fi
        ln -s $(
            cd "$(dirname "$0")"
            pwd
        )/install.sh ${johnfordtv_commend_file}
        echo -e "${Green}Welcome to ${Red}JohnFordTV${Font} XRay management script\n${Font}"
    fi
}

menu() {
    update_sh
    echo -e "\t Xray installation management script ${Red}[${shell_version}]${Font}"
    echo -e "\t---authored by paniy---"
    echo -e "\t---changed by johnfordtv---"
    echo -e "\thttps://github.com/johnfordtv\n"
    echo -e "Currently installed version:${shell_mode}\n"

    johnfordtv_commend

    echo -e "—————————————— installation wizard ——————————————"""
    echo -e "${Green}0.${Font}  Upgrade script"
    echo -e "${Green}1.${Font}  Install Xray (Nginx+ws+tls)"
    echo -e "${Green}2.${Font}  Install Xray (xtls+Nginx)"
    echo -e "${Green}3.${Font}  Upgrade Xray "
    echo -e "—————————————— Configuration changes ——————————————"
    echo -e "${Green}4.${Font}  Change UUID"
    echo -e "${Green}5.${Font}  Change alterid"
    echo -e "${Green}6.${Font}  Change port"
    echo -e "${Green}7.${Font}  Change TLS Version (only ws+tls valid)"
    echo -e "—————————————— View information ——————————————"
    echo -e "${Green}8.${Font}  View real-time access log"
    echo -e "${Green}9.${Font}  View real-time error log"
    echo -e "${Green}10.${Font} View Xray configuration information"
    echo -e "—————————————— Other options ——————————————"
    echo -e "${Green}11.${Font} Install 4 in 1 bbr sharp speed installation script"
    echo -e "${Green}12.${Font} Install MTproxy (support TLS obfuscation)"
    echo -e "${Green}13.${Font} Certificate Validity Update"
    echo -e "${Green}14.${Font} Uninstall Xray"
    echo -e "${Green}15.${Font} Update certificate crontab scheduled task"
    echo -e "${Green}16.${Font} Empty certificate legacy files"
    echo -e "${Green}17.${Font} Exit \n"

    read -rp "Please enter the number：" menu_num
    case $menu_num in
    0)
        update_sh
        bash johnfordtv
        ;;
    1)
        shell_mode="ws"
        install_xray_ws_tls
        bash johnfordtv
        ;;
    2)
        shell_mode="xtls"
        install_v2_xtls
        bash johnfordtv
        ;;
    3)
        xray_update
        bash johnfordtv
        ;;
    4)
        read -rp "Please enter UUID:" UUID
        modify_UUID
        start_process_systemd
        bash johnfordtv
        ;;
    5)
        read -rp "Please enter alterID:" alterID
        modify_alterid
        start_process_systemd
        bash johnfordtv
        ;;
    6)
        read -rp "Please enter the connection port:" port
        if grep -q "ws" $xray_qr_config_file; then
            modify_nginx_port
        elif grep -q "xtls" $xray_qr_config_file; then
            modify_inbound_port
        fi
        start_process_systemd
        bash johnfordtv
        ;;
    7)
        tls_type
        bash johnfordtv
        ;;
    8)
        show_access_log
        bash johnfordtv
        ;;
    9)
        show_error_log
        bash johnfordtv
        ;;
    10)
        basic_information
        if [[ $shell_mode == "ws" ]]; then
            vmess_link_image_choice
        else
            vmess_qr_link_image
        fi
        show_information
        bash johnfordtv
        ;;
    11)
        bbr_boost_sh
        bash johnfordtv
        ;;
    12)
        mtproxy_sh
        bash johnfordtv
        ;;
    13)
        stop_process_systemd
        ssl_update_manuel
        start_process_systemd
        bash johnfordtv
        ;;
    14)
        uninstall_all
        bash johnfordtv
        ;;
    15)
        acme_cron_update
        bash johnfordtv
        ;;
    16)
        delete_tls_key_and_crt
        bash johnfordtv
        ;;
    17)
        exit 0
        ;;
    *)
        echo -e "${RedBG}Please enter the correct number${Font}"
        bash johnfordtv
        ;;
    esac
}

judge_mode
list "$1"
