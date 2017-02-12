#!/bin/bash
#
# Intrusion Script
# JeSTeR@H4CK3D.US
#
######################################################
######################################################
##_________ .__ Change         Below                ##
##\_   ___ \|  |__ _____    ____    ____   ____     ##
##/    \  \/|  |  \\__  \  /    \  / ___\_/ __ \    ##
##\     \___|   Y  \/ __ \|   |  \/ /_/  >  ___/    ##
## \______  /___|  (____  /___|  /\___  / \___  >   ##
##        \/     \/     \/     \//_____/      \/    ##
######################################################
######################################################
#Your Email And Other Needed Info
mymail="root@localhost" #Will End Up In /var/mail/root

#adduser BadName like $ adduser JeSTeR
#Things Simple Like Adding UPPER/lower case names
#Can Confuse Hackers And Make Things Alot Harder
badname="JeSTeR"

#Admin User (Like Root) Mine Is (user2="JeSTeR")
#Select permroot="no" And use this server as sudo
user2="Systemback" #This User Will Have Full 100% Access

#SSH Key Types (SHA256/md5)
hashkey="SHA256" #Change This To Prefered

#SSH Config ( * = ALL)
sship="123.456.789.012" #The IP Your Server Will Listen For SSH 
sshd="52529"  #The Port You Want SSH To Use
permroot="yes" #Permit root logins (yes/no)

#IRC Ports
irc1="6665"
irc2="6667"
irc3="6669"
irc4="7000"
irc5="7010"
irc6="7012"
#IRC SSL
irc7="6697"

#BlackList Subnets Or Single IPs
#Can Be In Synax Like (1.2.3.4/2.3.4.5 OR 1.2.3.4)
subnet="103.10.197.50/103.10.197.59"
subnet1="212.21.66.6/212.21.66.60"
subnet2="66.180.193.219"
####################################################
#           DO NOT TOUCH BELOW HERE                #
#              Changing Variables                  #
####################################################
####################################################
#           DO NOT TOUCH BELOW HERE                #
####################################################
version="v1.5.8"
DEFAULT_ROUTE=$(ip route show default | awk '/default/ {print $3}')
IFACE=$(ip route show | awk '(NR == 2) {print $3}')
myipad=$(curl -s checkip.dyndns.org | sed -e 's/.*Current IP Address: //' -e 's/<.*$//')
UserName=$(whoami)
LogDay=$(date '+%Y-%m-%d')
LogTime=$(date '+%Y-%m-%d %H:%M:%S')
LogFile=/var/log/uss_$LogDay.log
installit="Do you want to continue? (Y/N)"
iptables="iptables"
Creator="JeSTeR"
Email="JeSTeR@H4CK3D.US"
ircsrv="Chat.H4CK3D.Tech"
channle="#Expl0it"

####################################################
#           DO NOT TOUCH BELOW HERE                #
####################################################

if [ $UID -ne 0 ]; then
    echo -e "\033[34mThis program must be run as root or this will all fail.\033[m"
    sleep 3
    fi

###### Install script if not installed
if [ ! -e "/usr/bin/intrusion" ];then
	echo "Intrusion Script is not installed. Do you want to install it ? (Y/N)"
	read install
	if [[ $install = Y || $install = y ]] ; then
		cp -v $0 /usr/bin/intrusion
		chmod +x /usr/bin/intrusion
		#rm $0
		echo "Intrusion Script in installed. Launching it!"
		sleep 3
		intrusion
		exit 1
	else
		echo -e "\e[32m[-]If You Say So. Another Time Then\e[0m"
	fi
else
	echo "Intrusion Script is installed"
	sleep 1
fi
### End of install
### Install GitHub
if [ ! -e "/usr/bin/git" ];then
	echo "GitHub command git is not installed. Do you want to install it? It IS required (Y/N)"
	read install
	if [[ $install = Y || $install = y ]] ; then
		sudo apt install -y git
		#rm $0
		echo "GitHub command git installed."
		sleep 3
		intrusion
		exit 1
	else
		echo -e "\e[32m[-]If You Say So. Another Time Then\e[0m"
	fi
else
	echo "GitHub is installed"
	sleep 1
fi
### End GitHub
### Install GitHub
if [ ! -e "/usr/bin/curl" ];then
	echo "curl is not installed. Do you want to install it? It IS required (Y/N)"
	read install
	if [[ $install = Y || $install = y ]] ; then
		sudo apt install -y curl
		#rm $0
		echo "curl installed."
		sleep 3
		intrusion
		exit 1
	else
		echo -e "\e[32m[-]If You Say So. Another Time Then\e[0m"
	fi
else
	echo "curl is installed"
	sleep 1
fi
### End GitHub
### Install GitHub
if [ ! -e "/usr/bin/yamas" ];then
	echo "yamas is not installed. Do you want to install it?(Y/N)"
	read install
	if [[ $install = Y || $install = y ]] ; then
			cd /tmp
			wget http://comax.fr/yamas/bt5/yamas.sh
			cp yamas.sh /usr/bin/yamas
			chmod +x /usr/bin/yamas
			rm yamas.sh
			cd
			echo "yamas Script should now be installed. Launching it !"
			sleep 3
			sudo bash yamas 2>/dev/null & sleep 2
			exit 1
		else
			echo -e "\e[32m[-]If You Say So. Another Time Then\e[0m"
		fi
else
	echo "yamas is installed"
	sleep 1
fi
### End Yamas
### Check for updates !
if [[ "$silent" = "1" ]];then
	echo "Not checking for a new version : silent mode."
else
	changelog=$(curl --silent -q https://raw.githubusercontent.com/JeSTeRFLA/IntrusionScript/master/changelog)
	last_version=$(curl --silent -q https://raw.githubusercontent.com/JeSTeRFLA/IntrusionScript/master/version) #store last version number to variable
	if [[ $last_version > $version ]];then # Comparing to current version
		echo -e "You are running version \033[34m$version\033[m, do you want to update to \033[32m$last_version\033[m? (Y/N)
Last changes are :
$changelog"
		read update
		if [[ $update = Y || $update = y ]];then
			echo "[+] Updating script..."
			wget -q http://Node1.H4CK3D.US/scripts/intrusion.sh -O $0
			chmod +x $0
			echo "[-] Script updated !"
			if [[ $0 != '/usr/bin/yamas' && $ask_for_install = 'y' ]];then
				echo -e "Do you want to install it so that you can launch it with \"intrusion\" (Y/N)?"
				read install
				if [[ $install = Y || $install = y ]];then 
					cp $0 /usr/bin/intrusion
					chmod +x /usr/bin/intrusion
					echo "Intrusion Script is installed. Going to launching it!"
					sleep 3
					intrusion
					exit 1
				else
					echo "Continuing with the updated version... $last_version "
					sleep 3
					$0
					exit 1
				fi
			fi
		
		sleep 2
		$0
		exit 1
		else
			echo "Ok, continuing with current version... $version "
		fi
	else
		echo "No Intrusion Script update available"
	fi
fi
### End of update
#### pause function
function pause(){
   read -sn 1 -p "Press any key to continue..."
}

#### Screwup function
function screwup {
	echo "\033[1;31mYou Screwed Something Up, Fix It Or Install Old Version.\033[m"
	echo "\033[1;31mEmail JeSTeR@H4CK3D.US ASAP.\033[m"
	pause 
	clear
}

####################################################
#           DO NOT TOUCH BELOW HERE                #
####################################################
function LTables {
	echo -e "Locating Tables"
	echo -e "$installit"

	read install
	if [[ $install = Y || $install = y ]] ; then
IPTABLES=/sbin/iptables
BLACKLIST=/etc/blacklist.ips
else
		echo -e "\e[32m[-]If You Say So. Another Time Then\e[0m"
	fi
}

function Flushrl {	
echo -e " * flushing old rules"
echo -e "$installit"
read install
	if [[ $install = Y || $install = y ]] ; then
$iptables --flush
$iptables --delete-chain
$iptables --table nat --flush
$iptables --table nat --delete-chain
else
		echo -e "\e[32m[-]If You Say So. Another Time Then\e[0m"
	fi
}

function SDef {	
echo -e " * setting default policies"
echo -e "$installit"
read install
	if [[ $install = Y || $install = y ]] ; then
$iptables -P INPUT DROP
$iptables -P FORWARD DROP
$iptables -P OUTPUT ACCEPT
else
		echo -e "\e[32m[-]If You Say So. Another Time Then\e[0m"
	fi
}

function Loop {
echo -e " * allowing loopback devices"
echo -e "$installit"
read install
	if [[ $install = Y || $install = y ]] ; then
$iptables -A INPUT -i lo -j ACCEPT
$iptables -A OUTPUT -o lo -j ACCEPT

$iptables -A INPUT -p tcp ! --syn -m state --state NEW -j DROP
$iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
else
		echo -e "\e[32m[-]If You Say So. Another Time Then\e[0m"
	fi
}

function BLAdd {
## BLOCK ABUSING IPs HERE ##
echo -e " * BLACKLIST Known IPS"
echo -e "$installit"
read install
	if [[ $install = Y || $install = y ]] ; then
$iptables -A INPUT -s $subnet -j DROP
$iptables -A INPUT -s $subnet1 -j DROP
$iptables -A INPUT -s $subnet2 -j DROP
if [[ -f "${BLACKLIST}" ]] && [[ -s "${BLACKLIST}" ]]; then
    echo -e " * BLOCKING ABUSIVE IPs"
    while read IP; do
        $iptables -I INPUT -s "${IP}" -j DROP
    done < <(cat "${BLACKLIST}")
fi
else
		echo -e "\e[32m[-]If You Say So. Another Time Then\e[0m"
	fi
}

function assh {
echo -e " * allowing ssh on port"
echo -e "$installit"
read install
	if [[ $install = Y || $install = y ]] ; then
$iptables -A INPUT -p tcp --dport $sshd  -m state --state NEW -j ACCEPT
else
		echo -e "\e[32m[-]If You Say So. Another Time Then\e[0m"
	fi
}

function avpn {
echo -e " * allowing OpenVPN on port 1194"
echo -e "$installit"
read install
	if [[ $install = Y || $install = y ]] ; then
$iptables -A INPUT -p tcp -m state --state NEW -m tcp --dport 1194 -j ACCEPT
$iptables -A INPUT -p udp -m udp --dport 1194 -j ACCEPT
else
		echo -e "\e[32m[-]If You Say So. Another Time Then\e[0m"
	fi
}

function airc {
echo -e " * allowing IRC on port 6665,6667,6669,6697,7000,7010,7020"
echo -e "$installit"
read install
	if [[ $install = Y || $install = y ]] ; then
$iptables -A INPUT -p tcp -m state --state NEW -m tcp --dport $irc1 -j ACCEPT
$iptables -A INPUT -p tcp -m state --state NEW -m tcp --dport $irc2 -j ACCEPT
$iptables -A INPUT -p tcp -m state --state NEW -m tcp --dport $irc3 -j ACCEPT
$iptables -A INPUT -p tcp -m state --state NEW -m tcp --dport $irc4 -j ACCEPT
$iptables -A INPUT -p tcp -m state --state NEW -m tcp --dport $irc5 -j ACCEPT
$iptables -A INPUT -p tcp -m state --state NEW -m tcp --dport $irc6 -j ACCEPT
$iptables -A INPUT -p tcp -m state --state NEW -m tcp --dport $irc7 -j ACCEPT
$iptables -A INPUT -p udp -m udp --dport $irc7 -j ACCEPT
else
		echo -e "\e[32m[-]If You Say So. Another Time Then\e[0m"
	fi
}

function adnst {
echo -e " * allowing dns on port 53 tcp/udp"
echo -e "$installit"
read install
	if [[ $install = Y || $install = y ]] ; then
$iptables -A INPUT -p udp -m udp --dport 53 -j ACCEPT
$iptables -A INPUT -p tcp -m tcp --dport 53 -j ACCEPT
else
		echo -e "\e[32m[-]If You Say So. Another Time Then\e[0m"
	fi
}

function ahttp {
echo -e " * allowing http on port 80"
echo -e "$installit"
read install
	if [[ $install = Y || $install = y ]] ; then
$iptables -A INPUT -p tcp --dport 80  -m state --state NEW -j ACCEPT
else
		echo -e "\e[32m[-]If You Say So. Another Time Then\e[0m"
	fi
}

function ahttps {
echo -e " * allowing https on port 443"
echo -e "$installit"
read install
	if [[ $install = Y || $install = y ]] ; then
$iptables -A INPUT -p tcp --dport 443 -m state --state NEW -j ACCEPT
else
		echo -e "\e[32m[-]If You Say So. Another Time Then\e[0m"
	fi
}

function asmtp {
echo -e " * allowing smtp on port 25"
echo -e "$installit"
read install
	if [[ $install = Y || $install = y ]] ; then
$iptables -A INPUT -p tcp -m state --state NEW -m tcp --dport 25 -j ACCEPT
else
		echo -e "\e[32m[-]If You Say So. Another Time Then\e[0m"
	fi
}

function asub {
echo -e " * allowing submission on port 587"
echo -e "$installit"
read install
	if [[ $install = Y || $install = y ]] ; then
$iptables -A INPUT -p tcp -m state --state NEW -m tcp --dport 587 -j ACCEPT
else
		echo -e "\e[32m[-]If You Say So. Another Time Then\e[0m"
	fi
}

function aimaps {
echo -e " * allowing imaps on port 993"
echo -e "$installit"
read install
	if [[ $install = Y || $install = y ]] ; then
$iptables -A INPUT -p tcp -m state --state NEW -m tcp --dport 993 -j ACCEPT
else
		echo -e "\e[32m[-]If You Say So. Another Time Then\e[0m"
	fi
}

function apop3s {
echo -e " * allowing pop3s on port 995"
echo -e "$installit"
read install
	if [[ $install = Y || $install = y ]] ; then
$iptables -A INPUT -p tcp -m state --state NEW -m tcp --dport 995 -j ACCEPT
else
		echo -e "\e[32m[-]If You Say So. Another Time Then\e[0m"
	fi
}

function aimap {
echo -e " * allowing imap on port 143"
echo -e "$installit"
read install
	if [[ $install = Y || $install = y ]] ; then
$iptables -A INPUT -p tcp -m state --state NEW -m tcp --dport 143 -j ACCEPT
else
		echo -e "\e[32m[-]If You Say So. Another Time Then\e[0m"
	fi
}

function apop3 {
echo -e " * allowing pop3 on port 110"
echo -e "$installit"
read install
	if [[ $install = Y || $install = y ]] ; then
$iptables -A INPUT -p tcp -m state --state NEW -m tcp --dport 110 -j ACCEPT
else
		echo -e "\e[32m[-]If You Say So. Another Time Then\e[0m"
	fi
}

function alpingrep {
echo -e " * allowing ping responses"
echo -e "$installit"
read install
	if [[ $install = Y || $install = y ]] ; then
$iptables -A INPUT -p ICMP --icmp-type 8 -j ACCEPT
else
		echo -e "\e[32m[-]If You Say So. Another Time Then\e[0m"
	fi
}

function daale {
echo -e " * Drop ALL And Log Events"
echo -e "$installit"
read install
	if [[ $install = Y || $install = y ]] ; then	
# DROP everything else and Log it
#$iptables -A INPUT -j LOG
$iptables -A INPUT -j DROP
else
		echo -e "\e[32m[-]If You Say So. Another Time Then\e[0m"
	fi
}

function Save {
echo -e " * Drop All ELSE And Log Events"
echo -e "$installit"
read install
if [[ $install = Y || $install = y ]] ; then
if [[ -d /etc/network/if-pre-up.d ]]; then
    if [[ ! -f /etc/network/if-pre-up.d/iptables ]]; then
        echo -e "#!/bin/bash" > /etc/network/if-pre-up.d/iptables
        echo -e "test -e /etc/iptables.rules && iptables-restore -c /etc/iptables.rules" >> /etc/network/if-pre-up.d/iptables
        chmod +x /etc/network/if-pre-up.d/iptables
    fi
fi
iptables-save > /etc/intrusion.rules
iptables-restore -c /etc/intrusion.rules
else
		echo -e "\e[32m[-]If You Say So. Another Time Then\e[0m"
	fi
}

############
###Extras###
############
function credits2 {
clear
echo -e "
\033[34m#######################################################\033[m
                       Credits To
\033[34m#######################################################\033[m"
echo -e "\033[32m
Special thanks to:
Pain: for more ideas. (Things to add)
LionSec for xerosploit (https://github.com/LionSec/xerosploit)
thc.org for Hydra

You: for testing it out.

\033[m"
}

function nexttime {
echo -e "
                    version : \033[32m$version\033[m
                    Created By : \033[32m$Creator\033[m
                    Email : \033[32m$Email\033[m
                    IRC  : \033[32m$ircsrv\033[m
                    Chan :  \033[32m$channle\033[m
Script Location    : \033[32m$0\033[m
Info :--------------------------------------------------
        \033[32mMaybe Next Time Ill Add More\033[m
Info :-----------------------------------------------"
read install
if [[ $install = Y || $install = y ]] ; then
	sudo apt update
else
		echo -e "\e[32m[-]If You Say So. Another Time Then\e[0m"
	fi
}

function Hydra666 {
echo -e "Install Hydra"
echo -e "$installit"
read install
if [[ $install = Y || $install = y ]] ; then
	sudo apt install hydra -y
	sudo apt-get update
else
		echo -e "\e[32m[-]If You Say So. Another Time Then\e[0m"
	fi
}

function xero666 {
echo -e "Installing xerosploit by LionSec"
echo -e "$installit"
read install
if [[ $install = Y || $install = y ]] ; then
	git clone https://github.com/LionSec/xerosploit.git
	cd xerosploit && sudo python install.py
	sudo chmod +x run.sh
	echo -e "xerosploit is not in anyway my script"
	echo -e "( sudo xerosploit ) to run it."
	echo -e "https://github.com/LionSec/xerosploit"
else
		echo -e "\e[32m[-]If You Say So. Another Time Then\e[0m"
	fi
}

function MSF666 {
echo -e "Installing Metasploit Framework"
echo -e "$installit"
read install
if [[ $install = Y || $install = y ]] ; then
	sudo add-apt-repository -y ppa:webupd8team/java
	sudo apt update
	sudo apt -y install oracle-java8-installer
	sudo apt update && sudo apt -y upgrade
	sudo apt-get -y install build-essential libreadline-dev libssl-dev libpq5 libpq-dev libreadline5 libsqlite3-dev libpcap-dev git-core autoconf postgresql pgadmin3 curl zlib1g-dev libxml2-dev libxslt1-dev vncviewer libyaml-dev curl zlib1g-dev
	curl -sSL https://rvm.io/mpapis.asc | gpg2 --import -
    curl -L https://get.rvm.io | bash -s stable
    source ~/.rvm/scripts/rvm
    echo "source ~/.rvm/scripts/rvm" >> ~/.bashrc
    source ~/.bashrc
    RUBYVERSION=$(wget https://raw.githubusercontent.com/rapid7/metasploit-framework/master/.ruby-version -q -O - )
    rvm install $RUBYVERSION
    rvm use $RUBYVERSION --default
    ruby -v
    su postgres
    createuser msf -P -S -R -D
    createdb -O msf msf
    exit
    cd /opt
    git clone https://github.com/rapid7/metasploit-framework.git
    chown -R `whoami` /opt/metasploit-framework
    cd metasploit-framework
    gem install bundler
    bundle install
    sudo bash -c 'for MSF in $(ls msf*); do ln -s /opt/metasploit-framework/$MSF /usr/local/bin/$MSF;done'
	echo -e "Installed Metasploit Framework"
else
		echo -e "\e[32m[-]If You Say So. Another Time Then\e[0m"
	fi
}

function metasploitservices {
clear
echo -e "Metasploit Services"
select menusel in "Start Metasploit Services" "Stop Metasploit Services" "Restart Metasploit Services" "Autostart Metasploit Services" "Back to Main"; do
case $menusel in
	"Start Metasploit Services")
		echo -e "\033[32mStarting Metasploit Services..\033[m"
		service postgresql start && service metasploit start
		echo -e "\033[32mNow Open a new Terminal and launch msfconsole\033[m"
		pause ;;
	
	"Stop Metasploit Services")
		echo -e "\033[32mStoping Metasploit Services..\033[m"
		service postgresql stop && service metasploit stop
		pause ;;
		
	"Restart Metasploit Services")
		echo -e "\033[32mRestarting Metasploit Services..\033[m"
		service postgresql restart && service metasploit restart
		pause ;;
		
	"Autostart Metasploit Services")
		echo -e "\033[32mSetting Metasploit Services to start on boot..\033[m"
		update-rc.d postgresql enable && update-rc.d metasploit enable
		pause ;;

	"Back to Extras")
		clear
		extras6 ;;
		
	*)
		screwup
		metasploitservices ;;		
		
esac

break

done
}

function pwnstar {
		if [ ! -e "/opt/PwnSTAR_0.9/PwnSTAR_0.9" ];then
			echo "PwnStar is not installed. Do you want to install it ? (Y/N)"
			read install
			if [[ $install = Y || $install = y ]] ; then
				mkdir /opt/PwnSTAR_0.9
				cd /opt/PwnSTAR_0.9
				wget http://pwn-star.googlecode.com/files/PwnSTAR_0.9.tgz
				tar -zxvf PwnSTAR_0.9.tgz 
				mv hotspot_3 /var/www/ && mv portal_hotspot /var/www/ && mv portal_pdf /var/www/ && mv portal_simple /var/www/
				#rm $0
				echo "PwnStar should now be installed. Launching it !"
				sleep 3
				gnome-terminal -t "PwnStar" -e /opt/PwnSTAR_0.9/PwnSTAR_0.9 2>/dev/null & sleep 2
				pause
				sniffspoof
				exit 1
			else
				echo -e "\e[32m[-]If You Say So. Another Time Then\e[0m"
			fi
		else
			echo "PwnStar is installed, Launching it now!"
			sleep 1
			gnome-terminal -t "PwnStar" -e /opt/PwnSTAR_0.9/PwnSTAR_0.9 2>/dev/null & sleep 2
		fi 
}

function subterfuge {
	echo "This will install Subterfuge. Do you want to install it ? (Y/N)"
	read install
	if [[ $install = Y || $install = y ]] ; then
		echo -e "\e[31m[+] Installing Subterfuge now!\e[0m"
		cd /tmp
		wget http://subterfuge.googlecode.com/files/SubterfugePublicBeta5.0.tar.gz
		tar zxvf SubterfugePublicBeta5.0.tar.gz
		cd subterfuge
		python install.py
		cd ../
		rm -rf subterfuge/
		rm SubterfugePublicBeta5.0.tar.gz
		echo -e "\e[32m[-] Done Installing Subterfuge!\e[0m"		
	else
		echo -e "\e[32m[-]If You Say So. Another Time Then\e[0m"
	fi
}

############
##INSTALLS##
############


function issh {
echo -e "Install OpenSSH"
echo -e "$installit"
read install
if [[ $install = Y || $install = y ]] ; then
	sudo apt install openssh-server -y
else
		echo -e "\e[32m[-]If You Say So. Another Time Then\e[0m"
	fi
}

function rkhunter {
echo -e "Install RootKit Hunter"
echo -e "$installit"
read install  
if [[ $install = Y || $install = y ]] ; then
	sudo apt install rkhunter -y
	sudo rkhunter --update
    sudo rkhunter --propupd
    sudo rkhunter --check
else
		echo -e "\e[32m[-]If You Say So. Another Time Then\e[0m"
	fi
}

function chkrootkit {
echo -e "Install CheckRootKit"
echo -e "$installit"
read install 
if [[ $install = Y || $install = y ]] ; then
	sudo apt install chkrootkit -y
	sudo chkrootkit
else
		echo -e "\e[32m[-]If You Say So. Another Time Then\e[0m"
	fi
}

function inmap {
echo -e "Install NMap"
echo -e "$installit"
read install 
if [[ $install = Y || $install = y ]] ; then
	sudo apt install nmap -y
else
		echo -e "\e[32m[-]If You Say So. Another Time Then\e[0m"
	fi
}

function ilgw {
echo -e "Install LogWatch"
echo -e "$installit"
read install 
if [[ $install = Y || $install = y ]] ; then
	sudo apt install logwatch libdate-manip-perl -y
	sudo logwatch | less
	sudo logwatch --mailto $mymail --output mail --format html --range 'between -7 days and today'
else
		echo -e "\e[32m[-]If You Say So. Another Time Then\e[0m"
	fi
}

function armor {
echo -e "Install AppArmor"
echo -e "$installit"
read install 
if [[ $install = Y || $install = y ]] ; then
	sudo apt install apparmor apparmor-profiles -y
	sudo apparmor_status
else
		echo -e "\e[32m[-]If You Say So. Another Time Then\e[0m"
	fi
}

function tiger {
echo -e "Install Tiger Security Tools"
echo -e "$installit"
read install 
if [[ $install = Y || $install = y ]] ; then
	sudo apt install tiger -y
	sudo tiger
	sudo less /var/log/tiger/security.report.*
else
		echo -e "\e[32m[-]If You Say So. Another Time Then\e[0m"
	fi
}

function Tripwire {
echo -e "Install Tripwire"
echo -e "$installit"
read install 
if [[ $install = Y || $install = y ]] ; then
	sudo apt install tripwire -y
	sudo twadmin --create-polfile /etc/tripwire/twpol.txt
	sudo tripwire --init
	sudo sh -c 'tripwire --check | grep Filename > test_results'
	less /etc/tripwire/test_results
	sudo tripwire --check
else
		echo -e "\e[32m[-]If You Say So. Another Time Then\e[0m"
	fi
}

function apm {
echo -e "Install Apache2/PHP7/PHP5/Mysql-server"
echo -e "$installit"
read install
if [[ $install = Y || $install = y ]] ; then
	apt-get -y install mysql-server mysql-client apache2 php libapache2-mod-php
	apt-get -y install php7.0 php5.6 php5.6-mysql php-gettext php5.6-mbstring php-xdebug libapache2-mod-php5.6 libapache2-mod-php7.0
	apt-get -y install php7.0-cgi php7.0-cli php7.0-common php7.0-curl php7.0-dev php7.0-gd php7.0-json php7.0-mysql php7.0-pgsql php7.0-sqlite3 libphp7.0-embed php-apcu php-geoip php-oauth php-ssh2 php7.0-bz2 php7.0-mcrypt php-http php-memcache php5.6-cgi php5.6-cli php5.6-phpdbg libphp5.6-embed php5.6-dev php5.6-common php5.6-curl php5.6-gd php5.6-mysql php5.6-sqlite3 php5.6-json php-memcached php5.6-bz2 php5.6-mcrypt
	apt-get -y install apache2-bin apache2-data apache2-dev libapache2-mod-apparmor libapache2-mod-perl2 libapache2-mod-perl2-dev libapache2-mod-php7.0 libapache2-mod-python libapache2-mod-geoip libapache2-mod-gnutls libapache2-mod-log-sql-mysql libapache2-mod-log-sql-ssl libapache2-mod-security2 libapache2-mod-spamhaus libapache2-modsecurity libembperl-perl php7.0-fpm php5.6-fpm libmysql-java
else
		echo -e "\e[32m[-]If You Say So. Another Time Then\e[0m"
	fi
}

function uprep {
echo -e "Updating Repos"
echo -e "$installit"
read install
if [[ $install = Y || $install = y ]] ; then
	sudo echo "#------------------------------------------------------------------------------#" > /etc/apt/source.list
sudo echo "#                            OFFICIAL UBUNTU REPOS                             #" >> /etc/apt/source.list
sudo echo "#------------------------------------------------------------------------------#" >> /etc/apt/source.list
sudo echo "deb http://01.archive.ubuntu.com/ubuntu/ xenial main restricted universe multiverse " >> /etc/apt/source.list
sudo echo "deb-src http://01.archive.ubuntu.com/ubuntu/ xenial main restricted universe multiverse " >> /etc/apt/source.list
sudo echo "deb http://01.archive.ubuntu.com/ubuntu/ xenial-security main restricted universe multiverse " >> /etc/apt/source.list
sudo echo "deb http://01.archive.ubuntu.com/ubuntu/ xenial-updates main restricted universe multiverse " >> /etc/apt/source.list
sudo echo "deb http://01.archive.ubuntu.com/ubuntu/ xenial-proposed main restricted universe multiverse " >> /etc/apt/source.list
sudo echo "deb http://01.archive.ubuntu.com/ubuntu/ xenial-backports main restricted universe multiverse " >> /etc/apt/source.list
sudo echo "deb-src http://01.archive.ubuntu.com/ubuntu/ xenial-security main restricted universe multiverse " >> /etc/apt/source.list
sudo echo "deb-src http://01.archive.ubuntu.com/ubuntu/ xenial-updates main restricted universe multiverse " >> /etc/apt/source.list
sudo echo "deb-src http://01.archive.ubuntu.com/ubuntu/ xenial-proposed main restricted universe multiverse " >> /etc/apt/source.list
sudo echo "deb-src http://01.archive.ubuntu.com/ubuntu/ xenial-backports main restricted universe multiverse " >> /etc/apt/source.list
sudo echo "deb http://archive.canonical.com/ubuntu xenial partner" >> /etc/apt/source.list
sudo echo "deb-src http://archive.canonical.com/ubuntu xenial partner" >> /etc/apt/source.list
sudo echo "## Run this command: wget -q -O- http://archive.getdeb.net/getdeb-archive.key | sudo apt-key add -" >> /etc/apt/source.list
sudo echo "deb http://archive.getdeb.net/ubuntu xenial-getdeb apps" >> /etc/apt/source.list
sudo echo "#### Oracle Java (JDK) Installer PPA - http://www.webupd8.org/2012/01/install-oracle-java-jdk-7-in-ubuntu-via.html" >> /etc/apt/source.list
sudo echo "## Run this command: sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys EEA14886" >> /etc/apt/source.list
sudo echo "deb http://ppa.launchpad.net/webupd8team/java/ubuntu vivid main" >> /etc/apt/source.list
sudo echo "#### Tor: anonymity online - https://www.torproject.org" >> /etc/apt/source.list
sudo echo "## Run this command: sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 886DDD89" >> /etc/apt/source.list
sudo echo "deb http://deb.torproject.org/torproject.org xenial main" >> /etc/apt/source.list
sudo echo "## Run this command: wget http://www.webmin.com/jcameron-key.asc -O- | sudo apt-key add -" >> /etc/apt/source.list
sudo echo "deb http://download.webmin.com/download/repository sarge contrib" >> /etc/apt/source.list
sudo echo "#### Oracle Java (JDK) Installer PPA (Source) - http://www.webupd8.org/2012/01/install-oracle-java-jdk-7-in-ubuntu-via.html" >> /etc/apt/source.list
sudo echo "## Run this command: sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys EEA14886" >> /etc/apt/source.list
sudo echo "deb-src http://ppa.launchpad.net/webupd8team/java/ubuntu vivid main" >> /etc/apt/source.list
sudo echo "#### Tor: anonymity online (Source) - https://www.torproject.org" >> /etc/apt/source.list
sudo echo "## Run this command: sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 886DDD89" >> /etc/apt/source.list
sudo echo "deb-src http://deb.torproject.org/torproject.org xenial main" >> /etc/apt/source.list
wget -q -O- http://archive.getdeb.net/getdeb-archive.key | sudo apt-key add -
sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys EEA14886
sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 886DDD89
wget http://www.webmin.com/jcameron-key.asc -O- | sudo apt-key add -
else
		echo -e "\e[32m[-]If You Say So. Another Time Then\e[0m"
	fi
}

function build {
echo -e "Installing Build-Essential"
echo -e "$installit"
read install
if [[ $install = Y || $install = y ]] ; then
	apt-get -y install build-essential
	apt-get -y install cmake gmake
else
		echo -e "\e[32m[-]If You Say So. Another Time Then\e[0m"
	fi
}
#############
##Hardening##
#############
function gsshkey {
echo -e "Generating public/private rsa key pair"
echo -e "$installit"
read install
if [[ $install = Y || $install = y ]] ; then
	sudo ssh-keygen -t rsa
else
		echo -e "\e[32m[-]If You Say So. Another Time Then\e[0m"
	fi
}

function gsshhash {
echo -e "Generating public/private rsa key pair HASH"
echo -e "$installit"
read install
if [[ $install = Y || $install = y ]] ; then
	sudo ssh-keygen -l -f /etc/ssh/ssh_host_rsa_key.pub -E $hashkey

else
		echo -e "\e[32m[-]If You Say So. Another Time Then\e[0m"
	fi
}

function sunsshd {
echo -e "Changing /etc/ssh/sshd_conf File"
echo -e "Adding Port $sshd"
echo -e "Adding ListenAddress $sship"
echo -e "Commenting Out HostKey /etc/ssh/ssh_host_ecdsa_key"
echo -e "Changing PermitRootLogin = $permroot"
echo -e "$installit"
read install
if [[ $install = Y || $install = y ]] ; then
	sudo sed -i "s/Port 22/Port $sshd/g" /etc/ssh/sshd_conf
	sudo sed -i "s/#ListenAddress 0.0.0.0/ListenAddress $sship/g" /etc/ssh/sshd_conf
	sudo sed -i "s/PermitRootLogin yes/PermitRootLogin $permroot/g" /etc/ssh/sshd_conf
else
		echo -e "\e[32m[-]If You Say So. Another Time Then\e[0m"
	fi
}

function sshdrsrt {
echo -e "Restarting OpenSSH"
echo -e "$installit"
read install
if [[ $install = Y || $install = y ]] ; then
	service ssh restart
else
		echo -e "\e[32m[-]If You Say So. Another Time Then\e[0m"
	fi
}

function ftabsec {
echo -e "Securing Shared Memory"
echo -e "$installit"
read install
if [[ $install = Y || $install = y ]] ; then
	sudo echo "# Secure Shared Memory - $LogTime" >> /etc/fstab
	sudo echo "tmpfs /run/shm tmpfs defaults,noexec,nosuid 0 0" >> /etc/fstab
	echo -e "Secured Shared memory. Reboot Required"
else
		echo -e "\e[32m[-]If You Say So. Another Time Then\e[0m"
	fi
}

function addbad {
echo -e "Adding Illegal Char. Names IE: JeSTeR"
echo -e "Change Config At Top Of File (badname="JeSTeR")"
echo -e "$installit"
read install
if [[ $install = Y || $install = y ]] ; then
	adduser $badname --force-badname
else
		echo -e "\e[32m[-]If You Say So. Another Time Then\e[0m"
	fi
}

function adminusr {
echo -e "Making A ADMIN USER ( $user2    ALL=NOPASSWD: ALL"
echo -e "$installit"
read install
if [[ $install = Y || $install = y ]] ; then
    sudo groupadd admin
    sudo usermod -a -G admin,adm,root $user2
    sudo dpkg-statoverride --update --add root admin 4750 /bin/su
    sudo sed -i "s/# Members of the admin group may gain root privilege/$user2    ALL=NOPASSWD: ALL/g" /etc/sudoers
else
		echo -e "\e[32m[-]If You Say So. Another Time Then\e[0m"
	fi
}

function hardsys {
echo -e "Harden network with sysctl settings"
echo -e "$installit"
read install
if [[ $install = Y || $install = y ]] ; then
	sudo echo "# Created By Intrusion Script" > /etc/sysctl.conf
	sudo echo "# By JeSTeR" >> /etc/sysctl.conf
	sudo echo "# Email : JeSTeR@H4CK3D.US" >> /etc/sysctl.conf
	sudo echo "# IP Spoofing protection" >> /etc/sysctl.conf
	sudo echo "net.ipv4.conf.all.rp_filter = 1" >> /etc/sysctl.conf
	sudo echo "net.ipv4.conf.default.rp_filter = 1" >> /etc/sysctl.conf
	sudo echo "# Ignore ICMP broadcast requests" >> /etc/sysctl.conf
	sudo echo "net.ipv4.icmp_echo_ignore_broadcasts = 1" >> /etc/sysctl.conf
	sudo echo "# Disable source packet routing" >> /etc/sysctl.conf
	sudo echo "net.ipv4.conf.all.accept_source_route = 0" >> /etc/sysctl.conf
	sudo echo "net.ipv6.conf.all.accept_source_route = 0" >> /etc/sysctl.conf
	sudo echo "net.ipv4.conf.default.accept_source_route = 0" >> /etc/sysctl.conf
	sudo echo "net.ipv6.conf.default.accept_source_route = 0" >> /etc/sysctl.conf
	sudo echo "# Ignore send redirects" >> /etc/sysctl.conf
	sudo echo "net.ipv4.conf.all.send_redirects = 0" >> /etc/sysctl.conf
	sudo echo "net.ipv4.conf.default.send_redirects = 0" >> /etc/sysctl.conf
	sudo echo "# Block SYN attacks" >> /etc/sysctl.conf
	sudo echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.conf
	sudo echo "net.ipv4.tcp_max_syn_backlog = 2048" >> /etc/sysctl.conf
	sudo echo "net.ipv4.tcp_synack_retries = 2" >> /etc/sysctl.conf
	sudo echo "net.ipv4.tcp_syn_retries = 5" >> /etc/sysctl.conf
	sudo echo "# Log Martians" >> /etc/sysctl.conf
	sudo echo "net.ipv4.conf.all.log_martians = 1" >> /etc/sysctl.conf
	sudo echo "net.ipv4.icmp_ignore_bogus_error_responses = 1" >> /etc/sysctl.conf
	sudo echo "# Ignore ICMP redirects" >> /etc/sysctl.conf
	sudo echo "net.ipv4.conf.all.accept_redirects = 0" >> /etc/sysctl.conf
	sudo echo "net.ipv6.conf.all.accept_redirects = 0" >> /etc/sysctl.conf
	sudo echo "net.ipv4.conf.default.accept_redirects = 0 " >> /etc/sysctl.conf
	sudo echo "net.ipv6.conf.default.accept_redirects = 0" >> /etc/sysctl.conf
	sudo echo "# Ignore Directed pings" >> /etc/sysctl.conf
	sudo echo "net.ipv4.icmp_echo_ignore_all = 1" >> /etc/sysctl.conf
	sudo sysctl -p
else
		echo -e "\e[32m[-]If You Say So. Another Time Then\e[0m"
	fi
}

function nospoof {
echo -e "Prevent IP Spoofing"
echo -e "$installit"
read install
if [[ $install = Y || $install = y ]] ; then
    sudo echo "nospoof on" >> /etc/host.conf
else
		echo -e "\e[32m[-]If You Say So. Another Time Then\e[0m"
	fi
}
###########
#REBOOTING#
###########
function REBOOTING {
echo -e "REQUIRED REBOOT"
echo -e "$installit"
read install
if [[ $install = Y || $install = y ]] ; then
	sudo echo "Intrusion Script Rebooting System. Sorry For Any Inconvenience" | wall
	sudo reboot
	echo "Rebooting Now (Intrusion Script)"
else
		echo -e "\e[32m[-]If You Say So. Another Time Then\e[0m"
	fi
}

function chvars {
echo -e "Change Default Variables"
echo -e "$installit"
read install
if [[ $install = Y || $install = y ]] ; then
  sudo echo "Intrusion Script Installed" | wall
  sudo nano $0
  echo "Changed (Intrusion Script)"
else
    echo -e "\e[32m[-] YOU MUST DO THIS!\e[0m"
  fi
}

function inter22 {
echo -e "Changed Default Reseting Intrusion Script"
  sudo $0
  echo "Changed (Intrusion Script)"
}
############
####Menu####
############
function extras6 {
clear
echo -e "
\033[34m################################################################\033[m
\033[1;32m___________         __                         
\_   _____/__  ____/  |_____________    ______ 
 |    __)_\  \/  /\   __\_  __ \__  \  /  ___/ 
 |        \>    <  |  |  |  | \// __ \_\___ \  
/_______  /__/\_ \ |__|  |__|  (____  /____  > 
        \/      \/                  \/     \/                                          
\033[m                                        
                    version : \033[32m$version\033[m
                    Created By : \033[32m$Creator\033[m
                    Email : \033[32m$Email\033[m
                    Whoami : \033[32m$UserName\033[m
Script Location    : \033[32m$0\033[m
Default Info       :--------------------------------------------------
        \033[32mThese Will Be Used If You Did Not Set Them\033[m
Default Email      : \033[32m$mymail\033[m
Default Admin User : \033[32m$user2\033[m
Default SSH IP     : \033[32m$sship\033[m
Default SSH        : \033[32m$sshd\033[m
Default IRC        : \033[32m$irc1\033[m \033[32m$irc2\033[m \033[32m$irc3\033[m \033[32m$irc4\033[m \033[32m$irc5\033[m \033[32m$irc6\033[m 
Default IRC SSL    : \033[32m$irc7\033[m
Connection Info    :-----------------------------------------------
  Gateway: \033[32m$DEFAULT_ROUTE\033[m Interface: \033[32m$IFACE\033[m MyIP: \033[32m$myipad\033[m
\033[34m################################################################\033[m"
select menusel in "Hydra" "xerosploit" "Metasploit-Framework" "PwnStar" "Subterfuge" "Back to Main"; do
case $menusel in
	"Hydra")
		Hydra666
		pause
		extras6 ;;

  "xerosploit")
    xero666
    pause
    extras6 ;;

  "Metasploit-Framework")
    MSF666
    pause
    extras6 ;;

 	"PwnStar")
		pwnstar
		pause
    extras6 ;;
		
	"Subterfuge")
		subterfuge
		pause
    extras6 ;;

	"Back to Main")
		clear
		mainmenu ;;
		
	*)
		screwup
		mainmenu ;;
	
		
esac

break

done
}


function tables3 {
clear
echo -e "
\033[34m################################################################\033[m
\033[1;32m.________________________     ___.   .__                  
|   \______   \__    ___/____ \_ |__ |  |   ____   ______ 
|   ||     ___/ |    |  \__  \ | __ \|  | _/ __ \ /  ___/ 
|   ||    |     |    |   / __ \| \_\ \  |_\  ___/ \___ \  
|___||____|     |____|  (____  /___  /____/\___  >____  > 
                             \/    \/          \/     \/                                           
\033[m                                        
                    version : \033[32m$version\033[m
                    Created By : \033[32m$Creator\033[m
                    Email : \033[32m$Email\033[m
                    Whoami : \033[32m$UserName\033[m
Script Location    : \033[32m$0\033[m
Default Info       :--------------------------------------------------
        \033[32mThese Will Be Used If You Did Not Set Them\033[m
Default Email      : \033[32m$mymail\033[m
Default Admin User : \033[32m$user2\033[m
Default SSH IP     : \033[32m$sship\033[m
Default SSH        : \033[32m$sshd\033[m
Default IRC        : \033[32m$irc1\033[m \033[32m$irc2\033[m \033[32m$irc3\033[m \033[32m$irc4\033[m \033[32m$irc5\033[m \033[32m$irc6\033[m 
Default IRC SSL    : \033[32m$irc7\033[m
Connection Info    :-----------------------------------------------
  Gateway: \033[32m$DEFAULT_ROUTE\033[m Interface: \033[32m$IFACE\033[m MyIP: \033[32m$myipad\033[m
\033[34m################################################################\033[m"
select menusel in "IPTables" "Flush Old Rules" "Set Default Policies" "Allow LoopBack Devices" "BlackList Known IPs" "Add SSH (Change To Your Port)" "OpenVPN" "IRC Ports (Change To Your Ports)" "FTP (Change To Your FTP Port)" "DNS Server TCP/UDP" "HTTP" "HTTPS" "SMTP Mail" "Submission" "IMAP Secured" "POP3 Secured" "IMAP" "POP3" "Allow Pings" "Drop ELSE and Log Events (DROP everything else and Log it)" "Do ALL" "SAVE/RUN" "Back to Main"; do
case $menusel in
	"IPTables")
		LTables
		pause
		tables3
		clear ;;

	"Flush Old Rules")
		Flushrl
		pause
		tables3
		clear ;;

	"Set Default Policies")
		SDef
		pause
		tables3
		clear ;;

	"Allow LoopBack Devices")
		Loop
		pause
		tables3
		clear ;;

	"BlackList Known IPs")
		BLAdd
		pause
		tables3
		clear ;;

	"Add SSH (Change To Your Port)")
		sunsshd
		pause
		assh
		pause
		tables3
		clear ;;

	"OpenVPN")
		avpn
		pause
		tables3
		clear ;;

	"IRC Ports (Change To Your Ports)")
		airc
		pause
		tables3
		clear ;;

	"FTP (Change To Your FTP Port)")
		aftp
		pause
		tables3
		clear ;;

	"DNS Server TCP/UDP")
		adnst
		pause
		tables3
		clear ;;

	"HTTP")
		ahttp
		pause
		tables3
		clear ;;

	"HTTPS")
		ahttps
		pause
		tables3
		clear ;;

	"SMTP Mail")
		asmtp
		pause
		tables3
		clear ;;

	"Submission")
		asub
		pause
		tables3
		clear ;;

	"IMAP Secured")
		aimaps
		pause
		tables3
		clear ;;

	"POP3 Secured")
		apop3s
		pause
		tables3
		clear ;;

	"IMAP")
		aimap
		pause
		tables3
		clear ;;

	"POP3")
		apop3
		pause
		tables3
		clear ;;

	"Allow Pings")
		alpingrep
		pause
		tables3
		clear ;;

	"Drop ELSE and Log Events (DROP everything else and Log it)")
		daale
		pause
		tables3
		clear ;;

	"Do ALL")
		LTables
		Flushrl
		SDef
		Loop
		BLAdd
		sunsshd
		pause
		assh
		avpn
		airc
		aftp
		adnst
		ahttp
		ahttps
		asmtp
		asub
		aimap
		aimaps
		apop3
		apop3s
		alpingrep
		daale
		Save
		pause
		tables3
		clear ;;

	"SAVE/RUN")
		Save
		tables3
		clear ;;

	"Back to Main")
		clear
		mainmenu ;;
		
	*)
		screwup
		mainmenu ;;
	
		
esac

break

done
}

function insta33 {
clear
echo -e "
\033[34m################################################################\033[m
\033[1;32m.___                 __         .__  .__          
|   | ____   _______/  |______  |  | |  |   ______ 
|   |/    \ /  ___/\   __\__  \ |  | |  |  /  ___/ 
|   |   |  \\___  \  |  |  / __ \|  |_|  |__\___ \  
|___|___|  /____  > |__| (____  /____/____/____  > 
         \/     \/            \/               \/                                         
\033[m                                        
                    version : \033[32m$version\033[m
                    Created By : \033[32m$Creator\033[m
                    Email : \033[32m$Email\033[m
                    Whoami : \033[32m$UserName\033[m
Script Location    : \033[32m$0\033[m
Default Info       :--------------------------------------------------
        \033[32mThese Will Be Used If You Did Not Set Them\033[m
Default Email      : \033[32m$mymail\033[m
Default Admin User : \033[32m$user2\033[m
Default SSH IP     : \033[32m$sship\033[m
Default SSH        : \033[32m$sshd\033[m
Default IRC        : \033[32m$irc1\033[m \033[32m$irc2\033[m \033[32m$irc3\033[m \033[32m$irc4\033[m \033[32m$irc5\033[m \033[32m$irc6\033[m 
Default IRC SSL    : \033[32m$irc7\033[m
Connection Info    :-----------------------------------------------
  Gateway: \033[32m$DEFAULT_ROUTE\033[m Interface: \033[32m$IFACE\033[m MyIP: \033[32m$myipad\033[m
\033[34m################################################################\033[m"
select menusel in "Update Ubuntu Repos" "Apache/PHP/Mysql" "build-essential" "OpenSSH Install" "SSH Settings" "RootKitHunter" "CHKRootKit" "nMap" "LogWatcher" "AppArmor" "Tiger" "TripWire" "Back to Main"; do
case $menusel in

	"OpenSSH Install")
		issh
		pause
		sunsshd
		pause
		insta33
		clear ;;

	"SSH Settings")
		sunsshd
		pause
		insta33
		clear ;;

	"Apache/PHP/Mysql")
		apm
		pause
		insta33
		clear ;;

	"Update Ubuntu Repos")
		uprep
		pause
		insta33
		clear ;;

	"build-essential")
		build
		pause
		insta33
		clear ;;

	"RootKitHunter")
		rkhunter
		pause
		insta33
		clear ;;

	"CHKRootKit")
		chkrootkit
		pause
		insta33
		clear ;;

	"nMap")
		inmap
		pause
		insta33
		clear ;;

	"LogWatcher")
		ilgw
		pause
		insta33
		clear ;;

	"AppArmor")
		armor
		pause
		insta33
		clear ;;

	"Tiger")
		tiger
		pause
		insta33
		clear ;;

	"TripWire")
		Tripwire
		pause
		insta33
		clear ;;

	"Back to Main")
		clear
		mainmenu ;;
	*)
		screwup
		mainmenu ;;
	
		
esac

break

done
}

function syshard {
clear
echo -e "
\033[34m################################################################\033[m
\033[1;32m  ___ ___                  .___            .__                 
 /   |   \_____ _______  __| _/____   ____ |__| ____    ____   
/    ~    \__  \\_  __ \/ __ |/ __ \ /    \|  |/    \  / ___\  
\    Y    // __ \|  | \/ /_/ \  ___/|   |  \  |   |  \/ /_/  > 
 \___|_  /(____  /__|  \____ |\___  >___|  /__|___|  /\___  /  
       \/      \/           \/    \/     \/        \//_____/                                          
\033[m                                        
                    version : \033[32m$version\033[m
                    Created By : \033[32m$Creator\033[m
                    Email : \033[32m$Email\033[m
                    Whoami : \033[32m$UserName\033[m
Script Location    : \033[32m$0\033[m
Default Info       :--------------------------------------------------
        \033[32mThese Will Be Used If You Did Not Set Them\033[m
Default Email      : \033[32m$mymail\033[m
Default Admin User : \033[32m$user2\033[m
Default SSH IP     : \033[32m$sship\033[m
Default SSH        : \033[32m$sshd\033[m
Default IRC        : \033[32m$irc1\033[m \033[32m$irc2\033[m \033[32m$irc3\033[m \033[32m$irc4\033[m \033[32m$irc5\033[m \033[32m$irc6\033[m 
Default IRC SSL    : \033[32m$irc7\033[m
Connection Info    :-----------------------------------------------
  Gateway: \033[32m$DEFAULT_ROUTE\033[m Interface: \033[32m$IFACE\033[m MyIP: \033[32m$myipad\033[m
\033[34m################################################################\033[m"
select menusel in "Generating public/private rsa key pair" "SSHD_CONFIG Change" "Generating public/private rsa key pair HASH" "Comment Out HostKey" "Securing Shared Memory" "Adding Illegal Names" "Making A Super USER" "Harden network with sysctl settings" "Prevent IP Spoofing" "Back to Main"; do
case $menusel in

	"Generating public/private rsa key pair")
		gsshkey
		pause
		syshard
		clear ;;

	"SSHD_CONFIG Change")
		sunsshd
		pause
		syshard
		clear ;;

	"Generating public/private rsa key pair HASH")
		gsshhash
		pause
		sunsshd
		pause
		sshdrsrt
		pause
		syshard
		clear ;;

	"Restarting OpenSSH")
		sshdrsrt
		pause
		syshard
		clear ;;

	"Securing Shared Memory")
		ftabsec
		pause
		REBOOTING
		pause
		syshard
		clear ;;

	"Adding Illegal Names")
		addbad
		pause
		syshard
		clear ;;

	"Making A ADMIN USER")
		adminusr
		pause
		syshard
		clear ;;

	"Harden network with sysctl settings")
		hardsys
		pause
		syshard
		clear ;;

	"Prevent IP Spoofing")
		nospoof
		pause
		syshard
		clear ;;

	"Back to Main")
		clear
		mainmenu ;;
	*)
		screwup
		mainmenu ;;
	
		
esac

break

done
}

function mainmenu {
echo -e "
\033[34m################################################################\033[m
\033[1;32m.___        __                      .__                
|   | _____/  |________ __ __  _____|__| ____   ____   
|   |/    \   __\_  __ \  |  \/  ___/  |/  _ \ /    \  
|   |   |  \  |  |  | \/  |  /\___ \|  (  <_> )   |  \ 
|___|___|  /__|  |__|  |____//____  >__|\____/|___|  / 
   \033[34mBY\033[m   \033[1;32m\/\033[m   \033[34mJeSTeR@H4CK3D.US\033[m    \033[1;32m\/               \/   
\033[m                                        
                    version : \033[32m$version\033[m
                    Created By : \033[32m$Creator\033[m
                    Email : \033[32m$Email\033[m
                    Whoami : \033[32m$UserName\033[m
Script Location    : \033[32m$0\033[m
Default Info       :--------------------------------------------------
        \033[32mThese Will Be Used If You Did Not Set Them\033[m
Default Email      : \033[32m$mymail\033[m
Default Admin User : \033[32m$user2\033[m
Default SSH IP     : \033[32m$sship\033[m
Default SSH        : \033[32m$sshd\033[m
Default IRC        : \033[32m$irc1\033[m \033[32m$irc2\033[m \033[32m$irc3\033[m \033[32m$irc4\033[m \033[32m$irc5\033[m \033[32m$irc6\033[m 
Default IRC SSL    : \033[32m$irc7\033[m
Connection Info    :-----------------------------------------------
  Gateway: \033[32m$DEFAULT_ROUTE\033[m Interface: \033[32m$IFACE\033[m MyIP: \033[32m$myipad\033[m
\033[34m################################################################\033[m"


select menusel in "Change Variables" "IPTables" "Update Ubuntu Repos" "Installs" "Hardening" "Extras" "Credits" "EXIT PROGRAM"; do
case $menusel in
  "Change Variables")
    chvars
    exit 1
    sleep 3
	intr22
    clear ;;

	"Update Ubuntu Repos")
		uprep
		pause
		insta33
		clear ;;

	"IPTables")
		tables3
		clear ;;

	"Installs")
		insta33
		clear ;;

	"Hardening")
		syshard
		clear ;;

	"Extras")
		extras6
		pause
		clear ;;

	"Credits")
		credits2
		pause
		clear ;;

	"EXIT PROGRAM")
		clear && exit 0 ;;
		
	* )
		screwup
		clear ;;
esac

break

done
}

while true; do mainmenu; done
