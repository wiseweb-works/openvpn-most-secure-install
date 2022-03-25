#!/bin/bash
# Shellcheck adlı siteye ufak düzeltmeler için teşekkürler.

# Debian ve Ubuntu için en güvenli OpenVPN sunucu yükleyicisi.
# https://github.com/wiseweb-works/openvpn-most-secure-install

function isRoot() {
	if [ "$EUID" -ne 0 ]; then
		return 1
	fi
}

function tunAvailable() {
	if [ ! -e /dev/net/tun ]; then
		return 1
	fi
}

function checkOS() {
	if [[ -e /etc/debian_version ]]; then
		OS="debian"
		source /etc/os-release

		if [[ $ID == "debian" ]]; then
			if [[ $VERSION_ID -lt 9 ]]; then
				echo "⚠️ Debian sürümünüz desteklenmiyor."
				echo ""
				echo "Ancak, Debian >= 9 kullanıyorsanız veya kararsız/test kullanıyorsanız, riski size ait olmak üzere devam edebilirsiniz."
				echo ""
				until [[ $CONTINUE =~ (e|h) ]]; do
					read -rp "Devam? [e/h]: " -e CONTINUE
				done
				if [[ $CONTINUE == "h" ]]; then
					exit 1
				fi
			fi
		elif [[ $ID == "ubuntu" ]]; then
			OS="ubuntu"
			MAJOR_UBUNTU_VERSION=$(echo "$VERSION_ID" | cut -d '.' -f1)
			if [[ $MAJOR_UBUNTU_VERSION -lt 16 ]]; then
				echo "⚠️ Ubuntu sürümünüz desteklenmiyor."
				echo ""
				echo "Ancak, Ubuntu >= 16.04 veya beta kullanıyorsanız, riski size ait olmak üzere devam edebilirsiniz."
				echo ""
				until [[ $CONTINUE =~ (e|h) ]]; do
					read -rp "Devam? [e/h]: " -e CONTINUE
				done
				if [[ $CONTINUE == "h" ]]; then
					exit 1
				fi
			fi
		fi

		# İlerleyen zamanlarda belki bu sürümleri destekleyebiliriz.
	elif [[ -e /etc/system-release ]]; then
			source /etc/os-release
			if [[ $ID == "fedora" || $ID_LIKE == "fedora" ]]; then
				OS="fedora"
			fi
			if [[ $ID == "centos" || $ID == "rocky" || $ID == "almalinux" ]]; then
				OS="centos"
					echo "⚠️ İşletim sisteminiz desteklenmiyor."
					echo ""
					echo "Komut dosyası yalnızca Ubuntu ve Debian'ı destekler."
					echo ""
					exit 1
			fi
			if [[ $ID == "ol" ]]; then
				OS="oracle"
					echo "⚠️ İşletim sisteminiz desteklenmiyor."
					echo ""
					echo "Komut dosyası yalnızca Ubuntu ve Debian'ı destekler."
					exit 1
			fi
			if [[ $ID == "amzn" ]]; then
				OS="amzn"
					echo "⚠️ İşletim sisteminiz desteklenmiyor."
					echo ""
					echo "Komut dosyası yalnızca Ubuntu ve Debian'ı destekler."
					echo ""
					exit 1
			fi
		elif [[ -e /etc/arch-release ]]; then
			OS=arch

	else
		echo "Bu yükleyiciyi bir Debian veya Ubuntu sisteminde çalıştırmıyorsunuz gibi görünüyor"
		exit 1
	fi
}

function initialCheck() {
	if ! isRoot; then
		echo "Üzgünüm, bunu root yetkisiyle çalıştırmanız gerekiyor"
		exit 1
	fi
	if ! tunAvailable; then
		echo "TUN mevcut değil"
		exit 1
	fi
	checkOS
}

function installUnbound() {
	# Unbound kurulu değilse kuralım
	if [[ ! -e /etc/unbound/unbound.conf ]]; then

		if [[ $OS =~ (debian|ubuntu) ]]; then
			apt-get install -y unbound

			# Yapılandırma
			echo 'interface: 10.8.0.1
access-control: 10.8.0.1/24 allow
hide-identity: yes
hide-version: yes
use-caps-for-id: yes
prefetch: yes' >>/etc/unbound/unbound.conf

			if [[ ! -f /etc/unbound/unbound.conf.old ]]; then
				mv /etc/unbound/unbound.conf /etc/unbound/unbound.conf.old
			fi

			echo 'server:
	use-syslog: yes
	do-daemonize: no
	username: "unbound"
	directory: "/etc/unbound"
	trust-anchor-file: trusted-key.key
	root-hints: root.hints
	interface: 10.8.0.1
	access-control: 10.8.0.1/24 allow
	port: 53
	num-threads: 2
	use-caps-for-id: yes
	harden-glue: yes
	hide-identity: yes
	hide-version: yes
	qname-minimisation: yes
	prefetch: yes' >/etc/unbound/unbound.conf
		fi

		# Tüm işletim sistemleri için IPv6 DNS
		if [[ $IPV6_SUPPORT == 'y' ]]; then
			echo 'interface: fd42:42:42:42::1
access-control: fd42:42:42:42::/112 allow' >>/etc/unbound/unbound.conf
		fi

		if [[ ! $OS =~ (fedora|centos|amzn|oracle) ]]; then
			# DNS Rebinding sorunu çözümü
			echo "private-address: 10.0.0.0/8
private-address: fd42:42:42:42::/112
private-address: 172.16.0.0/12
private-address: 192.168.0.0/16
private-address: 169.254.0.0/16
private-address: fd00::/8
private-address: fe80::/10
private-address: 127.0.0.0/8
private-address: ::ffff:0:0/96" >>/etc/unbound/unbound.conf
		fi
	else
		echo 'include: /etc/unbound/openvpn.conf' >>/etc/unbound/unbound.conf

		# OpenVPN alt ağı için Unbound 'sunucusu' ekleyin
		echo 'server:
interface: 10.8.0.1
access-control: 10.8.0.1/24 allow
hide-identity: yes
hide-version: yes
use-caps-for-id: yes
prefetch: yes
private-address: 10.0.0.0/8
private-address: fd42:42:42:42::/112
private-address: 172.16.0.0/12
private-address: 192.168.0.0/16
private-address: 169.254.0.0/16
private-address: fd00::/8
private-address: fe80::/10
private-address: 127.0.0.0/8
private-address: ::ffff:0:0/96' >/etc/unbound/openvpn.conf
		if [[ $IPV6_SUPPORT == 'y' ]]; then
			echo 'interface: fd42:42:42:42::1
access-control: fd42:42:42:42::/112 allow' >>/etc/unbound/openvpn.conf
		fi
	fi

	systemctl enable unbound
	systemctl restart unbound
}

function installQuestions() {
	echo "OpenVPN yükleyicisine hoş geldiniz!"
	echo "Github repomuz için: https://github.com/wiseweb-works/openvpn-most-secure-install"
	echo ""

	echo "Kuruluma başlamadan önce size birkaç soru sormam gerekiyor."
	echo "Varsayılan seçenekleri bırakıp, uygunsanız enter'a basabilirsiniz."
	echo ""
	echo "OpenVPN'in dinlemesini istediğiniz ağ arayüzünün IPv4 adresinizi belirlemesi gerekiyor."
	echo "Sunucunuz NAT'ın arkasında değilse, bu sizin genel IPv4 adresiniz olmalıdır."

	# Genel IPv4 adresini tespit edelim ve kullanıcı için önceden dolduralım
	IP=$(ip -4 addr | sed -ne 's|^.* inet \([^/]*\)/.* scope global.*$|\1|p' | head -1)

	if [[ -z $IP ]]; then
		# Genel IPv6 adresini algılayalım
		IP=$(ip -6 addr | sed -ne 's|^.* inet6 \([^/]*\)/.* scope global.*$|\1|p' | head -1)
	fi
	APPROVE_IP=${APPROVE_IP:-n}
	if [[ $APPROVE_IP =~ n ]]; then
		read -rp "IP addresi: " -e -i "$IP" IP
	fi
	# $IP özel bir IP adresiyse, sunucu NAT arkasında olmalıdır.
	if echo "$IP" | grep -qE '^(10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168)'; then
		echo ""
		echo "Görünüşe göre sunucunuz NAT'ın arkasında. Genel IPv4 adresiniz veya ana bilgisayar adınız nedir?"
		echo "İstemcileriniz sunucuya bağlanması için bu bilgiye gerek olacaktır."

		PUBLICIP=$(curl -s https://api.ipify.org)
		until [[ $ENDPOINT != "" ]]; do
			read -rp "Genel IPv4 adresi veya ana bilgisayar adım: " -e -i "$PUBLICIP" ENDPOINT
		done
	fi

	echo ""
	echo "IPv6 bağlantınız kontrol ediliyor..."
	echo ""
	# "ping6" ve "ping -6" kullanılabilirliği dağıtıma göre değişir
	if type ping6 >/dev/null 2>&1; then
		PING6="ping6 -c3 ipv6.google.com > /dev/null 2>&1"
	else
		PING6="ping -6 -c3 ipv6.google.com > /dev/null 2>&1"
	fi
	if eval "$PING6"; then
		echo "Ana makineniz IPv6 bağlantısına sahip görünüyor."
		SUGGESTION="y"
	else
		echo "Ana makinenizin IPv6 bağlantısına sahip olmadığı görülüyor."
		SUGGESTION="n"
	fi
	echo ""
	# Kullanılabilirliğinden bağımsız olarak kullanıcıya IPv6'yı etkinleştirmek isteyip istemediğini soralım.
	until [[ $IPV6_SUPPORT =~ (e|h) ]]; do
		read -rp "IPv6 desteğini (NAT) etkinleştirmek istiyor musunuz? [e/h]: " -e -i $SUGGESTION IPV6_SUPPORT
	done
	echo ""
	echo "OpenVPN'in hangi bağlantı noktasını dinlemesini istiyorsunuz?"
	echo " 1) Varsayılan: 1194"
	echo " 2) Özel"
	echo " 3) Rastgele [49152-65535]"
	until [[ $PORT_CHOICE =~ ^[1-3]$ ]]; do
		read -rp "Port tercihim [1-3]: " -e -i 1 PORT_CHOICE
	done
	case $PORT_CHOICE in
	1)
		PORT="1194"
		;;
	2)
		until [[ $PORT =~ ^[0-9]+$ ]] && [ "$PORT" -ge 1 ] && [ "$PORT" -le 65535 ]; do
			read -rp "Özel port [1-65535]: " -e -i 1194 PORT
		done
		;;
	3)
		# Özel bağlantı noktaları aralığında rasgele sayı üretelim
		PORT=$(shuf -i49152-65535 -n1)
		echo "Rastgele Port: $PORT"
		;;
	esac
	echo ""
	echo "OpenVPN'in hangi protokolü kullanmasını istiyorsunuz?"
	echo "UDP daha hızlıdır. Ancak mevcut değilse TCP kullanmalısınız."
	echo "   1) UDP"
	echo "   2) TCP"
	until [[ $PROTOCOL_CHOICE =~ ^[1-2]$ ]]; do
		read -rp "Protokol [1-2]: " -e -i 1 PROTOCOL_CHOICE
	done
	case $PROTOCOL_CHOICE in
	1)
		PROTOCOL="udp"
		;;
	2)
		PROTOCOL="tcp"
		;;
	esac
	echo ""
	echo "VPN ile hangi DNS çözümleyicisini kullanmak istiyorsunuz?"
	echo " 1) Mevcut sistem çözümleyicileri (/etc/resolv.conf'dan)"
	echo " 2) Kendinden Barındırılan DNS Çözümleyici (Bağımsız)"
	echo " 3) Cloudflare (Dünya Çapında)"
	echo " 4) Quad9 (Dünya Çapında)"
	echo " 5) Quad9 sansürsüz (Dünya Çapında)"
	echo " 6) FDN (Fransa)"
	echo " 7) DNS.WATCH (Almanya)"
	echo " 8) OpenDNS (Dünya Çapında)"
	echo " 9) Google (Dünya Çapında)"
	echo " 10) Yandex Temel (Rusya)"
	echo " 11) AdGuard DNS (Dünya Çapında)"
	echo " 12) NextDNS (Dünya Çapında)"
	echo " 13) Özel"
	until [[ $DNS =~ ^[0-9]+$ ]] && [ "$DNS" -ge 1 ] && [ "$DNS" -le 13 ]; do
		read -rp "DNS [1-12]: " -e -i 11 DNS
		if [[ $DNS == 2 ]] && [[ -e /etc/unbound/unbound.conf ]]; then
			echo ""
			echo "Unbound zaten kurulu."
			echo "OpenVPN istemcilerinizin kullanması için betiğin yapılandırmasına izin verebilirsiniz"
			echo "OpenVPN alt ağı için /etc/unbound/unbound.conf dosyasına ikinci bir sunucu ekleyeceğiz."
			echo "Geçerli yapılandırmada herhangi bir değişiklik yapılmadı."
			echo ""

			until [[ $CONTINUE =~ (e|h) ]]; do
				read -rp "Yapılandırma değişiklikleri Unbound'a uygulansın mı? [e/h]: " -e CONTINUE
			done
			if [[ $CONTINUE == "h" ]]; then
				unset DNS
				unset CONTINUE
			fi
		elif [[ $DNS == "13" ]]; then
			until [[ $DNS1 =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; do
				read -rp "Birincil DNS: " -e DNS1
			done
			until [[ $DNS2 =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; do
				read -rp "İkincil DNS (isteğe bağlı): " -e DNS2
				if [[ $DNS2 == "" ]]; then
					break
				fi
			done
		fi
	done
	echo ""
	echo "Sıkıştırma kullanmak istiyor musunuz? VORACLE saldırısına karşı korumasız olacağı için önerilmez."
	until [[ $COMPRESSION_ENABLED =~ (e|h) ]]; do
		read -rp"Sıkıştırmayı etkinleştirelim mi? [e/h]: " -e -i n COMPRESSION_ENABLED
	done
	if [[ $COMPRESSION_ENABLED == "y" ]]; then
		echo "Hangi sıkıştırma algoritmasını kullanmak istediğinizi seçin: (verimliliğe göre sıralanmıştır)"
		echo "   1) LZ4-v2"
		echo "   2) LZ4"
		echo "   3) LZ0"
		until [[ $COMPRESSION_CHOICE =~ ^[1-3]$ ]]; do
			read -rp"Sıkıştırma algoritması [1-3]: " -e -i 1 COMPRESSION_CHOICE
		done
		case $COMPRESSION_CHOICE in
		1)
			COMPRESSION_ALG="lz4-v2"
			;;
		2)
			COMPRESSION_ALG="lz4"
			;;
		3)
			COMPRESSION_ALG="lzo"
			;;
		esac
	fi
	echo ""
	echo "Şifreleme ayarlarını özelleştirmek istiyor musunuz?"
	echo "Ne yaptığınızı bilmiyorsanız, komut dosyası tarafından sağlanan varsayılan parametrelere bağlı kalmalısınız."
	echo "Ne seçerseniz seçin, komut dosyasında sunulan tüm seçeneklerin yeterli düzeyde güvenli olduğunu unutmayın. (NSA tarafından izlenmiyorsanız elbette)"
	echo "Daha fazla bilgi için https://github.com/wiseweb-works/openvpn-most-secure-install#SSS adresine bakın."
	echo ""
	until [[ $CUSTOMIZE_ENC =~ (e|h) ]]; do
		read -rp "Şifreleme ayarları özelleştirilsin mi? [e/h]: " -e -i n CUSTOMIZE_ENC
	done
	if [[ $CUSTOMIZE_ENC == "n" ]]; then
		# Varsayılan, aklı başında (!) ve hızlı parametreleri seçelim
		CIPHER="AES-128-GCM"
		CERT_TYPE="1" # ECDSA
		CERT_CURVE="prime256v1"
		CC_CIPHER="TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256"
		DH_TYPE="1" # ECDH
		DH_CURVE="prime256v1"
		HMAC_ALG="SHA256"
		TLS_SIG="1" # tls-crypt
	else
		echo ""
		echo "Veri kanalı için kullanmak istediğiniz şifreyi seçin:"
		echo "   1) AES-128-GCM"
		echo "   2) AES-192-GCM"
		echo "   3) AES-256-GCM"
		echo "   4) AES-128-CBC"
		echo "   5) AES-192-CBC"
		echo "   6) AES-256-CBC"
		until [[ $CIPHER_CHOICE =~ ^[1-6]$ ]]; do
			read -rp "Cipher [1-6]: " -e -i 1 CIPHER_CHOICE
		done
		case $CIPHER_CHOICE in
		1)
			CIPHER="AES-128-GCM"
			;;
		2)
			CIPHER="AES-192-GCM"
			;;
		3)
			CIPHER="AES-256-GCM"
			;;
		4)
			CIPHER="AES-128-CBC"
			;;
		5)
			CIPHER="AES-192-CBC"
			;;
		6)
			CIPHER="AES-256-CBC"
			;;
		esac
		echo ""
		echo "Ne tür bir sertifika kullanmak istediğinizi seçin:"
		echo "   1) ECDSA"
		echo "   2) RSA"
		until [[ $CERT_TYPE =~ ^[1-2]$ ]]; do
			read -rp"Sertifika anahtarı türü [1-2]: " -e -i 1 CERT_TYPE
		done
		case $CERT_TYPE in
		1)
			echo ""
			echo "Sertifikanın anahtarı için kullanmak istediğiniz eğriyi seçin:"
			echo "   1) prime256v1"
			echo "   2) secp384r1"
			echo "   3) secp521r1"
			until [[ $CERT_CURVE_CHOICE =~ ^[1-3]$ ]]; do
				read -rp"Eğri [1-3]: " -e -i 1 CERT_CURVE_CHOICE
			done
			case $CERT_CURVE_CHOICE in
			1)
				CERT_CURVE="prime256v1"
				;;
			2)
				CERT_CURVE="secp384r1"
				;;
			3)
				CERT_CURVE="secp521r1"
				;;
			esac
			;;
		2)
			echo ""
			echo "Sertifikanın RSA anahtarı için kullanmak istediğiniz boyutu seçin:"
			echo "   1) 2048 bit"
			echo "   2) 3072 bit"
			echo "   3) 4096 bit"
			until [[ $RSA_KEY_SIZE_CHOICE =~ ^[1-3]$ ]]; do
				read -rp "RSA anahtar boyutu [1-3]: " -e -i 1 RSA_KEY_SIZE_CHOICE
			done
			case $RSA_KEY_SIZE_CHOICE in
			1)
				RSA_KEY_SIZE="2048"
				;;
			2)
				RSA_KEY_SIZE="3072"
				;;
			3)
				RSA_KEY_SIZE="4096"
				;;
			esac
			;;
		esac
		echo ""
		echo "Kontrol kanalı için kullanmak istediğiniz şifreyi seçin:"
		case $CERT_TYPE in
		1)
			echo "   1) ECDHE-ECDSA-AES-128-GCM-SHA256"
			echo "   2) ECDHE-ECDSA-AES-256-GCM-SHA384"
			until [[ $CC_CIPHER_CHOICE =~ ^[1-2]$ ]]; do
				read -rp"Kontrol kanalı şifresi [1-2]: " -e -i 1 CC_CIPHER_CHOICE
			done
			case $CC_CIPHER_CHOICE in
			1)
				CC_CIPHER="TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256"
				;;
			2)
				CC_CIPHER="TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384"
				;;
			esac
			;;
		2)
			echo "   1) ECDHE-RSA-AES-128-GCM-SHA256"
			echo "   2) ECDHE-RSA-AES-256-GCM-SHA384"
			until [[ $CC_CIPHER_CHOICE =~ ^[1-2]$ ]]; do
				read -rp"Kontrol kanalı şifresi [1-2]: " -e -i 1 CC_CIPHER_CHOICE
			done
			case $CC_CIPHER_CHOICE in
			1)
				CC_CIPHER="TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256"
				;;
			2)
				CC_CIPHER="TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384"
				;;
			esac
			;;
		esac
		echo ""
		echo "Ne tür bir Diffie-Hellman anahtarı kullanmak istediğinizi seçin:"
		echo "   1) ECDH"
		echo "   2) DH"
		until [[ $DH_TYPE =~ [1-2] ]]; do
			read -rp"DH anahtar tipi [1-2]: " -e -i 1 DH_TYPE
		done
		case $DH_TYPE in
		1)
			echo ""
			echo "ECDH anahtarı için kullanmak istediğiniz eğriyi seçin:"
			echo "   1) prime256v1"
			echo "   2) secp384r1"
			echo "   3) secp521r1"
			while [[ $DH_CURVE_CHOICE != "1" && $DH_CURVE_CHOICE != "2" && $DH_CURVE_CHOICE != "3" ]]; do
				read -rp"Eğri [1-3]: " -e -i 1 DH_CURVE_CHOICE
			done
			case $DH_CURVE_CHOICE in
			1)
				DH_CURVE="prime256v1"
				;;
			2)
				DH_CURVE="secp384r1"
				;;
			3)
				DH_CURVE="secp521r1"
				;;
			esac
			;;
		2)
			echo ""
			echo "Hangi boyutta Diffie-Hellman anahtarı kullanmak istediğinizi seçin:"
			echo "   1) 2048 bits (üretmesi daha kısa sürer)"
			echo "   2) 3072 bits"
			echo "   3) 4096 bits (daha güvenli ama üretmesi çok uzun sürer)"
			until [[ $DH_KEY_SIZE_CHOICE =~ ^[1-3]$ ]]; do
				read -rp "DH anahtar boyutu [1-3]: " -e -i 1 DH_KEY_SIZE_CHOICE
			done
			case $DH_KEY_SIZE_CHOICE in
			1)
				DH_KEY_SIZE="2048"
				;;
			2)
				DH_KEY_SIZE="3072"
				;;
			3)
				DH_KEY_SIZE="4096"
				;;
			esac
			;;
		esac
		echo ""
		# "Doğrulama" seçenekleri, AEAD şifrelerinden farklı davranır
		if [[ $CIPHER =~ CBC$ ]]; then
			echo "Özet algoritması, kontrol kanalından veri kanalı paketlerinin ve tls-auth paketlerinin kimliğini doğrular."
		elif [[ $CIPHER =~ GCM$ ]]; then
			echo "Özet algoritması, kontrol kanalından tls-auth paketlerinin kimliğini doğrular."
		fi
		echo "HMAC için hangi özet algoritmasını kullanmak istiyorsunuz?"
		echo "   1) SHA-256"
		echo "   2) SHA-384"
		echo "   3) SHA-512"
		until [[ $HMAC_ALG_CHOICE =~ ^[1-3]$ ]]; do
			read -rp "Özet algoritması [1-3]: " -e -i 1 HMAC_ALG_CHOICE
		done
		case $HMAC_ALG_CHOICE in
		1)
			HMAC_ALG="SHA256"
			;;
		2)
			HMAC_ALG="SHA384"
			;;
		3)
			HMAC_ALG="SHA512"
			;;
		esac
		echo ""
		echo "tls-auth ve tls-crypt ile kontrol kanalına ek bir güvenlik katmanı ekleyebilirsiniz"
		echo "tls-auth paketlerin kimliğini doğrular, tls-crypt ise onları doğrular ve şifreler."
		echo "   1) tls-crypt"
		echo "   2) tls-auth"
		until [[ $TLS_SIG =~ [1-2] ]]; do
			read -rp "Kontrol kanalı ek güvenlik mekanizması [1-2]: " -e -i 1 TLS_SIG
		done
	fi
	echo ""
	echo "Tamam, ihtiyacımız olan tek şey buydu. Artık OpenVPN sunucunuzu kurmaya hazırız."
	echo "Kurulumun sonunda bir istemci oluşturabileceksiniz."
	APPROVE_INSTALL=${APPROVE_INSTALL:-n}
	if [[ $APPROVE_INSTALL =~ n ]]; then
		read -n1 -r -p "Devam etmek için herhangi bir tuşa basın..."
	fi
}

function installOpenVPN() {
	if [[ $AUTO_INSTALL == "y" ]]; then
		# Varsayılan seçenekleri ayarlayın, böylece hiçbir soru sorulmayacak.
		APPROVE_INSTALL=${APPROVE_INSTALL:-y}
		APPROVE_IP=${APPROVE_IP:-y}
		IPV6_SUPPORT=${IPV6_SUPPORT:-n}
		PORT_CHOICE=${PORT_CHOICE:-1}
		PROTOCOL_CHOICE=${PROTOCOL_CHOICE:-1}
		DNS=${DNS:-1}
		COMPRESSION_ENABLED=${COMPRESSION_ENABLED:-n}
		CUSTOMIZE_ENC=${CUSTOMIZE_ENC:-n}
		CLIENT=${CLIENT:-client}
		PASS=${PASS:-1}
		CONTINUE=${CONTINUE:-y}

		# NAT'ın arkasında, varsayılan olarak herkesin erişebileceği IPv4/IPv6'yı tespit edeceğiz
		if [[ $IPV6_SUPPORT == "y" ]]; then
			PUBLIC_IP=$(curl --retry 5 --retry-connrefused https://ifconfig.co)
		else
			PUBLIC_IP=$(curl --retry 5 --retry-connrefused -4 https://ifconfig.co)
		fi
		ENDPOINT=${ENDPOINT:-$PUBLIC_IP}
	fi

	# Önce kurulum sorularını çalıştıralım ve otomatik kurulum varsa diğer değişkenleri ayarlayalım
	installQuestions

	# Get the "public" interface from the default route
	NIC=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
	if [[ -z $NIC ]] && [[ $IPV6_SUPPORT == 'y' ]]; then
		NIC=$(ip -6 route show default | sed -ne 's/^default .* dev \([^ ]*\) .*$/\1/p')
	fi

	# $NIC, open-kurallarini-sil.sh komut dosyası için boş olamaz
	if [[ -z $NIC ]]; then
		echo
		echo "Genel arayüz algılanamıyor."
		echo "MASQUERADE kurulumu için bu gereklidir."
		until [[ $CONTINUE =~ (e|h) ]]; do
			read -rp "Devam? [e/h]: " -e CONTINUE
		done
		if [[ $CONTINUE == "h" ]]; then
			exit 1
		fi
	fi

	# OpenVPN henüz kurulu değilse kurun.
	# Bu komut dosyası, birden çok çalıştırmada aşağı yukarı önemsizdir,
	# ancak OpenVPN'i yalnızca ilk kez yükleyecektir.
	if [[ ! -e /etc/openvpn/server.conf ]]; then
		if [[ $OS =~ (debian|ubuntu) ]]; then
			apt-get update
			apt-get -y install ca-certificates gnupg
			# En son sürümü almak için OpenVPN deposunu ekliyoruz.
			if [[ $VERSION_ID == "16.04" ]]; then
				echo "deb http://build.openvpn.net/debian/openvpn/stable xenial main" >/etc/apt/sources.list.d/openvpn.list
				wget -O - https://swupdate.openvpn.net/repos/repo-public.gpg | apt-key add -
				apt-get update
			fi
			# Ubuntu > 16.04 ve Debian > 8, üçüncü taraf deposuna ihtiyaç duymadan OpenVPN >= 2.4'e sahiptir.
			apt-get install -y openvpn iptables openssl wget ca-certificates curl
		# Bazı openvpn paketlerinde varsayılan olarak easy-rsa'nın eski bir sürümü mevcuttu
		if [[ -d /etc/openvpn/easy-rsa/ ]]; then
			rm -rf /etc/openvpn/easy-rsa/
		fi
		fi
	fi

	# Makinenin izinsiz grup için "nogroup" kullanıp kullanmadığını veya "nobody" kullanıp kullanmadığını öğrenin
	if grep -qs "^nogroup:" /etc/group; then
		NOGROUP=nogroup
	else
		NOGROUP=nobody
	fi

	# Henüz yüklenmemişse, kaynaktan easy-rsa'nın (kontrol ettiğim) en son sürümünü yükleyelim.
	if [[ ! -d /etc/openvpn/easy-rsa/ ]]; then
		local version="3.0.8" # En güncel versiyon 03.2022 için.
		wget -O ~/easy-rsa.tgz https://github.com/OpenVPN/easy-rsa/releases/download/v${version}/EasyRSA-${version}.tgz
		mkdir -p /etc/openvpn/easy-rsa
		tar xzf ~/easy-rsa.tgz --strip-components=1 --directory /etc/openvpn/easy-rsa
		rm -f ~/easy-rsa.tgz

		cd /etc/openvpn/easy-rsa/ || return
		case $CERT_TYPE in
		1)
			echo "set_var EASYRSA_ALGO ec" >vars
			echo "set_var EASYRSA_CURVE $CERT_CURVE" >>vars
			;;
		2)
			echo "set_var EASYRSA_KEY_SIZE $RSA_KEY_SIZE" >vars
			;;
		esac

		# CN için 16 karakterden ve sunucu adı için bir karakterden oluşan rastgele, alfasayısal bir tanımlayıcı oluşturun
		SERVER_CN="cn_$(head /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 16 | head -n 1)"
		echo "$SERVER_CN" >SERVER_CN_GENERATED
		SERVER_NAME="server_$(head /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 16 | head -n 1)"
		echo "$SERVER_NAME" >SERVER_NAME_GENERATED

		echo "set_var EASYRSA_REQ_CN $SERVER_CN" >>vars

		# PKI'yi oluşturup, CA'yı, DH parametrelerini ve sunucu sertifikasını ayarlayalım
		./easyrsa init-pki
		./easyrsa --batch build-ca nopass

		if [[ $DH_TYPE == "2" ]]; then
			# ECDH anahtarları anında oluşturulur, bu nedenle onları önceden oluşturmamız gerekmez
			openssl dhparam -out dh.pem $DH_KEY_SIZE
		fi

		./easyrsa build-server-full "$SERVER_NAME" nopass
		EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl

		case $TLS_SIG in
		1)
			# tls-crypt anahtarı oluştur
			openvpn --genkey --secret /etc/openvpn/tls-crypt.key
			;;
		2)
			# tls-auth anahtarı oluştur
			openvpn --genkey --secret /etc/openvpn/tls-auth.key
			;;
		esac
	else
		# easy-rsa zaten kuruluysa, istemci yapılandırmaları için oluşturulan
		# SERVER_NAME dosyasını alın
		cd /etc/openvpn/easy-rsa/ || return
		SERVER_NAME=$(cat SERVER_NAME_GENERATED)
	fi

	# Oluşturulan tüm dosyaları taşı
	cp pki/ca.crt pki/private/ca.key "pki/issued/$SERVER_NAME.crt" "pki/private/$SERVER_NAME.key" /etc/openvpn/easy-rsa/pki/crl.pem /etc/openvpn
	if [[ $DH_TYPE == "2" ]]; then
		cp dh.pem /etc/openvpn
	fi

	# Kök olmayanlar kullanıcılar için sertifika iptal listesini okunabilir yap
	chmod 644 /etc/openvpn/crl.pem

	# server.conf dosyasını oluştur
	echo "port $PORT" >/etc/openvpn/server.conf
	if [[ $IPV6_SUPPORT == 'n' ]]; then
		echo "proto $PROTOCOL" >>/etc/openvpn/server.conf
	elif [[ $IPV6_SUPPORT == 'y' ]]; then
		echo "proto ${PROTOCOL}6" >>/etc/openvpn/server.conf
	fi

	echo "dev tun
user nobody
group $NOGROUP
persist-key
persist-tun
keepalive 10 120
topology subnet
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt" >>/etc/openvpn/server.conf

	# DNS çözümleyicileri ayarlamaları
	case $DNS in
	1) # systemd-resolved çalıştıran sistemler için gerekli
		if grep -q "127.0.0.53" "/etc/resolv.conf"; then
			RESOLVCONF='/run/systemd/resolve/resolv.conf'
		else
			RESOLVCONF='/etc/resolv.conf'
		fi
		# Çözücüleri resolv.conf'tan alın ve OpenVPN için kullanın
		sed -ne 's/^nameserver[[:space:]]\+\([^[:space:]]\+\).*$/\1/p' $RESOLVCONF | while read -r line; do
			# IPv4 ise veya IPv6 etkinse kopyalayın, IPv4/IPv6 önemli değil
			if [[ $line =~ ^[0-9.]*$ ]] || [[ $IPV6_SUPPORT == 'y' ]]; then
				echo "push \"dhcp-option DNS $line\"" >>/etc/openvpn/server.conf
			fi
		done
		;;
	2) # Kendinden barındırılan DNS çözümleyici (Unbound)
		echo 'push "dhcp-option DNS 10.8.0.1"' >>/etc/openvpn/server.conf
		if [[ $IPV6_SUPPORT == 'y' ]]; then
			echo 'push "dhcp-option DNS fd42:42:42:42::1"' >>/etc/openvpn/server.conf
		fi
		;;
	3) # Cloudflare
		echo 'push "dhcp-option DNS 1.0.0.1"' >>/etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 1.1.1.1"' >>/etc/openvpn/server.conf
		;;
	4) # Quad9
		echo 'push "dhcp-option DNS 9.9.9.9"' >>/etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 149.112.112.112"' >>/etc/openvpn/server.conf
		;;
	5) # Quad9 sansürsüz
		echo 'push "dhcp-option DNS 9.9.9.10"' >>/etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 149.112.112.10"' >>/etc/openvpn/server.conf
		;;
	6) # FDN
		echo 'push "dhcp-option DNS 80.67.169.40"' >>/etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 80.67.169.12"' >>/etc/openvpn/server.conf
		;;
	7) # DNS.WATCH
		echo 'push "dhcp-option DNS 84.200.69.80"' >>/etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 84.200.70.40"' >>/etc/openvpn/server.conf
		;;
	8) # OpenDNS
		echo 'push "dhcp-option DNS 208.67.222.222"' >>/etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 208.67.220.220"' >>/etc/openvpn/server.conf
		;;
	9) # Google
		echo 'push "dhcp-option DNS 8.8.8.8"' >>/etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 8.8.4.4"' >>/etc/openvpn/server.conf
		;;
	10) # Yandex Basic
		echo 'push "dhcp-option DNS 77.88.8.8"' >>/etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 77.88.8.1"' >>/etc/openvpn/server.conf
		;;
	11) # AdGuard DNS
		echo 'push "dhcp-option DNS 94.140.14.14"' >>/etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 94.140.15.15"' >>/etc/openvpn/server.conf
		;;
	12) # NextDNS
		echo 'push "dhcp-option DNS 45.90.28.167"' >>/etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 45.90.30.167"' >>/etc/openvpn/server.conf
		;;
	13) # Custom DNS
		echo "push \"dhcp-option DNS $DNS1\"" >>/etc/openvpn/server.conf
		if [[ $DNS2 != "" ]]; then
			echo "push \"dhcp-option DNS $DNS2\"" >>/etc/openvpn/server.conf
		fi
		;;
	esac
	echo 'push "redirect-gateway def1 bypass-dhcp"' >>/etc/openvpn/server.conf

	# Gerekirse diye IPv6 ağ ayarları
	if [[ $IPV6_SUPPORT == 'y' ]]; then
		echo 'server-ipv6 fd42:42:42:42::/112
tun-ipv6
push tun-ipv6
push "route-ipv6 2000::/3"
push "redirect-gateway ipv6"' >>/etc/openvpn/server.conf
	fi

	if [[ $COMPRESSION_ENABLED == "y" ]]; then
		echo "compress $COMPRESSION_ALG" >>/etc/openvpn/server.conf
	fi

	if [[ $DH_TYPE == "1" ]]; then
		echo "dh none" >>/etc/openvpn/server.conf
		echo "ecdh-curve $DH_CURVE" >>/etc/openvpn/server.conf
	elif [[ $DH_TYPE == "2" ]]; then
		echo "dh dh.pem" >>/etc/openvpn/server.conf
	fi

	case $TLS_SIG in
	1)
		echo "tls-crypt tls-crypt.key" >>/etc/openvpn/server.conf
		;;
	2)
		echo "tls-auth tls-auth.key 0" >>/etc/openvpn/server.conf
		;;
	esac

	echo "crl-verify crl.pem
ca ca.crt
cert $SERVER_NAME.crt
key $SERVER_NAME.key
auth $HMAC_ALG
cipher $CIPHER
ncp-ciphers $CIPHER
tls-server
tls-version-min 1.2
tls-cipher $CC_CIPHER
client-config-dir /etc/openvpn/ccd
status /var/log/openvpn/status.log
verb 3" >>/etc/openvpn/server.conf

	# client-config-dir dizini oluştur
	mkdir -p /etc/openvpn/ccd
	# Günlük dizini oluştur
	mkdir -p /var/log/openvpn

	# Yönlendirmeyi etkinleştir
	echo 'net.ipv4.ip_forward=1' >/etc/sysctl.d/99-openvpn.conf
	if [[ $IPV6_SUPPORT == 'y' ]]; then
		echo 'net.ipv6.conf.all.forwarding=1' >>/etc/sysctl.d/99-openvpn.conf
	fi
	# sysctl kurallarını uygula
	sysctl --system

	# Son olarak, OpenVPN'i yeniden başlatın ve etkinleştirin
	if [[ $OS == 'arch' || $OS == 'fedora' || $OS == 'centos' || $OS == 'oracle' ]]; then
		# Paket tarafından sağlanan hizmeti değiştirmiyoruz
		cp /usr/lib/systemd/system/openvpn-server@.service /etc/systemd/system/openvpn-server@.service

		# OpenVPN hizmetini OpenVZ'de düzeltmek için geçici çözüm
		sed -i 's|LimitNPROC|#LimitNPROC|' /etc/systemd/system/openvpn-server@.service
		# /etc/openvpn/ kullanmaya devam etmek için başka bir geçici çözüm
		sed -i 's|/etc/openvpn/server|/etc/openvpn|' /etc/systemd/system/openvpn-server@.service

		systemctl daemon-reload
		systemctl enable openvpn-server@server
		systemctl restart openvpn-server@server
	elif [[ $OS == "ubuntu" ]] && [[ $VERSION_ID == "16.04" ]]; then
		# Ubuntu 16.04'te OpenVPN deposundaki paketi kullanıyoruz
		# Bu paket bir sysvinit hizmeti kullanıyor
		systemctl enable openvpn
		systemctl start openvpn
	else
		# Paket tarafından sağlanan hizmeti değiştirmiyoruz
		cp /lib/systemd/system/openvpn\@.service /etc/systemd/system/openvpn\@.service

		# OpenVPN hizmetini OpenVZ'de düzeltmek için geçici çözüm
		sed -i 's|LimitNPROC|#LimitNPROC|' /etc/systemd/system/openvpn\@.service
		# /etc/openvpn/ kullanmaya devam etmek için başka bir geçici çözüm
		sed -i 's|/etc/openvpn/server|/etc/openvpn|' /etc/systemd/system/openvpn\@.service

		systemctl daemon-reload
		systemctl enable openvpn@server
		systemctl restart openvpn@server
	fi

	if [[ $DNS == 2 ]]; then
		installUnbound
	fi

	# Komut dosyasına iptables kuralları ekleyin
	mkdir -p /etc/iptables

	# Kuralları eklemek için başkaca bir komut dosyası
	echo "#!/bin/sh
iptables -t nat -I POSTROUTING 1 -s 10.8.0.0/24 -o $NIC -j MASQUERADE
iptables -I INPUT 1 -i tun0 -j ACCEPT
iptables -I FORWARD 1 -i $NIC -o tun0 -j ACCEPT
iptables -I FORWARD 1 -i tun0 -o $NIC -j ACCEPT
iptables -I INPUT 1 -i $NIC -p $PROTOCOL --dport $PORT -j ACCEPT" >/etc/iptables/open-kurallari-ekle.sh

	if [[ $IPV6_SUPPORT == 'y' ]]; then
		echo "ip6tables -t nat -I POSTROUTING 1 -s fd42:42:42:42::/112 -o $NIC -j MASQUERADE
ip6tables -I INPUT 1 -i tun0 -j ACCEPT
ip6tables -I FORWARD 1 -i $NIC -o tun0 -j ACCEPT
ip6tables -I FORWARD 1 -i tun0 -o $NIC -j ACCEPT
ip6tables -I INPUT 1 -i $NIC -p $PROTOCOL --dport $PORT -j ACCEPT" >>/etc/iptables/open-kurallari-ekle.sh
	fi

	# Kuralları kaldırmak için başkaca bir komut dosyası
	echo "#!/bin/sh
iptables -t nat -D POSTROUTING -s 10.8.0.0/24 -o $NIC -j MASQUERADE
iptables -D INPUT -i tun0 -j ACCEPT
iptables -D FORWARD -i $NIC -o tun0 -j ACCEPT
iptables -D FORWARD -i tun0 -o $NIC -j ACCEPT
iptables -D INPUT -i $NIC -p $PROTOCOL --dport $PORT -j ACCEPT" >/etc/iptables/open-kurallarini-sil.sh

	if [[ $IPV6_SUPPORT == 'y' ]]; then
		echo "ip6tables -t nat -D POSTROUTING -s fd42:42:42:42::/112 -o $NIC -j MASQUERADE
ip6tables -D INPUT -i tun0 -j ACCEPT
ip6tables -D FORWARD -i $NIC -o tun0 -j ACCEPT
ip6tables -D FORWARD -i tun0 -o $NIC -j ACCEPT
ip6tables -D INPUT -i $NIC -p $PROTOCOL --dport $PORT -j ACCEPT" >>/etc/iptables/open-kurallarini-sil.sh
	fi

	chmod +x /etc/iptables/open-kurallari-ekle.sh
	chmod +x /etc/iptables/open-kurallarini-sil.sh

	# Bir systemd betiği aracılığıyla kuralları işleyelim
	echo "[Unit]
Description=iptables rules for OpenVPN
Before=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/etc/iptables/open-kurallari-ekle.sh
ExecStop=/etc/iptables/open-kurallarini-sil.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target" >/etc/systemd/system/iptables-openvpn.service

	# Hizmeti etkinleştir ve kuralları uygula
	systemctl daemon-reload
	systemctl enable iptables-openvpn
	systemctl start iptables-openvpn

	# Sunucu bir NAT arkasındaysa, istemcilerin bağlanacağı doğru IP adresini kullanın.
	if [[ $ENDPOINT != "" ]]; then
		IP=$ENDPOINT
	fi

	# istemci-taslagi.txt oluşturuldu, böylece daha sonra başka kullanıcılar eklemek için bir şablonumuz var
	echo "client" >/etc/openvpn/istemci-taslagi.txt
	if [[ $PROTOCOL == 'udp' ]]; then
		echo "proto udp" >>/etc/openvpn/istemci-taslagi.txt
		echo "explicit-exit-notify" >>/etc/openvpn/istemci-taslagi.txt
	elif [[ $PROTOCOL == 'tcp' ]]; then
		echo "proto tcp-client" >>/etc/openvpn/istemci-taslagi.txt
	fi
	echo "remote $IP $PORT
dev tun
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
verify-x509-name $SERVER_NAME name
auth $HMAC_ALG
auth-nocache
cipher $CIPHER
tls-client
tls-version-min 1.2
tls-cipher $CC_CIPHER
ignore-unknown-option block-outside-dns
setenv opt block-outside-dns # Prevent Windows 10 DNS leak
verb 3" >>/etc/openvpn/istemci-taslagi.txt

	if [[ $COMPRESSION_ENABLED == "y" ]]; then
		echo "compress $COMPRESSION_ALG" >>/etc/openvpn/istemci-taslagi.txt
	fi

	# Özel istemci.ovpn'yi oluşturun
	newClient
	echo "Daha fazla istemci eklemek istiyorsanız, bu betiği başka bir zaman çalıştırmanız yeterlidir!"
}

function newClient() {
	echo ""
	echo "Bana istemci için bir isim söyle."
	echo "İsim alfasayısal karakterden oluşmalıdır. Ayrıca bir alt çizgi veya kısa çizgi içerebilir."

	until [[ $CLIENT =~ ^[a-zA-Z0-9_-]+$ ]]; do
		read -rp "İstemci adı :" -e CLIENT
	done

	echo ""
	echo "Yapılandırma dosyasını bir parola ile korumak istiyor musunuz?"
	echo "(ör. özel anahtarı bir parola ile şifreleyin)"
	echo " 1) Parolasız bir istemci ekleyin"
	echo " 2) İstemci için bir parola kullanın"

	until [[ $PASS =~ ^[1-2]$ ]]; do
		read -rp "Bir seçenek seçin [1-2]: " -e -i 1 PASS
	done

	CLIENTEXISTS=$(tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep -c -E "/CN=$CLIENT\$")
	if [[ $CLIENTEXISTS == '1' ]]; then
		echo ""
		echo "Belirtilen istemci ismi easy-rsada zaten bulundu, lütfen başka bir ad seçin."
		exit
	else
		cd /etc/openvpn/easy-rsa/ || return
		case $PASS in
		1)
			./easyrsa build-client-full "$CLIENT" nopass
			;;
		2)
			echo "⚠️ Aşağıda istemci şifresi istenecektir ⚠️"
			./easyrsa build-client-full "$CLIENT"
			;;
		esac
		echo "İstemci $CLIENT oluşturuldu."
	fi

	# İstemci yapılandırmasının yazılacağı kullanıcının ana dizini
	if [ -e "/home/${CLIENT}" ]; then
		# Eğer bir kullanıcı adıysa
		homeDir="/home/${CLIENT}"
	elif [ "${SUDO_USER}" ]; then
		# değilse, SUDO_USER kullanın
		if [ "${SUDO_USER}" == "root" ]; then
			# Kök olarak sudo çalıştırıyorsanız
			homeDir="/root"
		else
			homeDir="/home/${SUDO_USER}"
		fi
	else
		# SUDO_USER değilse, /root kullanın
		homeDir="/root"
	fi

	# tls-auth veya tls-crypt kullanıp kullanmadığımızı belirleyin
	if grep -qs "^tls-crypt" /etc/openvpn/server.conf; then
		TLS_SIG="1"
	elif grep -qs "^tls-auth" /etc/openvpn/server.conf; then
		TLS_SIG="2"
	fi

	# istemci.ovpn'yi oluşturur
	cp /etc/openvpn/istemci-taslagi.txt "$homeDir/$CLIENT.ovpn"
	{
		echo "<ca>"
		cat "/etc/openvpn/easy-rsa/pki/ca.crt"
		echo "</ca>"

		echo "<cert>"
		awk '/BEGIN/,/END/' "/etc/openvpn/easy-rsa/pki/issued/$CLIENT.crt"
		echo "</cert>"

		echo "<key>"
		cat "/etc/openvpn/easy-rsa/pki/private/$CLIENT.key"
		echo "</key>"

		case $TLS_SIG in
		1)
			echo "<tls-crypt>"
			cat /etc/openvpn/tls-crypt.key
			echo "</tls-crypt>"
			;;
		2)
			echo "key-direction 1"
			echo "<tls-auth>"
			cat /etc/openvpn/tls-auth.key
			echo "</tls-auth>"
			;;
		esac
	} >>"$homeDir/$CLIENT.ovpn"

	echo ""
	echo "Yapılandırma dosyası şu adrese yazıldı: $homeDir/$CLIENT.ovpn."
	echo ".ovpn dosyasını indirin ve OpenVPN istemcinize aktarın."

	exit 0
}

function revokeClient() {
	NUMBEROFCLIENTS=$(tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep -c "^V")
	if [[ $NUMBEROFCLIENTS == '0' ]]; then
		echo ""
		echo "Mevcut istemciniz yok!"
		exit 1
	fi

	echo ""
	echo "İptal etmek istediğiniz mevcut istemci sertifikasını seçin"
	tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | nl -s ') '
	until [[ $CLIENTNUMBER -ge 1 && $CLIENTNUMBER -le $NUMBEROFCLIENTS ]]; do
		if [[ $CLIENTNUMBER == '1' ]]; then
			read -rp "Bir istemci seçin[1]: " CLIENTNUMBER
		else
			read -rp "Bir istemciyi seçin [1-$NUMBEROFCLIENTS]: " CLIENTNUMBER
		fi
	done
	CLIENT=$(tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | sed -n "$CLIENTNUMBER"p)
	cd /etc/openvpn/easy-rsa/ || return
	./easyrsa --batch revoke "$CLIENT"
	EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl
	rm -f /etc/openvpn/crl.pem
	cp /etc/openvpn/easy-rsa/pki/crl.pem /etc/openvpn/crl.pem
	chmod 644 /etc/openvpn/crl.pem
	find /home/ -maxdepth 2 -name "$CLIENT.ovpn" -delete
	rm -f "/root/$CLIENT.ovpn"
	sed -i "/^$CLIENT,.*/d" /etc/openvpn/ipp.txt
	cp /etc/openvpn/easy-rsa/pki/index.txt{,.bk}

	echo ""
	echo "$CLIENT istemcisinin sertifikası iptal edildi."
}

function removeUnbound() {
	# OpenVPN ile ilgili yapılandırmayı kaldırın
	sed -i '/include: \/etc\/unbound\/openvpn.conf/d' /etc/unbound/unbound.conf
	rm /etc/unbound/openvpn.conf

	until [[ $REMOVE_UNBOUND =~ (e|h) ]]; do
		echo ""
		echo "OpenVPNi kurmadan önce zaten Unbound kullanıyorsanız, OpenVPN ile ilgili yapılandırmayı kaldırın."
		read -rp "Unboundu tamamen kaldırmak istiyor musunuz?[e/h]: " -e REMOVE_UNBOUND
	done

	if [[ $REMOVE_UNBOUND == 'y' ]]; then
		# Unbound'u durduralım
		systemctl stop unbound

		if [[ $OS =~ (debian|ubuntu) ]]; then
			apt-get remove --purge -y unbound
		fi
		rm -rf /etc/unbound/

		echo ""
		echo "Unbound kaldırıldı!"
	else
		systemctl restart unbound
		echo ""
		echo "Unbound kaldırılamadı!"
	fi
}

function removeOpenVPN() {
	echo ""
	read -rp "OpenVPNi gerçekten kaldırmak istiyor musunuz? [e/h]: " -e -i n REMOVE
	if [[ $REMOVE == 'e' ]]; then
		# Yapılandırmadan OpenVPN bağlantı noktasını alın
		PORT=$(grep '^port ' /etc/openvpn/server.conf | cut -d " " -f 2)
		PROTOCOL=$(grep '^proto ' /etc/openvpn/server.conf | cut -d " " -f 2)
fi
		# OpenVPN'i durdur
		if [[ $OS == "ubuntu" ]] && [[ $VERSION_ID == "16.04" ]]; then
			systemctl disable openvpn
			systemctl stop openvpn
		else
			systemctl disable openvpn@server
			systemctl stop openvpn@server
			# Özelleştirilmiş hizmetleri kaldır
			rm /etc/systemd/system/openvpn\@.service
		fi

		# Komut dosyasıyla ilgili iptables kurallarını kaldırın
		systemctl stop iptables-openvpn
		# Temizlik
		systemctl disable iptables-openvpn
		rm /etc/systemd/system/iptables-openvpn.service
		systemctl daemon-reload
		rm /etc/iptables/open-kurallari-ekle.sh
		rm /etc/iptables/open-kurallarini-sil.sh

		if [[ $OS =~ (debian|ubuntu) ]]; then
			apt-get remove --purge -y openvpn
			if [[ -e /etc/apt/sources.list.d/openvpn.list ]]; then
				rm /etc/apt/sources.list.d/openvpn.list
				apt-get update
			fi

		# Temizlik
		find /home/ -maxdepth 2 -name "*.ovpn" -delete
		find /root/ -maxdepth 1 -name "*.ovpn" -delete
		rm -rf /etc/openvpn
		rm -rf /usr/share/doc/openvpn*
		rm -f /etc/sysctl.d/99-openvpn.conf
		rm -rf /var/log/openvpn

		# Unbound
		if [[ -e /etc/unbound/openvpn.conf ]]; then
			removeUnbound
		fi
		echo ""
		echo "OpenVPN kaldırıldı!"
	else
		echo ""
		echo "Kaldırma işlemi iptal edildi!"
	fi
}

function manageMenu() {
	echo "openvpn-most-güvenli-kurulumuna hoş geldiniz!"
	echo "Git deposu şu adreste mevcuttur: https://github.com/wiseweb-works/openvpn-most-secure-install"
	Eko ""
	echo "OpenVPN zaten kurulu gibi görünüyor."
	Eko ""
	echo "Ne yapmak istiyorsunuz?"
	echo " 1) Yeni bir kullanıcı ekleyin"
	echo " 2) Mevcut kullanıcıyı iptal et"
	echo " 3) OpenVPN'i Kaldır"
	echo " 4) Çık"
	until [[ $MENU_OPTION =~ ^[1-4]$ ]]; do
		read -rp "Select an option [1-4]: " MENU_OPTION
	done

	case $MENU_OPTION in
	1)
		newClient
		;;
	2)
		revokeClient
		;;
	3)
		removeOpenVPN
		;;
	4)
		exit 0
		;;
	esac
}

# Kök yetkisi, TUN, işletim sistemi v.b şeyleri kontrol edelim ...
initialCheck
# OpenVPN'in zaten kurulu olup olmadığını kontrol edelim
if [[ -e /etc/openvpn/server.conf && $AUTO_INSTALL != "y" ]]; then
	manageMenu
else
	installOpenVPN
fi
