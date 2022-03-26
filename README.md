# Özet
![coverage](https://img.shields.io/badge/coverage-80%25-green)
![version](https://img.shields.io/badge/version-0.1-blue)
![codacy](https://img.shields.io/badge/codacy-A-green)
![uptime](https://img.shields.io/badge/uptime-100%25-brightgreen)

[![GitHub issues](https://img.shields.io/github/issues/wiseweb-works/openvpn-most-secure-install)](https://github.com/wiseweb-works/openvpn-most-secure-install/issues)
[![GitHub forks](https://img.shields.io/github/forks/wiseweb-works/openvpn-most-secure-install)](https://github.com/wiseweb-works/openvpn-most-secure-install/network)
[![GitHub license](https://img.shields.io/github/license/wiseweb-works/openvpn-most-secure-install)](https://github.com/wiseweb-works/openvpn-most-secure-install)

Debian ve Ubuntu için OpenVPN yükleyicisi ([Angristan'ın projesinin](https://github.com/angristan/openvpn-install) katkısıyla)

Bu komut dosyası, yalnızca birkaç dakika içinde kendi güvenli VPN sunucunuzu kurmanıza olanak tanır.

<details>
<summary>Ayrıntılar</summary>

### Fihriste

- [Özet](#özet)
  - [Kullanım](#kullanım)
    - [Headless kurulum](#headless-kurulum)
  - [Özellikler](#özellikler)
  - [Uyumluluk](#uyumluluk)
  - [Proje eski yöneticileri](#proje-eski-yöneticileri)
  - [SSS](#sss)
    - [1. Hangi VPS/VDS sağlayıcıyı önerirsiniz ?](#1-hangi-vpsvds-sağlayıcıyı-önerirsiniz-)
    - [2. Hangi OpenVPN istemcisini önerirsiniz ?](#2-hangi-openvpn-istemcisini-önerirsiniz-)
    - [3. NSA'dan/Devletten güvende miyim ?](#3-projenizdeki-scripti-kullanarak-nsadandevletten-güvende-miyim-)
    - [4. OpenVPN için `man/manual` belgeleri var mı ?](#4-openvpn-için-manmanual-belgeleri-var-mı-)  
  - [Katkı](#katkı)
    - [Kod biçimlendirme](#kod-biçimlendirme)
  - [Güvenlik ve Şifreleme](#güvenlik-ve-şifreleme)
    - [Sıkıştırma](#sıkıştırma)
    - [TLS sürümü](#tls-sürümü)
    - [Sertifika](#sertifika)
    - [Veri kanalı](#veri-kanalı)
    - [Kontrol kanalı](#kontrol-kanalı)
    - [Diffie-Hellman anahtar değişimi](#diffie-hellman-anahtar-değişimi)
    - [HMAC özet algoritması](#hmac-özet-algoritması)
    - [`tls-auth` ve `tls-crypt`](#tls-auth-ve-tls-crypt)
  - [Atıf ve Lisans](#atıf-ve-lisans)
- [Son](#son)
</details>

## Kullanım

Önce script dosyamızı indiriyoruz ve komut satırında yürütülebilir hale getiriyoruz:

```bash
curl -O https://raw.githubusercontent.com/wiseweb-works/openvpn-most-secure-install/master/openvpn-most-secure-install.sh
chmod +x openvpn-most-secure-install.sh
```

Ardından kodumuzu çalıştıralım:

```sh
./openvpn-most-secure-install.sh
```

Komut dosyasını root yetkileriyle çalıştırmanız ve TUN modülünü etkinleştirmeniz gerekir.

Kodu ilk defa çalıştırdığınızda, VPN sunucunuzu kurmak için size birkaç soruyu sormamız gerekecek.

OpenVPN kurulduğunda, scripti tekrar çalıştırabilirsiniz. Scripti çalıştırdığınızda karşınıza şu seçenekler çıkacaktır:

- İstemci ekle
- Bir istemciyi kaldırın
- OpenVPN'i kaldırın

Home dizininizde `.ovpn` dosyalarınız olacak. Bunlar istemci yapılandırma dosyalarıdır. Bunları sunucunuzdan indirin ve favori OpenVPN istemcinizi kullanarak bağlanın.

Herhangi bir sorunuz varsa, önce [SSS](#SSS) bölümüne gidin. Lütfen konu açmadan önce her şeyi okuyunuz.

**Bana yardım isteyen e-postalar gönderebilirsiniz.** Fakat daha aktif bir yardım almak ve aynı sorunlarla karşılaşan kişilere de yol haritası olması için Github'ın Issues bölümünü kullanabilirsini.z Böylece siz de diğer insanlara yardımcı olabilir ve gelecekte başka kullanıcılar da sizinle aynı sorunla karşılaştığı zaman daha kısa sürede çözüme ulaşmalarını sağlarsınız. Unutmayın ki açık kaynaklı projeler topluluk desteği olduğu sürece büyür ve belirli bir yere gelir. Lütfen sevdiğiniz ve kullandığınız projeleri destekleyin.

### Headless kurulum

Komut dosyasını headless olarak da çalıştırmak mümkündür, ör. kullanıcı girişi beklemeden, otomatik bir şekilde hazır kurulum.

Örnek kullanım:

```bash
AUTO_INSTALL=y ./openvpn-most-secure-install.sh

# veya

export AUTO_INSTALL=y
./openvpn-most-secure-install.sh
```

## Özellikler

- Kullanıma hazır bir OpenVPN sunucusu kurar ve yapılandırır
- Iptables kuralları ve yönlendirmesini sorunsuz bir şekilde yönetir
- Gerekirse komut dosyası, yapılandırma ve iptables kuralları dahil olmak üzere OpenVPN'i temiz bir şekilde kaldırabilir
- Özelleştirilebilir şifreleme ayarları, gelişmiş varsayılan ayarlar (aşağıdaki [Güvenlik ve Şifreleme](#güvenlik-ve-şifreleme) bölümüne bakın)
- OpenVPN 2.4 özellikleri, özellikle şifreleme iyileştirmeleri (aşağıdaki [Güvenlik ve Şifreleme](#güvenlik-ve-şifreleme) bölümüne bakın)
- İstemcilere gönderilecek çeşitli DNS çözümleyicileri barındırır
- Unbound ile kendi kendine barındırılan bir çözümleyici kullanma seçeneği (zaten mevcut Unbound kurulumlarını destekler)
- TCP ve UDP arasında seçim
- NAT arkasından IPv6 desteği
- VORACLE'ı önlemek için sıkıştırma varsayılan olarak devre dışı bırakıldı. LZ4 (v1/v2) ve LZ0 algoritmaları aksi takdirde kullanılabilir.
- Yetkisiz mod: `nobody`/`nogroup` olarak çalıştırın
- Windows 10'da DNS sızıntılarını engelleyin
- Rastgele sunucu sertifika adı oluşturma
- İstemcileri bir parola ile koruma seçeneği (özel anahtar şifrelemesi)
- Diğer birçok küçük şey! Hepsi sizin güvenliğiniz için

## Uyumluluk

Komut dosyası şu işletim sistemini ve mimarileri destekler:

|                 | i386 | amd64 | armhf | arm64 |
|  | - | -- | -- | -- |
| Amazon Linux    | ❌   | ❌   | ❌    | ❌   |
| Arch Linux      | ❌   | ❌   | ❌    | ❌   |
| CentOS          | ❌   | ❌   | ❌    | ❌   |
| Debian >= 9     | ✅   | ✅   | ✅    | ✅   |
| Fedora          | ❌   | ❌   | ❌    | ❌   |
| Ubuntu 16.04    | ✅   | ✅   | ❌    | ❌   |
| Ubuntu >= 18.04 | ✅   | ✅   | ✅    | ✅   |
| Oracle Linux    | ❌   | ❌   | ❌    | ❌   |
| Rocky Linux     | ❌   | ❌   | ❌    | ❌   |
| AlmaLinux       | ❌   | ❌   | ❌    | ❌   |

Akılda bulundurulacak:

- Debian 9+ ve Ubuntu 16.04+ üzerinde çalışmalıdır. Ancak yukarıdaki tabloda olmayan sürümler **resmi olarak desteklenmemektedir**.
- Komut dosyası `systemd` gerektiriyor.
- Komut dosyası düzenli olarak yalnızca `amd64`e karşı test ediliyor.
- Tabloda desteklenmediği özellikle belirtilen işletim sistemleri için destek sunmayı şu an için düşünmüyoruz.

## Proje eski yöneticileri

Bu komut dosyası, [Nyr](https://github.com/Nyr/openvpn-install) ve [Angristan](https://github.com/angristan/openvpn-install)'ın harika çalışmalarına dayanmaktadır. Kendileri bu projeye 2013 ve 2016 yıllarında başlamış ve 2022 yılına kadar da uzunca bir yol katetmişlerdir. Bu aşamada yol ayrımına giderek projeyi Türkçe bir projeye çevirmek ve kendimce değişiklikler yapmaya karar verdim. Böyleyece eski projeden tamamen farklı bir yol izleyecek bu proje ortaya çıktı.

Benim projem sadece son dağıtımları desteklemek üzerine odaklanmıştır, bu nedenle çok eski bir sunucu veya istemci kullanmanız gerekiyorsa, Nyr'in veya angristan'ın projelerine gözatmanızı öneririm.

## SSS

[Wiki](../../wiki) bölümünde daha fazla Soru-Cevap bulabilirsiniz.

### 1. Hangi VPS/VDS sağlayıcıyı önerirsiniz ?
- Bunları tavsiye ederim:
 - [Vultr](https://www.vultr.com/): Dünya çapında konumlar
 - [Hetzner](https://hetzner.cloud/): Almanya
 - [Digital Ocean](https://digitalocean.com/): Dünya çapında konumlar
 - [Oracle Always Free](https://www.oracle.com/tr/cloud/free/): Dünya çapında konumlar, Aylık 4vCpu ve 24 GB Ram'e kadar ücretsiz

### 2. Hangi OpenVPN istemcisini önerirsiniz ?
- Resmi bir OpenVPN => 2.4 istemcisi. Mümkünse en son versiyonu [Github Sayfasından](https://github.com/OpenVPN/openvpn/tags) indirin.
 - Windows: [Resmi OpenVPN topluluk istemcisi](https://openvpn.net/index.php/download/community-downloads.html).
 - Linux: Dağıtımınızdaki `openvpn` paketi. Debian/Ubuntu tabanlı dağıtımlarınız için bir [resmi APT deposu](https://community.openvpn.net/openvpn/wiki/OpenvpnSoftwareRepos) vardır.
 - macOS: [Mac için Resmi İstemci](https://openvpn.net/client-connect-vpn-for-mac-os/)
 - Android: [Android için OpenVPN](https://play.google.com/store/apps/details?id=de.blinkt.openvpn).
 - iOS: [Resmi OpenVPN Connect istemcisi](https://itunes.apple.com/us/app/openvpn-connect/id590379981).

### 3. Projenizdeki scripti kullanarak NSA'dan/Devletten güvende miyim ?
- Lütfen tehdit modellerinizi inceleyin. Bu komut dosyası aslında oldukças güvenli ve gizlilik öncelikli olsa da size kesinlikle böyle bir söz veremez. Çünkü hiçbir zaman için bir sistem %100 güvenli değildir.

### 4. OpenVPN için `man/manual` belgeleri var mı ?
- Evet, lütfen tüm seçeneklere atıfta bulunan [OpenVPN Kılavuzuna](https://community.openvpn.net/openvpn/wiki/Openvpn24ManPage) gidin.

## Katkı

### Kod biçimlendirme

Bash stil yönergelerini ve iyi uygulamaları uygulamak için [shellcheck](https://github.com/koalaman/shellcheck) kullanıyoruz.

## Güvenlik ve Şifreleme

OpenVPN'in varsayılan ayarları şifreleme konusunda oldukça zayıftır. Bu komut dosyası ile bunu geliştirmeyi ve potansiyelini ortaya çıkarmayı amaçlamaktayız.

OpenVPN 2.4 ve sonrası, şifreleme konusunda harika bir güncellemeydi. `ECDSA`, `ECDH`, `AES GCM`, `NCP` ve `tls-crypt` için destek ekledi.

Aşağıda belirtilen bir seçenek hakkında daha fazla bilgi istiyorsanız, [OpenVPN kılavuzuna](https://community.openvpn.net/openvpn/wiki/Openvpn24ManPage) gidin. Kendileri çok eksiksiz ve güzel bir kılavuz hazırlamışlar.

OpenVPN'in şifrelemeyle ilgili öğelerinin çoğu [Easy-RSA](https://github.com/OpenVPN/easy-rsa) tarafından yönetilir. Varsayılan parametreler [vars.example](https://github.com/OpenVPN/easy-rsa/blob/v3.0.7/easyrsa3/vars.example) dosyasındadır.

### Sıkıştırma

Varsayılan olarak, OpenVPN sıkıştırmayı etkinleştirmez. Bu komut dosyası, LZ0 ve LZ4 (v1/v2) algoritmaları için destek sağlar, ikincisi daha verimlidir.

Ancak, [VORACLE saldırısı](https://protonvpn.com/blog/voracle-attack/) sıkıştırmayı hedef aldığından sıkıştırma kullanılması önerilmez.

### TLS sürümü

OpenVPN varsayılan olarak TLS 1.0'ı kabul eder, bu da neredeyse [20 yaşında](https://en.wikipedia.org/wiki/Transport_Layer_Security#TLS_1.0).

'tls-version-min 1.2' ile, şu anda OpenVPN için mevcut en iyi protokol olan TLS 1.2'yi uyguluyoruz.

TLS 1.2, OpenVPN 2.3.3'ten beri desteklenmektedir. İleride TLS 1.3'ü de entegre etmeyi düşünüyoruz.

### Sertifika

OpenVPN, varsayılan olarak 2048 bit anahtarlı bir RSA sertifikası kullanır.

OpenVPN 2.4, ECDSA için destek ekledi. Eliptik eğri kriptografisi daha hızlı, daha hafif ve daha güvenlidir.

Bu komut dosyası şunları sağlar:

- ECDSA: `prime256v1`/`secp384r1`/`secp521r1` eğrileri
- RSA: `2048`/`3072`/`4096` bit anahtarları

`prime256v1` ile varsayılan olarak ECDSA'dır.

OpenVPN, varsayılan olarak imza karması olarak `SHA-256`yı kullanır ve komut dosyası da öyle. Şu anda başka bir seçenek sunmuyor.

### Veri kanalı

Varsayılan olarak OpenVPN, veri kanalı şifresi olarak `BF-CBC`yi kullanır. Blowfish eski (1993) ve zayıf bir algoritmadır. Resmi OpenVPN belgeleri bile bunu kabul ediyor.

> Varsayılan, Cipher Block Chaining modunda Blowfish'in kısaltması olan BF-CBC'dir.
>
> 64 bit blok boyutu nedeniyle BF-CBC kullanılması artık önerilmemektedir. Bu küçük blok boyutu, SWEET32 tarafından gösterildiği gibi, çarpışmalara dayalı saldırılara izin verir. Ayrıntılar için <https://community.openvpn.net/openvpn/wiki/SWEET32> adresine bakın.
> INRIA'daki güvenlik araştırmacıları, 3DES ve Blowfish gibi 64-bit blok şifrelere yönelik bir saldırı yayınladı. Aynı veriler yeterince sık gönderildiğinde düz metni kurtarabildiklerini ve ilgilenilen verileri yeterince sık göndermek için siteler arası komut dosyası çalıştırma güvenlik açıklarını nasıl kullanabileceklerini gösteriyorlar. Bu, HTTPS üzerinden çalışır, ancak OpenVPN üzerinden HTTP için de çalışır. Çok daha iyi ve ayrıntılı bir açıklama için <https://sweet32.info/> adresine bakın.
>
> OpenVPN'in varsayılan şifresi BF-CBC bu saldırıdan etkilenir.

Gerçekten de, AES bugünün standardıdır. Bugün mevcut olan en hızlı ve daha güvenli şifredir. [SEED](https://en.wikipedia.org/wiki/SEED) ve [Camellia](<https://en.wikipedia.org/wiki/Camellia_(cipher)>) tarihlere karşı savunmasız değildir ancak daha yavaştır AES'ten daha az ve nispeten daha az güvenilir.

> Şu anda desteklenen şifrelerden OpenVPN şu anda AES-256-CBC veya AES-128-CBC kullanılmasını önermektedir. OpenVPN 2.4 ve daha yenisi de GCM'yi destekleyecektir. 2.4+ için AES-256-GCM veya AES-128-GCM kullanmanızı öneririz.

AES-256, AES-128'den %40 daha yavaştır ve AES ile 128 bit anahtar yerine 256 bit anahtar kullanmanın gerçek bir nedeni yoktur. (Kaynak: [1](http://security.stackexchange.com/questions/14068/why-most-people-use-256-bit-encryption-instead-of-128-bit), [2](http://security.stackexchange.com/questions/6141/amount-of-simple-processs-o-is-safely-out-out-out-all-humanity/6149#6149). Ayrıca AES-256, [Zamanlama saldırılarına](https://en.wikipedia.org/wiki/Timing_attack) karşı daha savunmasızdır.

AES-GCM bir [AEAD şifresidir](https://en.wikipedia.org/wiki/Authenticated_encryption), yani aynı anda veriler üzerinde gizlilik, bütünlük ve özgünlük güvenceleri sağlar.

Komut dosyası aşağıdaki şifreleri destekler:

- `AES-128-GCM`
- `AES-192-GCM`
- `AES-256-GCM`
- `AES-128-CBC`
- `AES-192-CBC`
- `AES-256-CBC`

Ve varsayılan olarak `AES-128-GCM` olur.

OpenVPN 2.4, `NCP` adlı bir özellik ekledi: _Negotiable Crypto Parameters_. Bu, HTTPS'deki gibi bir şifre paketi sağlayabileceğiniz anlamına gelir. Varsayılan olarak `AES-256-GCM:AES-128-GCM` olarak ayarlanmıştır ve bir OpenVPN 2.4 istemcisi ile kullanıldığında `--cipher` parametresini geçersiz kılar. Basitlik adına, komut dosyası hem `--cipher` hem de `-ncp-cipher` öğelerini yukarıda seçilen şifreye ayarlar.

### Kontrol kanalı

OpenVPN 2.4, varsayılan olarak mevcut olan en iyi şifreyi belirleyecektir (ör. ECDHE+AES-256-GCM)

Komut dosyası, sertifikaya bağlı olarak aşağıdaki seçenekleri önerir:

- ECDSA:
  - `TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256`
  - `TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384`
- RSA:
  - `TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256`
  - `TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384`

Varsayılan olarak `TLS-ECDHE-*-WITH-AES-128-GCM-SHA256` şeklindedir.

### Diffie-Hellman anahtar değişimi

OpenVPN, varsayılan olarak 2048 bitlik bir DH anahtarı kullanır.

OpenVPN 2.4, ECDH anahtarları için destek ekledi. Eliptik eğri kriptografisi daha hızlı, daha hafif ve daha güvenlidir.

Ayrıca, klasik bir DH anahtarları oluşturmak uzun, çok uzun zaman alabilir. ECDH anahtarları geçicidir: anında oluşturulurlar.

Komut dosyası aşağıdaki seçenekleri sunar:

- ECDH: `prime256v1`/`secp384r1`/`secp521r1` eğrileri
- DH: `2048`/`3072`/`4096` bit anahtarları

Varsayılan olarak `prime256v1` şeklindedir.

### HMAC özet algoritması

OpenVPN wiki'sinden `--auth` hakkında:

> Veri kanalı paketlerinin ve (etkinleştirilmişse) tls-auth kontrol kanalı paketlerinin kimliğini mesaj özet algoritması alg kullanarak HMAC ile doğrulayın. (Varsayılan SHA1'dir). HMAC, dijital imza oluşturmak için bir veri dizisi, güvenli bir karma algoritma ve bir anahtar kullanan, yaygın olarak kullanılan bir mesaj doğrulama algoritmasıdır (MAC).
>
> Bir AEAD şifreleme modu (örneğin GCM) seçilirse, veri kanalı için belirtilen --auth algoritması yok sayılır ve bunun yerine AEAD şifresinin kimlik doğrulama yöntemi kullanılır. Alg'nin hala tls-auth için kullanılan özeti belirttiğine dikkat edin.

Komut dosyası aşağıdaki seçenekleri sunar:

- `SHA256`
- `SHA384`
- `SHA512`

Varsayılan olarak `SHA256`dır.

### `tls-auth` ve `tls-crypt`

OpenVPN wiki'sinden `tls-auth` hakkında:

> DoS saldırılarını ve TLS yığınına yönelik saldırıları azaltmak için TLS kontrol kanalının üstüne ek bir HMAC kimlik doğrulama katmanı ekleyin.
>
> Özetle, --tls-auth, OpenVPN'in TCP/UDP bağlantı noktasında bir tür `HMAC güvenlik duvarı` sağlar; burada yanlış bir HMAC imzası taşıyan TLS kontrol kanalı paketleri yanıt vermeden hemen bırakılabilir.

`tls-crypt` hakkında:

> Anahtar dosyasındaki anahtarla tüm kontrol kanalı paketlerini şifreleyin ve doğrulayın. (Daha fazla arka plan için --tls-auth bölümüne bakın.)
>
> Kontrol kanalı paketlerini şifreleme (ve doğrulama):
>
> - TLS bağlantısı için kullanılan sertifikayı gizleyerek daha fazla gizlilik sağlar,
> - OpenVPN trafiğini bu şekilde tanımlamayı zorlaştırır,
> - önceden paylaşılan anahtarı asla bilmeyecek (yani iletme gizliliği olmayan) saldırganlara karşı fakir adamın (poor man's shield) kuantum sonrası güvenliğini sağlar.

Böylece her ikisi de ek bir güvenlik katmanı sağlar ve DoS saldırılarını azaltır. OpenVPN tarafından varsayılan olarak kullanılmazlar.

`tls-crypt`, kimlik doğrulamaya ek olarak şifreleme sağlayan bir OpenVPN 2.4 özelliğidir (`tls-auth`dan farklı olarak). Daha fazla gizlilik dostudur.

Komut dosyası her ikisini de destekler ve varsayılan olarak `tls-crypt` kullanır.

## Atıf ve Lisans

[Katkıda bulunanlara](https://github.com/wiseweb-works/openvpn-most-secure-install/graphs/contributors), Nyr'in orijinal çalışmasına ve Angristan'ın çalışmasına çok teşekkürler.

Bu proje [MIT Lisansı](https://raw.githubusercontent.com/wiseweb-works/openvpn-most-secure-install/master/LICENSE) kapsamındadır.

# Son
**`@wiseweb-works/all:`** Her şey gönlünüzce olsun.
