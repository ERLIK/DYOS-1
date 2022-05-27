import optparse
import sys
import os
import ipaddress
from tabnanny import verbose
from scapy.all import *
import socket
import netifaces as ni
import subprocess
import datetime

# Bu ERLIK tarafından tasarlanması hedeflenen DYOS sisteminin ilk prototipidir.
# Hedef sistemin portlarına yönelik olarak gönderilen paketler ve bu paketlere gelen cevapları inceler.
# Bu cevaplar neticesinde bu portlar üzerinde çalısan servislerin versiyonları ile ilgili tarama gerçeklestirir.
# Bu taramalar neticesinde eğer servisin versiyonundan kaynaklı bir zafiyet varsa, bununla ilgili otomatik olarak intra nette search gerçeklestirir.
# En nihayetinde kullanıcı basit bir port tarama aracında tespit ettiği bu zafiyet için ayrı bir arama gerçeklestirmesi gerekmez.

# Gelistirilmeye çok müsait bir uygulama olarak görüyorum ben bu isleyisi.
# DYOS (Defend your own system) hayalimin baslangıcı bu sistem ile gerçeklesecektir.
# Umarım...

# Yapılacak tarama türleri sunlar olacaktır:

    # TCP Syn (half open) Scan:
        # Kaynak makinanın hedef makinaya TCP SYN bayraklı segment göndererek başlattığı bir tarama türüdür. 
        # Portların kapalı olduğu durumlarda hedef makina cevap olarak RST + ACK bayraklı segmenti döndürür. 
        # Portların açık olduğu durumlarda ise hedef makina SYN + ACK bayraklı segment döndürür. 
        # Daha sonra kaynak makina RST bayraklı segment göndererek bağlantıyı koparır ve böylelikle TCP üçlü el sıkışma (TCP three-way handshaking) tamamlanmaz. 
        # Bu tarama türünde TCP üçlü el sıkışma gerçekleşmediği için bu tarama türü hedef sistemlerinde herhangi bir şekilde iz bırakmaz. 
    
    # TCP Connect Scan
        # Kaynak makinanın gerçekleştireceği TCP Connect Scan, kapalı portlara yapıldığı zaman RST + ACK bayraklı segment dönecektir. 
        # Ancak açık portlara yapıldığı durumlarda hedef makinanın göndereceği SYN + ACK bayraklı segmenti, kaynak makina ACK bayraklı segment göndererek cevaplar ve üçlü el sıkışmayı tamamlar.
    
    # FIN (stealth) Scan
        # Hedef makinaya TCP bağlantı isteği olmadan gönderilen segmentle tarama yapılır. 
        # Kaynak makinanın göndereceği FIN bayraklı segment, hedef makinanın kapalı bir portuna gelirse hedef makina RST + ACK bayraklı segment döndürecektir. 
        # Eğer açık portuna gelirse hedef makinadan herhangi bir tepki dönmeyecektir. 
    
    # Xmas Scan
        #Bu tarama türünde kaynak bilgisayarın TCP segmentine URG,PSH ve FIN bayraklarını set edeceği ("1" yapılacağı) segment hedef makinaya gönderilir. 
        # Eğer Kaynak makinanın göndereceği URG,PSH ve FIN bayraklı segment, hedef makinanın kapalı bir portuna gelirse hedef makina RST + ACK bayraklı segment döndürecektir. 
        # Eğer port açık olursa hedef makinadan herhangi bir tepki dönmeyecektir.
    
    # Ping Scan
        # Bu tarama türünde kaynak makina hedef makinaya tek bir ICMP Echo istek paketi gönderir. 
        # IP adresi erişilebilir ve ICMP filtreleme bulunmadığı sürece, hedef makina ICMP Echo cevabı döndürecektir. 
        # Eğer hedef makina erişilebilir değilse veya paket filtreleyici ICMP paketlerini filtreliyorsa, hedef makinadan herhangi bir cevap dönmeyecektir. 

# Ek olarak eklenecek özellikler

    # IP
        # Kullanıcıdan IP değiskenini almama yarıyacak değisken.
        # Dikkat edilmesi gereken husus, kullanıcının özgür bir sekilde parametre girebilmesi çok önemli.
        # Kullanıcının girdiği IP parametresi bir IP bloğunu, IP grubunu ya da tek bir IP'yi temsil ediliyor olabilir.
        # Burada bunlara dikkat edilmeli ve kullanıcı bir yanlıs ifade verirse, kullanıcı düzgün bir sekilde bilgilendirilmeli.
    
    # PORT
        # Kullınıdan PORT ifadelerini almama yarıyacak değisken.
        # Dikkat edilmesi gereken husus, kullanıcının ifade özgürlüğü.
        # Kullanıcı bir PORT aralığı, PORT grubu, ya da tek bir PORT'u taratmak istiyor olabilir.
        # Bunlara dikkat edilip, DYOS-1 kullanıcıya girdiği yanlıs ifadede kullacının anlıyacağı düzeyde bilgi vermeli.
    
    # import file
        # Kullanıcı bir text dosyası içerisinde belirttiği IP aralığını tarayabilmesi için kullanması gereken parametre.

    # Save outputs as file
        # Kullanıcı eğer çıktıyı kaydetmek isterse kullanacağı parametre.

class DYOSMain():
    def __init__(self):
        self.userInput = optparse.OptionParser()
        self.takeArgv()
        self.IPcontrol()
        self.PORTcontrol()
        self.scan()
        self.makeSearch()
    def takeArgv(self):
        # IP: -i
        self.userInput.add_option('-i',
                                '--ip',
                                help = 'Targets IP address.',
                                dest = 'ip',
                                default = '127.0.0.1',
                                type = 'str')
        
        # PORT: -p
        self.userInput.add_option('-p',
                                '--port',
                                dest = 'port',
                                help = 'Targets port.',
                                type = 'str',
                                default = '1-1000')
        
        # save file: -s
        self.userInput.add_option('-s',
                                '--saveFile',
                                dest = 'way',
                                help = 'File location to save file where you want.',
                                default = False,
                                action = 'store_true')
        
        # import file: -m
        self.userInput.add_option('-m',
                                '--importFile',
                                dest = 'file',
                                help = 'Add file location to scan ip and ports.',
                                default = False,
                                action = 'store_true')

        # TCP Syn (half open) Scan: -q
        self.userInput.add_option('-q',
                                '--tcpsyn',
                                dest = 'tcpsyn',
                                help = 'Use this for make TCP Syn scan.',
                                default = False,
                                action = 'store_true')
        
        # TCP Connect Scan: -w
        self.userInput.add_option('-w',
                                '--tcpcon',
                                dest = 'tcpcon',
                                help = 'Use this for make TCP Connect scan.',
                                default = False,
                                action = 'store_true')
        
        # FIN (stealth) Scan: -e
        self.userInput.add_option('-e',
                                '--fin',
                                dest = 'fin',
                                help = 'Use this for make FIN scan.',
                                default = False,
                                action = 'store_true')

        # Xmas Scan: -r
        self.userInput.add_option('-r',
                                '--xmas',
                                dest = 'xmas',
                                help = 'Use this for make XMAS scan.',
                                default = False,
                                action = 'store_true')
        
        # Ping Scan: -t
        self.userInput.add_option('-t',
                                '--ping',
                                dest = 'ping',
                                help = 'Use this for make PING scan.',
                                default = False,
                                action = 'store_true')

        (self.option, self.addr) = self.userInput.parse_args()
        self.userValues = self.userInput.values

    # Bu fonksiyonda kullanıcının girdiği IP parametresi çesitli kontrolden geçecek.
    def IPcontrol(self):
        try:
            # Kullanıcının girdiği IP parametresi tek bir IP ise
            ipaddress.ip_address(self.option.ip)
        
        # Değilse zaten bir ValueError dönecektir bu IP değerinin baska bir seyi ifade ettiğini belirtir.

        except ValueError:
            # Burada IP parametresinin bir ip bloğu olup olmadığını kontrol ettim.
            # Eğer burada da hata alınırsa kullanıcının verdiği deger ya IP grubunu temsil ediyordur ya da hatalıdır. 
            try:
                self.option.ip = list(ipaddress.ip_network(self.option.ip))
            except ValueError:
                
                # Kullanının girdiği IP parametresinin IP grubu olup olmadığını kontrol etmek için bir sorgu soracağım.
                # Bu sorgu True ifade verirse kullanıcının girdiği ifadenin bir IP grubuna ait olduğunu anlayacağım.
                if '-' in self.option.ip:
                    ipList = list()
                    startPoint = int(self.option.ip.split('.')[-1].split('-')[0])
                    endPoint = int(self.option.ip.split('.')[-1].split('-')[1])

                    for ip in range(startPoint,endPoint+1):
                        ipList.append(f'{self.option.ip.split(".")[0]}.{self.option.ip.split(".")[1]}.{self.option.ip.split(".")[2]}.{ip}')
                    self.option.ip = ipList
                
                # Eğer kullanıcı bos değer verirse bir uyarı vermek istiyorum.
                # Teknik olarak IP ifadesinde default bir değer kullansamda, ilerideki güncellemelerde bu isleyis degisirse hata almak istemiyorum.
                # Bu yüzden bununla alakalı bir sorgu daha olusturacağım.
                elif self.option.ip == '':
                    print('''UYARI: Herhangi bir hedef belirtilmedi, bu yüzden 0 host tarandı.''')
                    sys.exit()
                # Bunun dısında bu versiyonda baska bir sorgu gelmeyecek onun yerine else ile olabilecek baska tüm hataları tek bir sorguda kontrol edeceğim.
                else:
                    print(f'''UYARI: "{self.option.ip}" çözümleme basarısız.''')
                    sys.exit()

    # Burada kullanıcının girdiği PORT parametresi çesitli kontrollerden gececek       
    def PORTcontrol(self):
        # Bu versiyonda kullanıcının 3 sekilde port bilgisini girmesine izin vereceğim, bunlar:
        # port grubu (-p 23,24,80)
        # port aralığı (-p 1-100)
        # tek bir port (-p 23)

        # Bunun kontrolleri için PORT parametresini çesitli sorgulara sokacağım
        # Eğer kullanıcının girdiği parametre bir port aralığını temsil ediyorsa...
        if '-' in self.option.port:
            try:
                portList = list()
                
                # Kullanıcının verdiği ilk değeri starter ikinci değeri ise endpoint olarak alıyorum.
                # Eğer kullanıcının girdiği ilk değer ikincisinden büyükse hata ver...
                startPoint = int(self.option.port.split('-')[0])
                endPoint = int(self.option.port.split('-')[1])

                if startPoint >= endPoint:
                    print('UYARI: PORT özellikleriniz geçersiz.')
                    sys.exit()               

                for port in range(startPoint, endPoint+1):
                    portList.append(port)

                self.option.port = portList
            # Eğer bu uyarı gerçeklesirse kullanıcı geçerli bir port değeri vermemis demektir.
            except ValueError:
                    print('UYARI: PORT özellikleriniz geçersiz.')
                    sys.exit()
            
        # Eğer kullanıcının girdiği parametre bir port grubunu temsil ediyorsa.
        # Burada kullanacğım kısım ',' karakterine göre split edip bu portları liste seklinde ana port değiskenime atamak.
        # Eğer hata alırsam zaten kullanıcı yanlıs bir ifade girmis demektir.
        # Bunu uygun bir dille kullanıcıya sunuyorum.
        elif ',' in self.option.port:
            try:
                portList = list(map(int,self.option.port.split(',')))
                self.option.port = portList
            except ValueError:
                    print('UYARI: PORT özellikleriniz geçersiz.')
                    sys.exit()

        # Eğer bunlar değilse kullanıcı ya tek bir PORT değiskeni vermistir ya da hatalı bir değer.
        # Bunun kontrolü için basit bir try except bloğu olusturacağım
        else:
            try:
                int(self.option.port)
            except ValueError:
                print('UYARI: PORT özellikleriniz geçersiz.')
                sys.exit()

    # Burada verilen ve seçinlen tarama türüne göre tarama islemini yapacağım. 
    def scan(self):

        now = datetime.datetime.now()
        print (f'DYOS-1 (Defend Your Own System-1) v1.00 {now.strftime("%Y-%m-%d %H:%M:%S")} TARAMA BASLATILDI...\n')

        # İlk olarak verilen ip ve port parametrelerinin bir liste olup olmadığını tespit etmem gerekiyor
        # Bu tespit sayesinde bir döngü içerisinde tarama içerisinde verilen tüm ip ve portlar için islem yapabileceğim.
        # Bunun tespiti için bir kaç sorgu ifadesi kullanacağım.
        # Her bir tarama seçeneği için bir if bloğu kullanağım bu programımın düzeltilmesini hedeflediğim büyük bir eksiklik.

        # Eğer kullanıcı TCP Syn taraması yapmak isterse.
        if self.option.tcpsyn == True:
            print('TCP SYN TARAMASI BASLATILDI:')
            # IP liste, PORT liste ise
            if isinstance(self.option.ip, list):
                if isinstance(self.option.port, list):
                    for ip in self.option.ip:
                        for port in self.option.port:
                            DYOSMain.tcpsyn(ip,port)
                
                # IP liste, PORT liste değil ise
                else:
                    for ip in self.option.ip:
                        DYOSMain.tcpsyn(ip,self.option.port)
            # IP liste değil, PORT liste
            else: 
                if isinstance(self.option.port, list):
                    for port in self.option.port:
                        DYOSMain.tcpsyn(self.option.ip, port)
                # IP liste değil, PORT liste değil
                else:
                    DYOSMain.tcpsyn(self.option.ip,self.option.port)
        
        # Eğer kullanıcı TCP Connect taraması yapmak isterse
        if self.option.tcpcon == True:
            print('TCP CONNECT TARAMASI BASLATILDI:\n')
            # IP liste, PORT liste ise
            if isinstance(self.option.ip, list):
                if isinstance(self.option.port, list):
                    for ip in self.option.ip:
                        for port in self.option.port:
                            DYOSMain.tcpcon(ip,port)
                
                # IP liste, PORT liste değil ise
                else:
                    for ip in self.option.ip:
                        DYOSMain.tcpcon(ip,self.option.port)
            # IP liste değil, PORT liste
            else: 
                if isinstance(self.option.port, list):
                    for port in self.option.port:
                        DYOSMain.tcpcon(self.option.ip, port)
                # IP liste değil, PORT liste değil
                else:
                    DYOSMain.tcpcon(self.option.ip,self.option.port)
        
        # Eğer kullanıcı FIN taraması yapmak isterse
        if self.option.fin == True:
            print('FIN TARAMASI BASLATILDI:\n')
            # IP liste, PORT liste ise
            if isinstance(self.option.ip, list):
                if isinstance(self.option.port, list):
                    for ip in self.option.ip:
                        for port in self.option.port:
                            # Tarama
                            pass
                # IP liste, PORT liste değil ise
                else:
                    for ip in self.option.ip:
                        # Tarama
                        pass
            # IP liste değil, PORT liste
            else: 
                if isinstance(self.option.port, list):
                    for port in self.option.port:
                        # Tarama
                        pass
                # IP liste değil, PORT liste değil
                else:
                    # Tarama
                    pass

        # Eğer kullanıcı XMAS taraması yapmak isterse
        if self.option.xmas == True:
            print('XMAS TARAMASI BASLATILDI:\n')
            # IP liste, PORT liste ise
            if isinstance(self.option.ip, list):
                if isinstance(self.option.port, list):
                    for ip in self.option.ip:
                        for port in self.option.port:
                            # Tarama
                            pass
                # IP liste, PORT liste değil ise
                else:
                    for ip in self.option.ip:
                        # Tarama
                        pass
            # IP liste değil, PORT liste
            else: 
                if isinstance(self.option.port, list):
                    for port in self.option.port:
                        # Tarama
                        pass
                # IP liste değil, PORT liste değil
                else:
                    # Tarama
                    pass

        # Eğer kullanıcı PING taraması yapmak isterse
        if self.option.ping == True:
            print('PING TARAMASI BASLATILDI:\n')
            # IP liste
            if isinstance(self.option.ip, list):
                for ip in list(self.option.ip):
                    DYOSMain.ping(ip)

            # IP liste değil
            else:
                DYOSMain.ping(self.option.ip)

    def tcpsyn(ip,port):
        packet = IP(src = str(ni.ifaddresses('eth0')[ni.AF_INET][0]['addr']),dst = ip) /TCP(sport = 80,dport= int(port),flags = 'S')
        resp = sr1(packet, iface='eth0', verbose = 0)
        if resp['TCP'].flags == 'SA':
            serviceName = socket.getservbyport(int(port), 'tcp')
            packet = IP(src = str(ni.ifaddresses('eth0')[ni.AF_INET][0]['addr']),dst = ip) /TCP(sport = 80,dport= int(port),flags = 'R')

            print(f'{ip}:{port} AKTİF {serviceName}')

    def tcpcon(ip, port):
        packet = IP(src = str(ni.ifaddresses('eth0')[ni.AF_INET][0]['addr']),dst = ip) /TCP(sport = 80,dport= int(port),flags = 'S')
        resp = sr1(packet, iface = 'eth0', verbose = 0)

        if resp['TCP'].flags == 'SA':
            serviceName = socket.getservbyport(int(port), 'tcp')
            packet = IP(src = str(ni.ifaddresses('eth0')[ni.AF_INET][0]['addr']),dst = ip) /TCP(sport = 80,dport= int(port),flags = 'A')
            resp = sr1(packet, iface = 'eth0', verbose = 0)
            print(f'{ip}:{port} AKTİF {serviceName}')

    def fin(ip, port):
        try:
            answer = sr1(IP(dst=ip)/TCP(sport=RandShort(),dport=port,flags="F"),timeout=1, verbose = 0)
            if (str(type(answer))=="<type 'NoneType'>"):
                print(f'{ip}{port} AKTİF!')
            elif(answer.haslayer(TCP)):
                if(answer.getlayer(TCP).flags == 0x14):
                    print(f'{ip}{port} KAPALI!')
                elif(answer.haslayer(ICMP)):
                    if(int(answer.getlayer(ICMP).type)==3 and int(answer.getlayer(ICMP).code) in [1,2,3,9,10,13]):
                        print(f'{ip}{port} FİLTRELENMİS!')

        except AttributeError:
            pass

    def xmas(ip,port):
        try:
            p = IP(dst=ip) / TCP(sport = RandShort(), dport = port, flags = 'FPU')
            resp = sr1(p, timeout=2, verbose = 0) 

            if str(type(resp)) == "<type 'NoneType'>":
                print(f'{ip}:{port} AKTİF!')
            elif resp.haslayer(TCP):
                if resp.getlayer(TCP).flags == 0x14:
                    print(f'{ip}:{port} KAPALI!')
                elif (int(resp.getlayer(ICMP).type)==3 and int(resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
                    print(f'{ip}:{port} FİLTRELENMİS!')

        except AttributeError:
            print(f'{ip}:{port} KAPALI!')

    def ping(ip):
        icmp = IP(dst=ip)/ICMP()
        resp = sr1(icmp, timeout=1, verbose = 0)
        if resp == None:
            pass
        else:
            print(f'{ip} AYAKTA!')
    
    def serviceVersion(ip,port):
        print('''
        IP:PORT bilgisi alınınan sistemde o port üzerinde çalışan sistemin uygulamasının versiyon bilgisinin alınması gerekiyor.
        Bunun için henüz bir yol bulunamadı.
        Mantık üzerinden çalışan uygulamaya bir paket yollamak.
        Ama asıl önemli olan kısım yollanan o paketin bir şekilde servisin versiyon bilgisini bize geri dönüştürmesi olacaktır.
        ''')

    def makeSearch(self):
        print('''
        Bu kısımdan sonra arama yapıp veri çekeceğim.
        Servis versiyonları gelecek ve versiyona göre zafiyet avlayacağım...
        ''')

if __name__ == '__main__':
    os.system('clear')
    print(
'''
#            _____                    _____                    _____            _____                    _____          
#           /\    \                  /\    \                  /\    \          /\    \                  /\    \         
#          /::\    \                /::\    \                /::\____\        /::\    \                /::\____\        
#         /::::\    \              /::::\    \              /:::/    /        \:::\    \              /:::/    /        
#        /::::::\    \            /::::::\    \            /:::/    /          \:::\    \            /:::/    /         
#       /:::/\:::\    \          /:::/\:::\    \          /:::/    /            \:::\    \          /:::/    /          
#      /:::/__\:::\    \        /:::/__\:::\    \        /:::/    /              \:::\    \        /:::/____/           
#     /::::\   \:::\    \      /::::\   \:::\    \      /:::/    /               /::::\    \      /::::\    \           
#    /::::::\   \:::\    \    /::::::\   \:::\    \    /:::/    /       ____    /::::::\    \    /::::::\____\________  
#   /:::/\:::\   \:::\    \  /:::/\:::\   \:::\____\  /:::/    /       /\   \  /:::/\:::\    \  /:::/\:::::::::::\    \ 
#  /:::/__\:::\   \:::\____\/:::/  \:::\   \:::|    |/:::/____/       /::\   \/:::/  \:::\____\/:::/  |:::::::::::\____\

#  \:::\   \:::\   \::/    /\::/   |::::\  /:::|____|\:::\    \       \:::\  /:::/    \::/    /\::/   |::|~~~|~~~~~     
#   \:::\   \:::\   \/____/  \/____|:::::\/:::/    /  \:::\    \       \:::\/:::/    / \/____/  \/____|::|   |          
#    \:::\   \:::\    \            |:::::::::/    /    \:::\    \       \::::::/    /                 |::|   |          
#     \:::\   \:::\____\           |::|\::::/    /      \:::\    \       \::::/____/                  |::|   |          
#      \:::\   \::/    /           |::| \::/____/        \:::\    \       \:::\    \                  |::|   |          
#       \:::\   \/____/            |::|  ~|               \:::\    \       \:::\    \                 |::|   |          
#        \:::\    \                |::|   |                \:::\    \       \:::\    \                |::|   |          
#         \:::\____\               \::|   |                 \:::\____\       \:::\____\               \::|   |          
#          \::/    /                \:|   |                  \::/    /        \::/    /                \:|   |          
#           \/____/                  \|___|                   \/____/          \/____/                  \|___|          
#   
'''
)

    DYOSMain()