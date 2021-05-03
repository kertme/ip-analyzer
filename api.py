from flask import Flask, jsonify, request
import flask
import resolve
from netaddr import IPNetwork
import concurrent.futures
import sys
import smtplib
from email.message import EmailMessage
from cryptography.fernet import Fernet
from datetime import datetime
from email.mime.text import MIMEText
import os
import io
import requests
import check_ntp
import validators
import check_ldap
import check_port

app = Flask(__name__)
app.config['JSONIFY_PRETTYPRINT_REGULAR'] = True
resolver = resolve.Resolver()


# log detaylarında işlemin yapıldığı anın tarih ve saatini döndürmek için
def get_time():
    return '[' + str(datetime.now().strftime("%d/%m/%Y %H:%M:%S")) + '] | '


# verilen ip adresi için açık port kontrolü
def open_port_checker(ip, port_list):
    open_ports_list = []
    for port in port_list:
        if not check_port.test(ip, port):
            open_ports_list.append(port)
    time = get_time()
    if open_ports_list:
        return time + ip + ':Acik portlar ' + str(open_ports_list)
    else:
        return time + ip + ':Portlar kapali'


# Açık kontrollerinin yapıldığı yer
# cevap alınabilen ilgili açıklar liste halinde döndürülüyor
def detect_problems(ip, check_list):
    problems = []
    # ssdp kontorlü
    if 'ssdp' in check_list and not check_port.test(ip, '1900'):
        problems.append('SSDP acigi')
    # smb kontrolü
    if 'smb' in check_list and not check_port.test(ip, '139'):
        problems.append('SMB acigi')
    # ldap kontrolü
    if 'ldap' in check_list:
        ldap_response = check_ldap.test(ip)
        if ldap_response:
            problems.append('LDAP acigi')
    # ntp kontrolü
    if 'ntp' in check_list:
        ntp_response = check_ntp.test(ip)
        if ntp_response:
            problems.append('NTP acigi')
    # recursive dns kontrolü
    if 'dns' in check_list:
        # recursive dns sorgusu yapacak obje oluşturuluyor
        resolver = resolve.Resolver()
        # sorgulanacak ip belirtiliyor
        resolver.ROOT_SERVER = ip
        # "google.com" adresi için recursive dns çözümleme sorgusu başlatıldı
        response = resolver.collect_results("google.com", resolver.dns_cache)
        # root cevabı döndüyse global root sunucusuna ulaşıldı:root açığı
        if resolver.root_response:
            problems.append('DNS Root acigi')
        # dönen cevap içinde ns adresi var ve timeout alınmadıysa recursion tamamlandı
        elif response['NS'] and not resolver.timeout:
            problems.append('DNS Recursion acigi')
        # yukarıdaki durumlar sağlanmadıysa dns sorgusu için bir güvenlik açığı tespit edilmedi
        else:
            pass
    return problems


# belirtilen subnet için açık tespitinde kullanılacak fonksiyon
# multithread olarak çalışması için tek ip adresi verilecek
def subnet_checker(ip, check_list):
    problems = detect_problems(ip, check_list)
    time = get_time()
    if problems:
        return time + ip + ':' + str(problems) + ' tespit edildi'
    else:
        return time + ip + ':Guvenli'


'''
# credentials.ini içeriği:
şifreleme anahtarı
Gönderici mail adresi
Gönderici mail adresi şifresi
Smtp sunucusu adresi
'''


# şifrelenmiş mail adresi bilgilerini çözümleme
def get_email_credentials(directory):
    with open(directory + '/credentials.ini', 'r') as f:
        lines = f.read().split('\n')

    key = lines[0].encode()
    token = lines[1].encode()
    token2 = lines[2].encode()
    token3 = lines[3].encode()
    f = Fernet(key)
    return f.decrypt(token).decode(), f.decrypt(token2).decode(), f.decrypt(token3).decode()


# gonderim şekli olarak belirtilen adrese mail gönderen fonksiyon
# receivers: alıcı listesi, content: mail içeriği, subject: konu başlığı,
# filename: .txt uzantılı oluşturulan raporun adı
# directory: raporun oluşturulduğu dizin
def send_email(receivers, content, subject, filename, directory):
    # mail bilgileri alınıyor
    sender, password, smtp_server = get_email_credentials(directory)
    receivers = receivers

    # formata uygun e-mail mesajı oluşturuluyor
    msg = EmailMessage()
    msg.set_content(content)
    msg['Subject'] = subject
    msg['From'] = sender
    msg['To'] = receivers

    # oluşturulan rapor, ek dosya olarak maile ekleniyor
    file_path = directory + '/' + filename
    msg.add_attachment(open(file_path, "r").read(), filename=filename)

    # mail gönderme denemesi
    try:
        s = smtplib.SMTP(smtp_server, 587)
        s.login(sender, password)
        s.send_message(msg)
        print(get_time() + 'Email sent to ' + str(receivers), file=sys.stderr)
    except Exception as e:
        print(get_time() + request.url + '|' + "Error: unable to send email:", e, file=sys.stderr)
    finally:
        # işlem sonucundan bağımsız, sunucuda yer kaplamaması için oluşturulan rapor silinecek
        os.remove(file_path)


# gonderim seçeneği 'web' ve 'post request' için sonuçları json formatına çeviren fonksiyon
def make_results_json(ip, subnet, start_time, results):
    finish_time = datetime.now()
    finish_time_s = finish_time.strftime("%d/%m/%Y %H:%M:%S")
    start_time_s = start_time.strftime("%d/%m/%Y %H:%M:%S")
    report_name = 'ip' + ip + '-' + 'subnet' + subnet

    content = {'report_name': report_name,
               'time': f'start:{start_time_s} finish:{finish_time_s}',
               'results': results
               }
    return content


# sonuçları e-mail ya da post request olarak yollayan fonksiyon
# e-mail flag: e-mail ya da post request ayrımı için
# diğer tüm parametreler sonuçların uygun formatta aktarılması için
def send_results(ip, subnet, email_flag, receiver, start_time, results, check_list):
    finish_time = datetime.now()
    finish_time_s = finish_time.strftime("%d/%m/%Y %H:%M:%S")
    start_time_s = start_time.strftime("%d/%m/%Y %H:%M:%S")
    # rapor ismi sorgunun ip ve subnet parametrelerine göre belirlenecek
    report_name = 'ip' + ip + '-' + 'subnet' + subnet
    if email_flag:
        # email gönderilecekse maile eklenmesi için sonuçlar .txt uzantılı dosyaya yazılacak
        directory = os.path.dirname(os.path.abspath(__file__))
        with open(directory + '/' + report_name + '.txt', 'w', encoding="utf-8") as f:
            f.write('Sorgu baslangic zamani:' + start_time_s + '-' + 'Sorgu bitis zamani:' + finish_time_s + '\n')
            f.write('Kontrol parametreleri:' + str(check_list) + '\n \n')
            for i in results:
                f.write(i + '\n')

        content = 'Sonuçlar ektedir.'
        subject = report_name + ' için sorgu sonuçları'
        send_email(receiver, content, subject, report_name + '.txt', directory)
        print('----------\n', file=sys.stderr)

    # post request ile iletilecekse sonuçlar json formatına çevrilecek
    else:
        content = {'report_name': report_name,
                   'time': f'start:{start_time_s} finish:{finish_time_s}',
                   'results': results
                   }

        res = requests.post(receiver, json=content)
        print(f'{get_time()}post request response:{res}', file=sys.stderr)
        print('----------\n', file=sys.stderr)


def run_threads(ip, subnet, control_function, control_list):
    # belirtilen subnet ip adresleri alınıyor
    snet = IPNetwork(ip + '/' + subnet)
    ip_addresses = [str(x) for x in snet]
    results = []

    start_time = datetime.now()
    # işlemler multithreading yapısında başlatılıyor
    with concurrent.futures.ThreadPoolExecutor() as executor:
        # subnet içindeki her ip adresi ayrı bir threadle port kontrolü fonksiyonuna aktarılıyor
        futures = [executor.submit(control_function, param, control_list) for param in ip_addresses]
        # biten işlem sonuç olarak eklenip loglanıyor
        for future in concurrent.futures.as_completed(futures):
            output = future.result()
            results.append(output)
            print(output, file=sys.stderr)
    return results, start_time







# port kontrolü sorgusu yapılan route
# örnek kullanım: address.com/portcheck?ip=178.20.231.180&subnet=30&gonderim=test.com&check_list=ldap,dns
@app.route("/portcheck")
def port_check():
    ip = request.args.get("ip")
    if not ip:
        return 'Kontrol edilecek ip adresini belirtin'
    # ip adresi doğrulama
    if not validators.ipv4(ip):
        return 'Geçerli bir ip adresi girin'

    port_param = request.args.get('portlist')
    # port listesi doğrulama
    if port_param:
        port_list = port_param.split(',')
    else:
        return 'portlist belirtmelisiniz'
    if not any(list(map(str.isnumeric, port_list))):
        return 'Port listesi hatalı. Örnek kullanım: &portlist=1 veya &portlist=1,2,3'
    if not port_list:
        return 'Kontrol edilecek port listesi belirtin'

    subnet = request.args.get("subnet")
    if subnet:
        receiver = request.args.get('gonderim')
        if not receiver:
            return 'sonuçların iletileceği bir adres belirtmelisiniz.'
        email_flag = False
        web_flag = False
        if receiver == 'web':
            web_flag = True
        else:
            # e-mail doğrulama
            if validators.email(receiver):
                email_flag = True
            else:
                # post url doğrulama
                if not validators.url(receiver):
                    return '&gonderim parametresi için \'web\' keywordu, geçerli bir url ya da e-mail adresi girmelisiniz'

        if subnet.isnumeric():
            # [19-32] arası subnet sorgulamaya izin veriliyor
            if 19 <= int(subnet) <= 32:
                @flask.after_this_request
                def add_close_action(response):
                    @response.call_on_close
                    def process_after_request():
                        # sonuçlar mail ya da post request ile iletilecekse
                        if not web_flag:
                            results, start_time = run_threads(ip, subnet, open_port_checker, port_list)
                            # tüm thread işlemleri tamamlandığında sonuçlar belirtilen şekilde gönderiliyor
                            send_results(ip, subnet, email_flag, receiver, start_time, results, port_list)

                    return response
            else:
                return 'Subnet parametresi [19-32] aralığında değerler alabilir.'
        else:
            return 'Subnet parametresi [19-32] aralığında değerler alabilir.'

        print(f'{get_time()}Sorgu baslatildi:{request.url}', file=sys.stderr)

        # gonderim şekli 'web' ise sonuçlar sayfada gösterilecek
        if web_flag:
            results, start_time = run_threads(ip, subnet, open_port_checker, port_list)
            print('----------\n', file=sys.stderr)
            return make_results_json(ip, subnet, start_time, results)
        return 'Sorgu başlatıldı. Subnet taranıyor, sonuçlar ' + receiver + ' adresine gönderilecek. Bu sayfayı kapatabilirsiniz.'

    # subnet belirtilmediyse tekil bir ip için kontrol yapılıp sonuç sayfada gösterilecek
    print(f'{get_time()}Sorgu baslatildi:{request.url}', file=sys.stderr)
    return open_port_checker(ip, port_list)


@app.route("/")
def index():
    # parametre kontrolleri
    ip = request.args.get("ip")
    if not ip:
        return 'Kontrol edilecek ip adresini belirtin'

    if not validators.ipv4(ip):
        return 'Geçerli bir ip adresi girin'

    check_list = request.args.get('check')
    if not check_list:
        return 'Kontrol edilmesini istediginiz sorgulari belirtin. ex: &check=dns,ntp'

    subnet = request.args.get("subnet")
    if subnet:
        receiver = request.args.get('gonderim')
        if not receiver:
            return 'sonuçların iletileceği bir adres belirtmelisiniz.'
        email_flag = False
        web_flag = False
        if receiver == 'web':
            web_flag = True
        else:
            if validators.email(receiver):
                email_flag = True
            else:
                if not validators.url(receiver):
                    return '&gonderim parametresi için \'web\' keywordu, geçerli bir url ya da e-mail adresi girmelisiniz'

        if subnet.isnumeric():
            if 19 <= int(subnet) <= 32:
                @flask.after_this_request
                def add_close_action(response):
                    @response.call_on_close
                    def process_after_request():
                        if not web_flag:
                            results, start_time = run_threads(ip, subnet, subnet_checker, check_list)
                            send_results(ip, subnet, email_flag, receiver, start_time, results, check_list)

                    return response
            else:
                return 'Subnet parametresi [19-32] aralığında değerler alabilir.'
        else:
            return 'Subnet parametresi [19-32] aralığında değerler alabilir.'

        print(f'{get_time()}Sorgu baslatildi:{request.url}', file=sys.stderr)
        if web_flag:
            results, start_time = run_threads(ip, subnet, subnet_checker, check_list)
            print('----------\n', file=sys.stderr)
            return make_results_json(ip, subnet, start_time, results)

        return 'Sorgu başlatıldı. Subnet taranıyor, sonuçlar ' + receiver + ' adresine gönderilecek. Bu sayfayı kapatabilirsiniz.'

    print(f'{get_time()}Sorgu baslatildi:{request.url}', file=sys.stderr)
    problems = detect_problems(ip, check_list)
    if problems:
        return ip + ':' + str(problems) + ' tespit edildi'
    else:
        return ip + ':Guvenli'

# app.run()
