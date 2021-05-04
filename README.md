# ip-analyzer
Belirtilen ip adresinin çeşitli sorgulara yanıt verip vermediğini analiz etmek için kullanılabilir. Dns Recursion, LDAP, SMB, NTP, SSDP sorguları ve belirtilen portların açık olup olmadığı kontrol edilebilir.

## Kurulum

1) .py uzantılı dosyaları aynı folder içerisine atın.
2) run-flask.sh, stop-flask.sh ve restart-flask.sh  dosyalarındaki ilgili dizinleri düzenleyin.
3) pip install -r /path/to/requirements.txt ile gerekli kütüphaneleri kurun.
4) Yeni bir mail sunucusu kullanılacaksa encrypt_credentials.py ile mail sunucusu bilgileri şifrelenebilir.


### (Centos)
Başlatma: ./run-flask.sh flask sunucusunu arka planda başlatır, process id'yi save_pid.txt içerisine kaydeder.

Durdurma: ./stop-flask.sh save_pid.txt den flask server process id'sini alır ve durdurur.

Restart: ./restart-flask.sh aktif serverin kodlarında degişiklik yapıldığında serveri yeniden başlatır.

## API 
https://documenter.getpostman.com/view/12485464/TzK2YYVP
