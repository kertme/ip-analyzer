from cryptography.fernet import Fernet

'''
# credentials.ini içeriği:
şifreleme anahtarı
Gönderici mail adresi
Gönderici mail adresi şifresi
Smtp sunucusu adresi
'''


# Güvenlik amacıyla mail detayları şifrelenmiş olarak tutulacak
# Uygulama farklı bir mail adresi ve sunucusu ile çalıştırılmak istendiğinde kullanılabilir
# Örnek kullanım: encrypt_credentials(test@test.com, 123456, smtp.test.com)
def encrypt_credentials(sender, passwd, smtp_server):
    key = Fernet.generate_key()
    f = Fernet(key)
    token = f.encrypt(sender.encode())
    token2 = f.encrypt(passwd.encode())
    token3 = f.encrypt(smtp_server.encode())

    with open('credentials.ini', 'w') as f:
        f.write(str(key)[2:-1] + '\n')  # şifreleme anahtarı
        f.write(str(token)[2:-1] + '\n')  # şifrelenmiş gönderici mail adresi
        f.write(str(token2)[2:-1] + '\n')  # şifrelenmiş gönderici mail adresi şifresi
        f.write(str(token3)[2:-1])  # şifrelenmiş smtp server adresi
