#_*_ coding:utf-8 _*_
import sys, os, shutil
import res_rc
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from PyQt5.QtGui import *
from PyQt5 import uic
import subprocess
import socket
import requests
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import hashlib
import binascii
import traceback

frm = uic.loadUiType('ui.ui')[0]

class MainWindow(QMainWindow, frm):
    def __init__(self):
        super().__init__()
        self.setupUi(self)
        self.endFlag = False
        self.subject_hash_old = ''
        self.selectedDevice = ''
        self.projectPath = os.path.dirname(os.path.realpath(__file__))
        self.checkButton.clicked.connect(self.checkInit)
        self.insertButton.clicked.connect(self.insertCert)
        self.deviceList.itemClicked.connect(self.setDevice)
        self.processADB = QProcess()
        self.processADB.setProcessChannelMode(QProcess.MergedChannels)
        self.processADB.readyRead.connect(self.adbOutputProcess)

        if os.path.isdir(self.projectPath + '/data'):
            shutil.rmtree(self.projectPath + '/data')
        os.mkdir(self.projectPath + '/data')

    def adbOutputProcess(self):
        try:
            result = []
            temp = str(self.processADB.readAll().data(), encoding='utf-8').strip()
            temp = temp.split('\n', 1)[1]
            temp = temp.split('\n')
            for list in temp:
                result.append(list.split('device')[0].strip())

            if result:
                for device in result:
                    self.deviceList.addItem(device)

        except Exception as ex:
            self.log('e', 'device not found')

    def log(self, type, msg):
        logTag = ''
        if type == 'i':
            logTag = '[INFO]'
        elif type == 'd':
            logTag = '[DEBUG]'
        elif type == 'e':
            logTag = '[ERROR]'

        tmp = logTag + " " + msg
        self.logEdit.append(tmp)
        pos = QTextCursor.End
        self.logEdit.moveCursor(pos)

    def checkProxy(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = sock.connect_ex((self.ipEdit.text(), int(self.portEdit.text())))
            if result == 0:
                return True
            else:
                return False
        except:
            return False

    def checkADB(self):
        self.log('d', 'check adb devices')
        self.processADB.start('adb devices -l')

    def setDevice(self):
        self.selectedDevice = self.deviceList.currentItem().text()
        self.log('i', 'select device - [' + self.selectedDevice + ']')

    def checkSU(self):
        cmd = 'adb -s ' + self.selectedDevice + ' shell su -c "id"'
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
        out = p.stdout.readline()
        if out.find('not found') == -1:
            return True
        else:
            return False

    def checkInit(self):
        if self.endFlag:
            self.logEdit.clear()
            self.endFlag = False

        self.log('d', 'check proxy server')
        if self.checkProxy():
            self.log('d', 'proxy server ok')
            self.checkADB()

            try:
                self.log('d', 'get certification from burp')
                with requests.Session() as r:
                    r.proxies = {}
                    r.proxies['http'] = 'http://' + self.ipEdit.text() + ':' + self.portEdit.text()
                    r.proxies['https'] = 'http://' + self.ipEdit.text() + ':' + self.portEdit.text()

                    saveCert = self.projectPath + '/data/cacert.der'
                    url = 'http://burp/cert'
                    o = r.get(url)
                    with open(saveCert, 'wb') as w:
                        for chunk in o.iter_content(chunk_size=512):
                            if chunk:
                                w.write(chunk)

                self.log('d', 'convert certification der to pem')
                if os.path.isfile(saveCert):
                    with open(saveCert, 'rb') as derfile:
                        der_data = bytearray(derfile.read())

                    cert = x509.load_der_x509_certificate(der_data, default_backend())
                    cert_val = cert.public_bytes(serialization.Encoding.PEM)

                    subject = hashlib.md5(cert.subject.public_bytes()).hexdigest()
                    subject_temp = binascii.unhexlify(subject)
                    self.subject_hash_old = '{:x}'.format(int((subject_temp[0] | (subject_temp[1] << 8) | (
                                subject_temp[2] << 16) | (subject_temp[3] << 24)) & 0xffffffff))

                    if not os.path.isfile(self.projectPath + '/data/' + self.subject_hash_old + '.0'):
                        with open(self.projectPath + '/data/cacert.pem', "wb") as outfile:
                            outfile.write(cert_val)
                        os.rename(self.projectPath + '/data/cacert.pem',
                                  self.projectPath + '/data/' + self.subject_hash_old + '.0')

            except Exception as e:
                self.log('e', f'{traceback.format_exc()}')
                pass

        else:
            self.log('e', 'proxy server down')

    def insertCert(self):
        if not self.selectedDevice == '':
            self.log('d', 'insert certification to device - [' + self.selectedDevice + ']')

            try:
                cmd1 = 'adb -s ' + self.selectedDevice + ' push "' + self.projectPath + '/data/' + self.subject_hash_old + '.0" /sdcard/Download/'
                p = subprocess.Popen(cmd1, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                out, err = p.communicate()

                if self.checkSU():
                    cmd2 = "adb -s " + self.selectedDevice + " shell su -c 'mv /sdcard/Download/" + self.subject_hash_old + ".0 /system/etc/security/cacerts/'"
                    p = subprocess.Popen(cmd2, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    out, err = p.communicate()

                    cmd3 = "adb -s " + self.selectedDevice + " shell su -c 'chmod 644 /system/etc/security/cacerts/" + self.subject_hash_old + ".0'"
                    p = subprocess.Popen(cmd3, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    out, err = p.communicate()

                    cmd4 = "adb -s " + self.selectedDevice + " shell su -c 'chown root:root /system/etc/security/cacerts/" + self.subject_hash_old + ".0'"
                    p = subprocess.Popen(cmd4, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    out, err = p.communicate()
                else:
                    self.log('e', 'device not rooted')

            except Exception as e:
                self.log('e', f'{traceback.format_exc()}')
                pass

            self.log('d', 'certification added in device')
            self.endFlag = True
        else:
            self.log('d', 'device not selected')

if __name__ == '__main__':
    app = QApplication(sys.argv)
    QApplication.setStyle(QStyleFactory.create('Fusion'))
    mApp = MainWindow()
    mApp.show()
    sys.exit(app.exec_())
