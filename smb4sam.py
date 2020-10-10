#!/usr/bin/python
# -*- coding: utf-8 -*-
# example:
#  cfg4 = Config("smb4.ini")
#  sam=Sam(cfg4.config)  
#  for p in sam.get_persons():
#    .....

import samba
from samba import param
from samba.samdb import SamDB
from samba.auth import system_session


class Sam():

  def __init__(self, config, debug=False):
    self.debug=debug
    self.config=config
    smba_conf=samba.param.default_path() # '/etc/samba/smb.conf'
    lp = samba.param.LoadParm()
    lp.load(smba_conf) 
    self.sam = SamDB(lp=lp,session_info=system_session())

  def start(self):
    self.sam.transaction_start()

  def commit(self):
    self.sam.transaction_commit()

  def get_persons(self):
    base = self.config['smb4']['base']
    res = self.sam.search(base=base,expression="(&(objectCategory=person)(objectClass=user))", 
                  attrs=[ 'description','sAMAccountName','displayName','givenName',
                          'mobile','telephoneNumber','physicalDeliveryOfficeName',
                          'mail' ])
    return res

  def setPwd(self, uid, pwd):
    dn=("CN=%s," % uid)+self.config['smb4']['base']
    setpw = """dn: %s
changetype: modify
replace: unicodePwd
unicodePwd::%s
    """ % (dn, pwd)
    self.sam.transaction_start()
    try:
      self.sam.modify_ldif(setpw,["local_oid:1.3.6.1.4.1.7165.4.3.12:0"])
    except Exception as e:
      self.sam.transaction_cancel()
      print( '!!! ERROR SET PASSWORD USER : %s' % e)
    else:
      self.sam.transaction_commit()
      print('Hasło zmienione')


if __name__ == '__main__':
  from smb4par import Config
  from pprint import pprint
  cfg4 = Config("smb4.ini")
  sam=Sam(cfg4.config)  
  for p in sam.get_persons():
    pprint(p)
