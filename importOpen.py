#!/usr/bin/python
# -*- coding: utf-8 -*-
#
import ldap,ldif
import sys
import base64
import binascii
import hashlib

import samba
from smb4open import OpenLDAP_person
from smb4par import Config
from smb4sam import Sam
from smb4ldap import SamLdap

global sam
global s4ldap

def ntPass(password):
    # https://en.wikipedia.org/wiki/NT_LAN_Manager
    password=password.decode('utf8')
    hash = hashlib.new('md4', password.encode('utf-16le')).digest()
    sambaNTpassword=binascii.hexlify(hash)
    return sambaNTpassword


class OpenLdap:

  def __init__(self, config, debug=False):
    self.config=config
    self.debug=debug
    self.uri=self.config['OpenLDAP']['uri']
    try:
      self.ldap = ldap.initialize(self.uri)
    except ldap.LDAPError as e:
      if self.debug:
        print(e)
      self.ldap=None

  def unbind(self):
    try:
      self.ldap.unbind()
    except:
      pass

  def ldap_dump(self):
    try:
      self.ldap.simple_bind(self.config['OpenLDAP']['binddn'], self.config['OpenLDAP']['password'])
    except ldap.LDAPError as e:
      if self.debug:
        print(e)
      return None
    result=None
    try:
      results = self.ldap.search_s(self.config['OpenLDAP']['base'],ldap.SCOPE_SUBTREE,
                                   self.config['OpenLDAP']['filter'])
      ldif_writer = ldif.LDIFWriter(sys.stdout)
      for dn,entry in results:
        ldif_writer.unparse(dn,entry)
    except ldap.LDAPError as e:
      if self.debug:
        print(e)
      pass      
    return result

  def ldap2smb(self):
    olPerson=OpenLDAP_person()
    try:
      self.ldap.simple_bind(self.config['OpenLDAP']['binddn'], self.config['OpenLDAP']['password'])
    except ldap.LDAPError as e:
      if self.debug:
        print(e)
      return None
    result=None
    try:
      retrieveAttributes = ['uid','displayName',
                            'cn',
#                            'mail','telephoneNumber',
                            'SCCardNumber',
                            'sambaNTPassword',
                            'sn', 'givenName'  ]
      results = self.ldap.search_s(self.config['OpenLDAP']['base'],ldap.SCOPE_SUBTREE,
                                   self.config['OpenLDAP']['filter'],
                                   retrieveAttributes)
      c=0
      for dn,entry in results:
        uid = entry['uid'][0].decode('utf8')
        attributes=olPerson.personAttr(entry)
        try:
           if uid != 'Administrator' and uid != 'admin':
             if s4ldap.user_add(uid,attributes):
               c+=1
               try:
                 sambaNTPassword = entry['sambaNTPassword'][0]
                 unicodePwd = base64.b64encode(binascii.a2b_hex(sambaNTPassword))
               except Exception as e:
                 print '??? %s ' % e
                 sambaNTPassword = None
                 unicodePwd = None
               if unicodePwd:
                 sam.setPwd(uid, unicodePwd)
        except  ldap.LDAPError as e:
          print(e)
        except UnicodeDecodeError as e:
          print(e)
        except Exception as e:
          print(e)
    except ldap.LDAPError as e:
      print('** ERROR **')
      if self.debug:
        print(e)
      pass      
    return result


  def sync_pwd(self):
    try:
      self.ldap.simple_bind(self.config['OpenLDAP']['binddn'], self.config['OpenLDAP']['password'])
    except ldap.LDAPError as e:
      if self.debug:
        print(e)
      return None
    result = None
    try:
      retrieveAttributes = ['uid','sambaNTPassword']
      results = self.ldap.search_s(self.config['OpenLDAP']['base'], ldap.SCOPE_SUBTREE,
                                   self.config['OpenLDAP']['filter'],
                                   retrieveAttributes)
      c=0
      for dn,entry in results:
        try:
         uid=entry['uid'][0].decode('utf8')
         if self.debug:
           print(uid)
         try:
            if not 'sambaNTPassword' in entry:
              print 'Brakuje sambaNTPassword'
            sambaNTPassword=entry['sambaNTPassword'][0]
         except Exception as e:
            print "error: %s" % e
#            from pprint import pprint
#            pprint(entry)
            sambaNTPassword=ntPass('BardzoTrudne++Haselko(2020)')
         if uid=='jurekw':
           print sambaNTPassword
           exit(0)
         try:
            sambaNTPassword=entry['sambaNTPassword'][0]
            unicodePwd=base64.b64encode(binascii.a2b_hex(sambaNTPassword))
         except:
            sambaNTPassword=None
            unicodePwd=None
         try:
           if uid != 'Administrator' and uid != 'admin' and unicodePwd:
             sam.setPwd(uid, unicodePwd)
         except  ldap.LDAPError as e:
           print(e)
        except UnicodeDecodeError as e:
          print(e)
    except ldap.LDAPError as e:
      print('** ERROR **')
      if self.debug:
        print(e)
      pass      
    return result



  def ldap2smb_update(self, to_empty=False, with_pwd=False):
    try:
      self.ldap.simple_bind(self.config['OpenLDAP']['binddn'], self.config['OpenLDAP']['password'])
    except ldap.LDAPError as e:
      if self.debug:
        print(e)
      return None
    result = None
    try:
      retrieveAttributes = ['uid', 'displayName',
                            'cn', 
                            'mail', 'telephoneNumber', 
                            'SCCardNumber',
                            'sn', 'givenName',
                            'sambaNTPassword',
                            'uidNumber', 'gidNumber',
                            #  employeeType',
                            'departmentNumber',
                            'sambaDomainName', 'sambaSID', 'sambaHomeDrive', 'sambaPrimaryGroupSID',
                            'sambaProfilePath', 'sambaLogonScript', 'sambaHomePath',
                            'homeDirectory', 'userPassword', 'sambaSID',
                            'employeeNumber',
                            'SCCardNumber', # mifare number
                            'pleduPersonGId', # USOS / PESEL
                            'pleduPersonstudentNumber' # USOS = card number
                              ]
      results = self.ldap.search_s(self.config['OpenLDAP']['base'], ldap.SCOPE_SUBTREE,
                                   self.config['OpenLDAP']['filter'],
                                   retrieveAttributes)
      c=0
      olPerson = OpenLDAP_person()
      for dn,entry in results:
        uid=entry['uid'][0]
        if self.debug:
          print(uid)
        if to_empty:
          old=None
        else:
          old=s4ldap.get_user(uid)
        if old:
          (uid,modifications)=olPerson.openAttr2smb4mod(entry)
          try:
            if s4ldap.user_modify(uid,modifications):
              c+=1
          except  ldap.LDAPError as e:
            print(e)
          except UnicodeDecodeError as e:
            print(e)
        else: # new
          (uid,attributes)=olPerson.openAttr2smb4new(entry)
          try:
            if uid != 'Administrator' and uid != 'admin':
              if s4ldap.user_add(uid,attributes):
                c+=1
                if with_pwd:
                  try:
                   sambaNTPassword=e['sambaNTPassword'][0]
                   unicodePwd=base64.b64encode(binascii.a2b_hex(sambaNTPassword))
                  except:
                   sambaNTPassword=None
                   unicodePwd=None
                  if unicodePwd:
                    sam.setPwd(uid, unicodePwd)
              else:
                print('Failed: %s ' % uid)
          except  ldap.LDAPError as e:
            print(e)
          except UnicodeDecodeError as e:
            print(e)
      # /new
      if c>0:
        result='Modified %s items' % c
    except ldap.LDAPError as e:
      result='** ERROR ** [%s]' % e
      if self.debug:
        print(e)
    return result


  def ldap_list(self):
    retrieveAttributes = ['uid','displayName','sambaNTPassword']
    try:
      self.ldap.simple_bind(self.config['OpenLDAP']['binddn'], self.config['OpenLDAP']['password'])
    except ldap.LDAPError as e:
      if self.debug:
        print(e)
      return None
    result = None
    stop=False
    try:
      ldap_result_id = self.ldap.search(self.config['OpenLDAP']['base'], ldap.SCOPE_SUBTREE,
                                   self.config['OpenLDAP']['filter'],
                                   retrieveAttributes)
      while not stop:
        (result_type, result_data) = self.ldap.result(ldap_result_id, 0)
        stop=(result_data==[]) or (c>10)
        if result_type == ldap.RES_SEARCH_ENTRY:
          for e in  result_data:
            if self.debug:
              print(e[1]['uid'][0])
              print(e[1]['sambaNTPassword'][0])
              print('---')
            uid=e[1]['uid'][0]
            if not result and  uid[:5]=='uczen':
              c=c+1
              result={'uid':e[1]['uid'][0],'displayName':e[1]['displayName'][0]}
    except ldap.LDAPError as e:
      if self.debug:
        print('** ERROR [2] **')
        print(e)
    return result


  def ldap_mails(self):
    f=open('lista.csv','w+')
    retrieveAttributes = ['uid','mail', 'givenName','sn']
    try:
      self.ldap.simple_bind(self.config['OpenLDAP']['binddn'], self.config['OpenLDAP']['password'])
    except ldap.LDAPError as e:
      if self.debug:
        print(e)
      return None
    stop=False
    c=0
    try:
      ldap_result_id = self.ldap.search(self.config['OpenLDAP']['base'], ldap.SCOPE_SUBTREE,
                                   self.config['OpenLDAP']['filter'],
                                   retrieveAttributes)
      while not stop:
        (result_type, result_data) = self.ldap.result(ldap_result_id, 0)
        stop=(result_data==[]) # or (c>10000)
        c+=1
        if result_type == ldap.RES_SEARCH_ENTRY:
          for e in  result_data:
            if self.debug:
              print(e[1]['uid'][0])
              print('---')
            uid=e[1]['uid'][0]
#            if (uid[:3]=='s37' or uid[:3]=='s36' or uid[:3]=='s35')  and uid<'s37969':
            if (uid[:2]=='s3') or  (uid[:2]=='s4'):
              print uid
              for mail in e[1]['mail']:
#                if mail[:6] != uid[:6]:
                f.write('%s;%s %s\n' % (mail, e[1]['givenName'][0], e[1]['sn'][0]))
    except ldap.LDAPError as e:
      if self.debug:
        print('** ERROR [2] **')
        print(e)
    f.close()

  def unbind(self):
   try:
     self.ldap.unbind()
   except:
     pass
                
                

def usage(argv):
  cmd = argv[0]
  print('Usage: ' + cmd + ' [sync | sync-pwd | dump | update | mails]')
  exit(1)


def do_sync(config):
  l=OpenLdap(config, debug=True)
  r=l.ldap2smb_update(False,True)
  print('wynik: %s' % r)
  l.unbind()

def do_sync_pwd(config):
  l=OpenLdap(config, debug=True)
  l.sync_pwd()
  l.unbind()

def do_ldap_dump(config):
  l=OpenLdap(config, debug=True)
  l.ldap_dump()
  l.unbind()

def do_update_all(config):
  l=OpenLdap(config, debug=True)
  r=l.ldap2smb_update()
  print('wynik: %s' % r)
  l.unbind()

def do_ldap_mails(config):
  l=OpenLdap(config, debug=False)
  l.ldap_mails()
  l.unbind()


def main():
  args = sys.argv
  if len(args) < 2:
    usage(args)

  cfg4 = Config("smb4.ini")
  global sam
  global s4ldap
  sam = Sam(cfg4.config)
  s4ldap = SamLdap(cfg4.config)
  s4ldap.connect()

  command  = args[1]
  commands = { 'sync' : do_sync,
               'sync-pwd' : do_sync_pwd,
               'dump' : do_ldap_dump,
               'update' : do_update_all,
               'mails' : do_ldap_mails
             }
  try:
    commands[command.lower()](cfg4.config)
  except Exception as e:
    print('Error: %s' % e)


if __name__ == '__main__':
  main()