#!/usr/bin/python
# -*- coding: utf-8 -*-
#
import ldap,ldif
import sys
import base64
import binascii

import samba
from smb4open import OpenLDAP_person
from smb4par import Config
from smb4sam import Sam
from smb4ldap import SamLdap

from ad_activate import enable_and_password
import hashlib


global sam
global s4ldap

import ldb
import samba.param
from samba.samdb import SamDB
from samba.auth import system_session
from pprint import pprint

from copy import copy
import syslog
import ldap.modlist as modlist
import sys

import ldap3
from ldap3 import Server, Connection, ALL


from ldap.controls import SimplePagedResultsControl

import configparser
try:
  config = configparser.ConfigParser()
  config.read('/etc/integration/sync.ini', encoding="UTF-8")
except KeyError as e:
  self.shutdown_with_error(
            "Configuration file is invalid! (Key not found: " + str(e) + ")")

LDAP_SERVER = "ldaps://"+config.get('ActiveDirectory', 'ip')
USER_BASE = config.get('ActiveDirectory', 'distinguishedname')
BIND_USER = config.get('ActiveDirectory', 'username')
BIND_DN = "CN=%s,%s" % (BIND_USER, USER_BASE)
BIND_PASS = config.get('ActiveDirectory', 'userpassword')
DOMAIN = config.get('ActiveDirectory', 'dns_domain')

def ntPass(password):
    # https://en.wikipedia.org/wiki/NT_LAN_Manager
    password=password.decode('utf8')
    hash = hashlib.new('md4', password.encode('utf-16le')).digest()
    sambaNTpassword=binascii.hexlify(hash)
    return sambaNTpassword


def CreateUser(username, base_dn, user_dn, user_attrs):
    try:
        ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, 0)
        ldap_connection = ldap.initialize(LDAP_SERVER)
        ldap_connection.simple_bind_s(BIND_DN, BIND_PASS)
    except ldap.LDAPError, error_message:
        print "Error connecting to LDAP server: %s" % error_message
        return False
    # Check and see if user exists
    try:
        user_results = ldap_connection.search_s(base_dn, ldap.SCOPE_SUBTREE,
                                                '(&(sAMAccountName=' +
                                                username +
                                                ')(objectClass=person))',
                                                ['distinguishedName'])
    except ldap.LDAPError, error_message:
        user_results = []
        print "Search Error: %s" % error_message
        return False
    # Check the results
    if len(user_results) != 0:
        print "User", username, "already exists in AD:", \
            user_results[0][1]['distinguishedName'][0]
        return False
    user_ldif = modlist.addModlist(user_attrs)
    # Add the new user
    try:
        ldap_connection.add_s(user_dn, user_ldif)
    except ldap.LDAPError, error_message:
        print "Error adding new user: %s" % error_message
        return False
    ldap_connection.unbind_s()
    return True

def Activate(user_dn):
    try:
        ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, 0)
        ldap_connection = ldap.initialize(LDAP_SERVER)
        ldap_connection.simple_bind_s(BIND_DN, BIND_PASS)
    except ldap.LDAPError, error_message:
        print "Error connecting to LDAP server: %s" % error_message
        return False
    # 512 will set user account to enabled
    mod_acct = [(ldap.MOD_REPLACE, 'userAccountControl', '512')]
    try:
      ldap_connection.modify_s(user_dn, mod_acct)
    except ldap.LDAPError, error_message:
      print "Error enabling user: %s" % error_message
      return False
    # LDAP unbind
    ldap_connection.unbind_s()

    # All is good
    return True


def ActivateAndPassword(username, base_dn, user_dn, password_value):
    try:
        ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, 0)
        ldap_connection = ldap.initialize(LDAP_SERVER)
        ldap_connection.simple_bind_s(BIND_DN, BIND_PASS)
    except ldap.LDAPError, error_message:
        print "Error connecting to LDAP server: %s" % error_message
        return False
    # Check and see if user exists
    try:
        user_results = ldap_connection.search_s(base_dn, ldap.SCOPE_SUBTREE,
                                                '(&(sAMAccountName=' +
                                                username +
                                                ')(objectClass=person))',
                                                ['distinguishedName'])
    except ldap.LDAPError, error_message:
        user_results = []
        print "Search Error: %s" % error_message
        return False
    # Check the results
    if len(user_results) == 0:
        print "User", username, "not found in AD"
        return False
    add_pass = [(ldap.MOD_REPLACE, 'unicodePwd', [password_value])]
    # 512 will set user account to enabled
    mod_acct = [(ldap.MOD_REPLACE, 'userAccountControl', '512')]
    # New group membership
    #add_member = [(ldap.MOD_ADD, 'member', user_dn)]
    # Add the password
    try:
      ldap_connection.modify_s(user_dn, add_pass)
    except ldap.LDAPError, error_message:
      print "Error setting password: %s" % error_message
    return False
    # Change the account back to enabled
    try:
      ldap_connection.modify_s(user_dn, mod_acct)
    except ldap.LDAPError, error_message:
      print "Error enabling user: %s" % error_message
      return False
    # LDAP unbind
    ldap_connection.unbind_s()

    # All is good
    return True



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


  def users(self):
    olPerson=OpenLDAP_person()
    try:
      self.ldap.simple_bind(self.config['OpenLDAP']['binddn'], self.config['OpenLDAP']['password'])
    except ldap.LDAPError as e:
      if self.debug:
        print(e)
    result=None
    try:
      retrieveAttributes = ['uid','displayName',
                            'cn',
                            'SCCardNumber',
                            'sambaNTPassword',
                            'sn', 'givenName',
                            'mail', 'telephoneNumber',
                            'uidNumber', 'gidNumber',
                            'departmentNumber',
                            'sambaDomainName', 'sambaSID', 'sambaHomeDrive', 'sambaPrimaryGroupSID',
                            'sambaProfilePath', 'sambaLogonScript', 'sambaHomePath',
                            'homeDirectory', 'userPassword', 'sambaSID',
                            'employeeNumber',
                            'SCCardNumber', # mifare number
                            'pleduPersonGId', # USOS / PESEL
                            'pleduPersonstudentNumber' # USOS = card number
                           ]
      results = self.ldap.search_s(self.config['OpenLDAP']['base'],ldap.SCOPE_SUBTREE,
                                   self.config['OpenLDAP']['filter'],
                                   retrieveAttributes)
      c=0
      for dn,entry in results:
        uid = entry['uid'][0] #.decode('utf8')
        yield (uid,entry)
    except Exception as e:
      print('** ERROR **')
      print(e)
    try:
      self.ldap.unbind()
    except Exception as e:
      print('error unbind')
      print(e)


def rr(r,xattrs,ident):
  try:
    xattrs[ident]=[r[ident][0],] #.decode('utf8'),]
  except:
    xattrs[ident]=''


def create():
  cfg4 = Config("smb4.ini")
  sam = Sam(cfg4.config)
  s4ldap = SamLdap(cfg4.config)
  s4ldap.connect()
  l=OpenLdap(cfg4.config, debug=True)
  for (uid,entry) in l.users():
    user_dn='CN='+uid+','+USER_BASE
    cn=str(entry['cn'][0])
    xattrs={'objectClass' : ['user', 'organizationalPerson', 'person', 'top'] }
    xattrs['cn'] = uid # cn
    xattrs['sAMAccountName'] = ''+uid
    xattrs['userPrincipalName'] = [uid + '@' +  DOMAIN, ]
    xattrs['name'] = [uid, ]
    rr(entry,xattrs,'displayName')
    rr(entry,xattrs,'givenName')
    rr(entry,xattrs,'sn')
    user_dn = 'CN='+uid+','+USER_BASE
    xattrs['userAccountControl'] = '514'
    try:
      if (uid[:2] == 's3') or (uid[:2] == 's4'):
        print uid
#        print user_dn
#        pprint(xattrs)
        print CreateUser(uid, USER_BASE, user_dn, xattrs)
    except Exception as e:
      print e
  #    exit()



def activate_passwd():
  cfg4 = Config("smb4.ini")
  sam = Sam(cfg4.config)
  s4ldap = SamLdap(cfg4.config)
  s4ldap.connect()
  l=OpenLdap(cfg4.config, debug=True)
  for (uid,entry) in l.users():
    if True: #uid.find('s38')>=0:
      try:
         sambaNTPassword = entry['sambaNTPassword'][0]
      except Exception as e:
         sambaNTPassword = ntPass('BardzoTrudne++Haselko(2020)')
      try:
         unicodePwd = base64.b64encode(binascii.a2b_hex(sambaNTPassword))
      except Exception as e:
         print 'Error: %s' % e
         unicodePwd = None
      if unicodePwd:
        print uid
        enable_and_password(BIND_USER, BIND_PASS, uid, unicodePwd)
#        print ActivateAndPassword(uid, USER_BASE, user_dn, unicodePwd)

def usage(argv):
  cmd = argv[0]
  print('Usage: ' + cmd + ' [sync | activ]')
  exit(1)

def main():
  args = sys.argv
  if len(args) < 2:
    usage(args)
  try:
    command  = args[1]
    if command=='sync':
      create()
    elif command=='activ':
      activate_passwd()
  except Exception as e:
    print('Error: %s' % e)

if __name__ == '__main__':
  main()