#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# all attrib.: https://docs.microsoft.com/pl-pl/windows/win32/adschema/attributes-all
# example:
#  cfg4 = Config("smb4.ini")
#  sam=Sam(cfg4.config)  
#  for sam.get_persons():
#    .....
import ssl
import ldap3
from ldap3 import Connection, Server
from ldap3 import SIMPLE, SUBTREE, ALL, Tls

from pprint import pprint


class SamLdap():

  def __init__(self, config, debug=False):
    self.debug  = debug
    self.config = config
    self.base   = self.config['smb4']['base']
    self.uri    = self.config['smb4']['uri']
    self.port   = int(self.config['smb4']['port'])
    self.binddn = self.config['smb4']['binddn']
    self.password = self.config['smb4']['password']
    self.user_suffix  = self.config['smb4']['user_suffix']
    self.usetls = self.config['smb4']['usetls']
    self.cacert = self.config['smb4']['cacert']
    self.key    = self.config['smb4']['key']
    self.cert   = self.config['smb4']['cert']

  def connect_tls(self):
    kerberos=True
    try:
      if kerberos:
        tls_configuration = ldap3.Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLSv1_2)
      else:
        tls_configuration = Tls(local_private_key_file=self.key,
                local_certificate_file=self.cacert,
                validate=ssl.CERT_REQUIRED,
                version=ssl.PROTOCOL_TLSv1,
                ca_certs_file=self.cacert) 
    except:
      tls_configuration = Tls(validate=ssl.CERT_REQUIRED, version=ssl.PROTOCOL_TLSv1_2)
    server = Server(self.uri, port=self.port, tls=tls_configuration, get_info=ALL)#, use_ssl=True,
    self.connection = Connection(server, user=self.binddn, password=self.password,
#                 auto_bind=AUTO_BIND_NONE,
                 version=3,
                 authentication=SIMPLE,
                 raise_exceptions=True
    )
    read_server_info=True
    self.connection.start_tls(read_server_info)
    try:
      self.connection.open()
      return self.connection.bind()
    except Exception as e:
      print("LDAP conenction error %s " %  e)
    return False


  def connect(self):
    server = Server(self.uri, port=self.port, get_info=ALL, use_ssl=False)
    self.connection = Connection(server, user=self.binddn, password=self.password,
                 version=3,
                 authentication=SIMPLE,
                 raise_exceptions=True
    )
    try:
      self.connection.open()
      return self.connection.bind()
    except Exception as e:
      print('LDAP Connection error')
      print("error %s " %  e)
    return False


  def user_modify(self, uid, modifications):
    user_dn = ('CN=%s,'+self.user_suffix)  % uid
    try:
      result = self.connection.modify(user_dn, modifications)
    except Exception as e:
      print(e)
      return None
    return result


  def user_add(self, uid, attributes):
    user_dn = ('CN=%s,'+self.user_suffix)  % uid
    try:
      result = self.connection.add(user_dn, attributes=attributes)
    except:
      return None
    return result

  def get_user(self, uid):
    self.connection.search(search_base=self.user_suffix,
                      search_filter='(&(objectClass=person)(cn=' + uid + '))',
                      search_scope=ldap3.SUBTREE,
                      attributes=['displayName', 'givenName', 'userPrincipalName', 'telephoneNumber',
                                  'initials', 'homeDirectory', 'description', 'sn', 'name',
                                  'loginShell', 'unixHomeDirectory'
                                  ])
    result = self.connection.entries
    if self.debug:
      print '---------------------'
      for p in result:
        pprint.pprint(p)
      print '---------------------'
    try:
      u = result[0]
    except:
      u = None
    return u

  def get_user_p(self, pesel):
    self.connection.search(search_base=self.user_suffix,
                      search_filter='(&(objectClass=person)(title=' + pesel  + '))',
                      search_scope=ldap3.SUBTREE,
                      attributes=['sAMAccountName', 
                                  'displayName', 'givenName', 'userPrincipalName', 
                                  'initials', 'homeDirectory', 'description', 'sn', 'name',
                                  'loginShell', 'unixHomeDirectory',
                                  'title', 
                                  'telephoneNumber', 'mobile', 'otherTelephone',
                                  'mail', 'otherMailbox',
                                  'physicalDeliveryOfficeName', 'postOfficeBox', 'department'
                                  ])
    result = self.connection.entries
    if self.debug:
      print '---------------------'
      for p in result:
        pprint.pprint(p)
      print '---------------------'
    try:
      u = result[0]
    except:
      u = None
    return u


if __name__ == '__main__':
  from smb4par import Config 
  cfg4 = Config("smb4.ini")
  ldap=SamLdap(cfg4.config)
  print ldap.connect()
