#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# non standard using:
# *  postOfficeBox: Student Card No
# *  physicalDeliveryOfficeName: HR Ident.
# *  otherTelephone: Mifare Ident.
# *  title: PESEL

from ldap3 import MODIFY_REPLACE
import base64
import binascii


class OpenLDAP_person():

    def __init__(self, debug=False):
      self.debug=debug


    def openAttr2smbAttr0(self, oAttr):
        try:
            uid = oAttr['uid'][0].decode('utf8')
            if self.debug:
                print(uid)
            try:
              sn = oAttr['sn'][0].decode('utf8')
            except:
              sn = uid
            try:
              sambaNTPassword = oAttr['sambaNTPassword'][0]
              unicodePwd = base64.b64encode(
                    binascii.a2b_hex(sambaNTPassword))
            except:
              sambaNTPassword = None
              unicodePwd = None
            try:
              displayName = oAttr['displayName'][0].decode('utf8')
            except:
              displayName = sn
            try:
              givenName = oAttr['givenName'][0].decode('utf8')
            except:
              givenName = sn
            try:
              mail = oAttr['mail'][0]
            except:
              mail = self.param.mail_pattern % uid
            try:
              telephoneNumber = oAttr['telephoneNumber'][0]
            except:
              telephoneNumber = '0'
            try:
              businessCategory = oAttr['businessCategory'][0]
            except:
              businessCategory = '-'
            try:
              employeeType = oAttr['employeeType'][0]
            except:
              employeeType = '-'
            try:
              employeeNumber = oAttr['employeeNumber'][0]
            except:
              employeeNumber = '-'
            initials = givenName[:1]+sn[:1]
            attributes = {'objectClass': ['user', 'organizationalPerson', 'person', 'top'],
                          'sn': sn,
                          'displayName': displayName,
                          # 'employeeNumber': uid,
                          'givenName': givenName,
                          'name': uid,
                          'initials': initials,
                          'instanceType': 4,
                          'sAMAccountName': uid,
                          'telephoneNumber': telephoneNumber,
                          'userPrincipalName': mail,
                          'loginShell': '/bin/bash',
                          'unixHomeDirectory': '/home/'.join(uid)
                          }
            return (unicodePwd, attributes)
        except:
            return (None, {})

    def openAttr2dict(self, e):

        def _g1(oAttr, s3, ident):
            try:
                s3[ident] = oAttr[ident][0].decode('utf8')
            except:
                s3[ident] = ''

        def _g2(oAttr, s3, ident):
            try:
                s3[ident] = ['?', ]
                s = oAttr[ident][0].decode('utf8')
                if s:
                    s3[ident][0] = s
                s = oAttr[ident][1].decode('utf8')
                if s:
                    s3[ident].append(s)
            except:
                pass

        s3 = {}
        if e:
            _g1(e, s3, 'uid')
            uid = s3['uid']
            if self.debug:
                print(uid)
            _g1(e, s3, 'displayName')
            _g1(e, s3, 'cn')
            _g1(e, s3, 'mail')
            _g2(e, s3, 'telephoneNumber')
            _g1(e, s3, 'sn')
            _g1(e, s3, 'givenName')
            _g1(e, s3, 'sambaNTPassword')
            _g1(e, s3, 'uidNumber')
            _g1(e, s3, 'gidNumber')
            _g2(e, s3, 'mail')
            _g1(e, s3, 'sambaDomainName')
            _g1(e, s3, 'sambaSID')
            _g1(e, s3, 'sambaHomeDrive')
            _g1(e, s3, 'sambaPrimaryGroupSID')
            _g1(e, s3, 'sambaProfilePath')
            _g1(e, s3, 'sambaLogonScript')
            _g1(e, s3, 'sambaHomePath')
            _g1(e, s3, 'homeDirectory')
            _g1(e, s3, 'userPassword')
            _g1(e, s3, 'sambaSID')
            _g1(e, s3, 'businessCategory')
            _g1(e, s3, 'employeeType')
            _g1(e, s3, 'employeeNumber') # HR number 
            _g1(e, s3, 'SCCardNumber') # mifare number
            _g1(e, s3, 'departmentNumber')  # departament
            _g1(e, s3, 'pleduPersonGId') # USOS / PESEL
            _g1(e, s3, 'pleduPersonLId') # USOS = employeeNumber 
            _g1(e, s3, 'pleduPersonstudentNumber') # USOS = card number
            if not s3['displayName']:
                s3['displayName'] = s3['sn']
            if not s3['givenName']:
                s3['givenName'] = s3['sn']
            s3['initials'] = s3['givenName'][:1]+s3['sn'][:1]
            s3['description'] = '%s|%s|%s|%s|%s|%s|%s\n' % (s3['sambaDomainName'],
                                                   s3['sambaSID'],
                                                   s3['sambaHomeDrive'],
                                                   s3['sambaPrimaryGroupSID'],
                                                   s3['sambaProfilePath'],
                                                   s3['sambaLogonScript'],
                                                   s3['sambaHomePath'])
        return s3

    def openAttr2smb4mod(self, oAttr, withContacts=False):
        s3=self.openAttr2dict(oAttr)
        modifications = {
                    'displayName': [(MODIFY_REPLACE, [s3['displayName']])],
                    'givenName':  [(MODIFY_REPLACE, [s3['givenName']])],
        }
        if withContacts:
          phones=[]
          mobiles=[]
          for ph in s3['telephoneNumber']:
            if ph[:1] in ('5','6'):
              mobiles.append(str(ph))
            phones.append(str(ph))
          modifications['telephoneNumber'] = [ (MODIFY_REPLACE, phones) ]
          modifications['mobile'] = [ (MODIFY_REPLACE, mobiles) ]
          mail=''
          otherMails=[]
          for m in s3['mail']:
            if m.find('@example.com'):
              mail=str(m)
            else:
              otherMails.append(str(m))
          modifications['mail'] = [(MODIFY_REPLACE, mail)]
          modifications['otherMailbox'] = [(MODIFY_REPLACE, otherMails)]
        if s3['departmentNumber']:  # departament
            modifications['department'] = [
                (MODIFY_REPLACE, [s3['departmentNumber']])]
        if s3['employeeNumber']: # HR number 
            modifications['physicalDeliveryOfficeName'] = [
                (MODIFY_REPLACE, [s3['employeeNumber']])]
        if s3['SCCardNumber']: # mifare number
            modifications['otherTelephone'] = [ (MODIFY_REPLACE, [s3['SCCardNumber']]) ]
        if s3['pleduPersonGId']: # USOS / PESEL
            modifications['title'] = [ (MODIFY_REPLACE, [s3['pleduPersonGId']]) ]
        if s3['pleduPersonLId']: # USOS = employeeNumber 
            pass
        if s3['pleduPersonstudentNumber']: # USOS = student card number
            modifications['postOfficeBox'] = [ (MODIFY_REPLACE, [s3['pleduPersonstudentNumber']]) ]
        return (s3['uid'],modifications)

    def openAttr2smb4new(self, oAttr):
        s3 = self.openAttr2dict(oAttr)
        attributes = {'objectClass': ['user', 'organizationalPerson', 'person', 'top'],
                      'displayName': s3['displayName'],
                      'givenName':  s3['givenName'],
                      'userPrincipalName': s3['mail'][0],
                      'telephoneNumber':  s3['telephoneNumber'][0],
                      'initials':  s3['initials'],
                      'homeDirectory':  s3['homeDirectory'],
                      'description':  s3['description'],
                      'sn': s3['sn'],
                      'name': s3['uid'],
                      'instanceType': 4,
                      'sAMAccountName': s3['uid'],
                      'loginShell': '/bin/bash',
                      'unixHomeDirectory': '/home/'.join(s3['uid'])
                      }
        return (s3['uid'],attributes)
