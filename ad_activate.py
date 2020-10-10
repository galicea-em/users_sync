#!/usr/bin/python

#https://github.com/palten08/pythonadtool-tkinter.git
import io
import configparser
from ldap3 import Server, Connection, NTLM, ALL, SUBTREE, MODIFY_REPLACE

class FromConfig:
    """ Parses the config file """


    def __init__(self):
        Config = configparser.ConfigParser()
        Config.read("ad.ini")
        self.serverip = Config.get('directoryinfo', 'ip')
        self.basepath = Config.get('schemainfo', 'basepath')
        self.objectclass = Config.get('schemainfo', 'objectclass')
        self.distinguishedname = Config.get('schemainfo', 'distinguishedname')
        self.domain = Config.get('schemainfo', 'domain')


def get_dn(displayname):
    """ Returns a username in full distinguished name format:
        ie: cn=First M.I. Last,cn=container,dc=domain,dc=local
    """
    return 'cn={},'.format(displayname) + config.distinguishedname


def get_object_class(configvalue):
    """ Formats the objectclass line from the config into a list """
    objclass = configvalue.split('|')
    return objclass


config = FromConfig()


def ad_server():
    """ Creates an instance of the ldap3 Server object with the ip / hostname defined in the config """

    return Server(config.serverip, use_ssl=True, get_info=ALL)


def ad_connection(sessionusername, sessionpassword):
    """ Establishes the connection using the ad_server instance and credentials from the application's input """

    domain_username = config.domain + '\\' + sessionusername
    return Connection(ad_server(), user=domain_username, password=sessionpassword, authentication=NTLM)

debugmessages = []

def add_user(sessionusername, sessionpassword, displayname, newuserpassword, attributesdict):
    user_dn = get_dn(displayname)
    objectclass = get_object_class(config.objectclass)
    ad_c = ad_connection(sessionusername, sessionpassword)
    if ad_c.bind():
        print 'bindok'
        ad_c.add(user_dn, objectclass, attributesdict)
        #ad_c.add(user_dn, objectclass, {'givenName': givenname, 'sn': surname, 'department': department, 'userPrincipalName': userprincipalname, 'sAMAccountName': samaccountname, 'description': 'Account made by Pete\'s User Creation Tool as a test'})
        if 'success' in ad_c.result.values():
            ad_c.extend.microsoft.unlock_account(user=user_dn)
            ad_c.extend.microsoft.modify_password(user=user_dn, new_password=newuserpassword, old_password=None)
            enable_account = {"userAccountControl": (MODIFY_REPLACE, [512])}
            user_must_change_password = {"pwdLastSet": (MODIFY_REPLACE, [0])}
            ad_c.modify(user_dn, changes=enable_account)
            ad_c.modify(user_dn, changes=user_must_change_password)
            if 'success' in ad_c.result.values():
                message = "User account '{}' was created and enabled".format(attributesdict['sAMAccountName'])
                print(message)
            else:
                message = "User account '{}' was created but could not be enabled".format(attributesdict['sAMAccountName'])
                print(message)
                print(ad_c.result['message'])
        else:
            message = "User account '{}' could not be created".format(attributesdict['sAMAccountName'])
            print(message)
            print(ad_c.result['message'])    
        ad_c.unbind()


def search_by_sam(SAM, sessionusername, sessionpassword):
    #domain_username = config.domain + '\\' + sessionusername
    search_filter = "(&(objectclass=user)(!(objectclass=computer))(sAMAccountName=" + SAM + "))"
    ad_c = ad_connection(sessionusername, sessionpassword)
    if ad_c.bind():
        print(ad_c)
        ad_c.search(search_base=config.basepath, search_filter=search_filter, search_scope=SUBTREE, attributes=['distinguishedName', 'department', 'description'], size_limit=0)

        if(ad_c.entries and len(ad_c.entries) > 0):
            print(ad_c.entries)
        else:
            print("User '{}' does not exist in Active Directory".format(SAM))
        ad_c.unbind()
    else:
        print("Connection to the AD server could not be made")




def enable_and_password(sessionusername, sessionpassword, displayname, newuserpassword):
    user_dn = get_dn(displayname)
    objectclass = get_object_class(config.objectclass)
    ad_c = ad_connection(sessionusername, sessionpassword)
    if ad_c.bind():
        ad_c.extend.microsoft.unlock_account(user=user_dn)
        ad_c.extend.microsoft.modify_password(user=user_dn, new_password=newuserpassword, old_password=None)
        enable_account = {"userAccountControl": (MODIFY_REPLACE, [512])}
        user_must_change_password = {"pwdLastSet": (MODIFY_REPLACE, [0])}
        ad_c.modify(user_dn, changes=enable_account)
        ad_c.modify(user_dn, changes=user_must_change_password)
        if 'success' in ad_c.result.values():
            message = "User account '{}' was enabled".format(displayname)
            print(message)
        else:
            message = "User account '{}' could not be enabled".format(displayname)
            print(message)
            print(ad_c.result['message'])
        ad_c.unbind()


def enable(sessionusername, sessionpassword, displayname):
    user_dn = get_dn(displayname)
    print user_dn
    objectclass = get_object_class(config.objectclass)
    ad_c = ad_connection(sessionusername, sessionpassword)
    if ad_c.bind():
        ad_c.extend.microsoft.unlock_account(user=user_dn)
        enable_account = {"userAccountControl": (MODIFY_REPLACE, [512])}
        user_must_change_password = {"pwdLastSet": (MODIFY_REPLACE, [0])}
        ad_c.modify(user_dn, changes=enable_account)
        ad_c.modify(user_dn, changes=user_must_change_password)
        if 'success' in ad_c.result.values():
            message = "User account '{}' was enabled".format(displayname)
            print(message)
        else:
            message = "User account '{}' could not be enabled".format(displayname)
            print(message)
            print(ad_c.result['message'])
        ad_c.unbind()



#enable_and_password('Administrator', 'apassword', 'user11', 'upassword11')