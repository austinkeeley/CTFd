import base64
from hashlib import md5
import ldap
from ldap import modlist
import re

from flask import current_app as app

class LDAPUser(object):
    def __init__(self, username, team, dn):
        self.username = username
        self.dn = dn
        self.team = team

def _md5(s, raw_output=False):
  res = md5(s.encode())                                                                                                                                                                                                   
  if raw_output:                                                                                                                                                                                                                  
      return res.digest()                                                                                                                                                                                                         
  return res.hexdigest() 

def hash_md5(password):
    return base64.b64encode(_md5(password, True))


def validate_user(username, password):
    """Validadates a user's credentials"""
    r = app.ldap_instance.search_s(app.config['LDAP_BASE_DN'], ldap.SCOPE_SUBTREE, attrlist=['uid', 'sn', 'givenname', 'userpassword', 'memberOf']) 
    user_dn_list = [x for x in r if x[0][0:3] == 'cn=']
    for dn, attrs in user_dn_list:
        print(attrs)
        uid = attrs.get('uid', None)
        if uid and uid[0].decode('utf-8') == username:

            actual_password = attrs.get('userPassword')
            if actual_password and len(actual_password) > 0:
                actual_password = actual_password[0]   # stupid ldap always returning lists.  hopefully there's only one password
                actual_password = actual_password[5:]  # in our case, the first five characters are always {MD5}, just remove those
                hashed_password = hash_md5(password)
                if hashed_password == actual_password:
                    team_regex = re.compile('cn=(.*),ou=team')
                    team = team_regex.match(attrs.get('memberOf', [b'cn=,ou=team'])[0].decode('utf-8')).group(1)
                    ldapuser = LDAPUser(attrs.get('uid', [b''])[0].decode('utf-8'), team, dn )
                    return ldapuser

    return None

def change_password(username, old_password, new_password):
    """Changes a user's password"""
    # First be sure the old password is right
    print(username)
    print(old_password)
    u = validate_user(username, old_password)
    if not u:
        print('Could not authenticate against old password')
        return None

   

   

   

