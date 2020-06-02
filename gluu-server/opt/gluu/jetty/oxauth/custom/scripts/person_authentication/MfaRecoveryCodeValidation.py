# oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
# Copyright (c) 2016, Gluu
#
# Author: Pawel Pietrzynski
#

from org.gluu.model.custom.script.type.auth import PersonAuthenticationType
from org.gluu.service.cdi.util import CdiUtil
from org.gluu.oxauth.security import Identity
from org.gluu.util import StringHelper
from org.gluu.oxauth.util import ServerUtil
from org.gluu.oxauth.service import AuthenticationService, UserService, SessionIdService
from org.gluu.oxauth.i18n import LanguageBean
from org.gluu.oxauth.model.common import User
from org.gluu.jsf2.message import FacesMessages
from javax.faces.application import FacesMessage
from java.util import Arrays
from java.security import Key
from javax.crypto import Cipher
from javax.crypto.spec import SecretKeySpec, IvParameterSpec
from org.bouncycastle.jce.provider import BouncyCastleProvider


import sys
import java
import json
import time
import base64
import random
import string

class PersonAuthentication(PersonAuthenticationType):
    def __init__(self, currentTimeMillis):
        self.currentTimeMillis = currentTimeMillis

    def init(self, configurationAttributes):

        # Load encryption key file content
        key_file = configurationAttributes.get("encryption_key_file").getValue2()
        f = open( key_file, 'r' )
        try:
            key = f.read()
            self.aesKey = key[:16]
        except:
            print "MFA Recovery. Initialization. Failed reading AES key file for encrypting recovery code: %s" % key_file
            return False
        finally:
            f.close()


        # Load customization content from file
        content_file = configurationAttributes.get("custom_page_content_file").getValue2()
        f = open(content_file, 'r')
        try:
            self.customPageContent = json.loads(f.read())
        except:
            print "MFA Recovery. Initialization. Failed to load RP customization content from file: %s" % content_file
            return False
        finally:
            f.close()

        print "MFA Recovery. Initialized successfully"
        return True

    def destroy(self, configurationAttributes):
        print "MFA Recovery. Destroyed successfully"
        return True

    def getApiVersion(self):
        return 2

    def isValidAuthenticationMethod(self, usageType, configurationAttributes):
        print "MFA Recovery. isValidAuthenticationMethod called"

        identity = CdiUtil.bean(Identity)
        # check if cancel was requested and go back to original validator
        authenticationFlow = identity.getSessionId().getSessionAttributes().get("authenticationFlow")
        if ( authenticationFlow == "MFA_VALIDATION" ):
            return False
        # check if the flow has completed successfully
        if ( identity.getWorkingParameter("user_code_success") ):
            print "MFA Recovery. isValidAuthenticationMethod return False, recovery complete"
            return False
        return True

    def getAlternativeAuthenticationMethod(self, usageType, configurationAttributes):
        print "MFA Recovery. getAlternativeAuthenticationMethod: redirecting to 'mfa_select'"
        identity = CdiUtil.bean(Identity)

        # check if cancel was requested and go back to original validator
        new_acr = "select_mfa"
        # get the validation ACR and authenticationFlow
        validationAcr = identity.getSessionId().getSessionAttributes().get("validationAcr")
        authenticationFlow = identity.getSessionId().getSessionAttributes().get("authenticationFlow")
        if ( authenticationFlow == "MFA_VALIDATION" ):
            new_acr = validationAcr
        # else we have successfully recovered, continue to enrollment

        # remove the validation ACR from the session variables either way
        identity.getSessionId().getSessionAttributes().remove("validationAcr")
        CdiUtil.bean(SessionIdService).updateSessionId( identity.getSessionId() )

        return new_acr

    def authenticate(self, configurationAttributes, requestParameters, step):
        print "MFA Recovery. authenticate called for step '%s'" % step

        identity = CdiUtil.bean(Identity)
        # For authentication then check if someone enrolling clicked CANCEL button
        alternateAction = self.alternateActionRequested(requestParameters)
        if ( alternateAction == 'cancel'):
            identity.getSessionId().getSessionAttributes().put("authenticationFlow", "MFA_VALIDATION")
            identity.setWorkingParameter("otp_count_login_steps", 2)
            CdiUtil.bean(SessionIdService).updateSessionId( identity.getSessionId() )
            return True

        ########################################################################################
        # 1. Make sure we have a session
        session_id_validation = self.validateSessionId(identity)
        if not session_id_validation:
            print "MFA Recovery. authenticate. Failed to validate session state" % step
            return False

        authenticationService = CdiUtil.bean(AuthenticationService)
        authenticated_user = authenticationService.getAuthenticatedUser()

        if authenticated_user == None:
            print "MFA Recovery. authenticate. Failed to determine authenticated user from previous module"
            return False

        ########################################################################################
        # 2. get the recovery code from the form
        requestCode = self.getCodeFromRequest(requestParameters)
        if (requestCode == None):
            print "MFA Recovery. authenticate. Did not receive code from request"
            return False

        ########################################################################################
        # 3. get the code from the user profile
        facesMessages = CdiUtil.bean(FacesMessages)
        # get the code from the user profile
        userCodeOrig = self.findExistingCode(authenticated_user)
        if (userCodeOrig == None):
            print "MFA Recovery. authenticate. Did not find code in user profile, cannot recover"
            facesMessages.add( FacesMessage.SEVERITY_ERROR, "Did not find recovery code in you profile, cannot recover" )
            return False
            
        ########################################################################################
        # 4. load code, lockout and attemps 
        userService = CdiUtil.bean(UserService)
        # check for retries
        lockoutTs = None
        attemptsCount = 0
        userCode = userCodeOrig
        if (userCode.find("|") > 0):
            attemptsCount = userCode.split('|')[1]
            userCode      = userCode.split('|')[0]
            attemptsCount = int(attemptsCount)
            # the attemptsCount could potentially be a lockout timestamp in seconds if > 10
            if ( attemptsCount > 10 ):
                lockoutTs = attemptsCount
                attemptsCount = 0
        
        ########################################################################################
        # 4. check for active lockout
        if ( lockoutTs != None ):
            # lockout is for 72 hours (259200 seconds)
            if ( time.time() < lockoutTs + 259200 ):
                facesMessages.add(FacesMessage.SEVERITY_ERROR, "Too many failed attempts, you are within a 72 hour recovery lockout until next recovery attempt.")
                return False
            else:
                lockoutTs = None

        ########################################################################################
        # 5. process code check, if fails process attemps and lockout
        userCodeDecrypted = self.decryptAES( self.aesKey, userCode )
        if (userCodeDecrypted != requestCode.lower()):
            print "MFA Recovery. authenticate. Recovery codes do not match, previous failed attempts = %s" % attemptsCount
            attemptsCount = attemptsCount + 1
            message = "Recovery attempt, bad code. Failed attempt %s out of 10" % attemptsCount
            # set attributes for saving
            userCodeNew = "%s|%s" % ( userCode, attemptsCount )
            # check lockout count
            if ( attemptsCount > 10 ):
                # set lockout message and adjust count to 0 and set lockout attribute
                message = "Recovery attempt, bad code. Too many attempts. You need to wait 72 hours to try again."
                attemptsCount = 0
                lockoutTs = int( round( time.time() ) )
                # update the new code to include lockout
                userCodeNew = "%s|%s" % ( userCode, lockoutTs )
            # udpate attempts with new value or lockout timestamp in the user profile
            userService.replaceUserAttribute( authenticated_user.getUserId() , "secretAnswer", userCodeOrig, userCodeNew )
            # set the failure message and exit
            facesMessages.add( FacesMessage.SEVERITY_ERROR, message )
            return False
        else:
            print "MFA Recovery. authenticate. Recovery code successfully verified."
            identity.setWorkingParameter("user_code", None)

        ########################################################################################
        # 6. Remove the recovery code from the user profile and redirect
        #    to mfa selection module to erase MFA enrollments and start over
        removed = userService.removeUserAttribute( authenticated_user.getUserId(), "secretAnswer", userCodeOrig)
        if not removed:
            print "MFA Recovery. authenticate. Failed removing code"
            return False

        print "MFA Recovery. authenticate. Recovery complete, code erased."
        identity.getSessionId().getSessionAttributes().put("authenticationFlow", "EXISTING_USER")
        identity.setWorkingParameter("user_code_success", True)
        CdiUtil.bean(SessionIdService).updateSessionId( identity.getSessionId() )
        return True

    def prepareForStep(self, configurationAttributes, requestParameters, step):
        print "MFA Recovery. prepareForStep called for step '%s'" % step

        identity = CdiUtil.bean(Identity)

        ########################################################################################
        # 1. Make sure we have a session
        session_id_validation = self.validateSessionId(identity)
        if not session_id_validation:
            print "MFA Recovery. prepareForStep. Failed to validate session state" % step
            return False

        authenticationService = CdiUtil.bean(AuthenticationService)
        authenticated_user = authenticationService.getAuthenticatedUser()

        if authenticated_user == None:
            print "MFA Recovery. prepareForStep. Failed to determine authenticated user from previous module"
            return False

        ########################################################################################
        # 2. get the recovery code from the form user profile and save it in the session
        userCode = self.findExistingCode(authenticated_user)
        if (userCode == None):
            print "MFA Recovery. prepareForStep. Did not find code in user profile, cannot recover"
            return False

        return True

    def getNextStep(self, configurationAttributes, requestParameters, step):
        print "MFA Recovery. getNextStep called for step '%s' (returns -1)" % step
        return -1

    def getExtraParametersForStep(self, configurationAttributes, step):
        print "MFA Recovery. getExtraParametersForStep called for step '%s'" % step
        return Arrays.asList("user_code", "user_code_orig", "user_code_attempts", "user_code_lockout_ts", "user_code_success")

    def getCountAuthenticationSteps(self, configurationAttributes):
        print "MFA Recovery. getCountAuthenticationSteps called"
        return 2

    def getPageForStep(self, configurationAttributes, step):
        # Get the locale/language from the browser
        locale = CdiUtil.bean(LanguageBean).getLocaleCode()[:2]
        print "MFA Recovery. getPageForStep called for step '%s' and locale '%s'" % (step, locale)
        # Make sure it matches "en" or "fr"
        if (locale != "en" and locale != "fr"):
            locale = "en"
        # determine what page to display
        if locale == "en":
            return "/en/recover/code.xhtml"
        if locale == "fr":
            return "/fr/recuperer/code.xhtml"

    def logout(self, configurationAttributes, requestParameters):
        print "MFA Recovery. logout called"
        return True

    def validateSessionId(self, identity):
        print "MFA Recovery. validateSessionId called"
        session_id = CdiUtil.bean(SessionIdService).getSessionIdFromCookie()
        if StringHelper.isEmpty(session_id):
            print "MFA Recovery. Validate session id. Failed to determine session_id"
            return False

        return True

    def getCodeFromRequest(self, requestParameters):
        print "MFA Recovery. getCodeFromRequest called"
        try:
            toBeFetched1 = "loginForm:recoveryCode1"
            toBeFetched2 = "loginForm:recoveryCode2"
            toBeFetched3 = "loginForm:recoveryCode3"
            code1 = ServerUtil.getFirstValue(requestParameters, toBeFetched1)
            code2 = ServerUtil.getFirstValue(requestParameters, toBeFetched2)
            code3 = ServerUtil.getFirstValue(requestParameters, toBeFetched3)

            print "MFA Recovery. getCodeFromRequest: fetched loginForm:recoveryCode(s) '%s-%s-%s'" % (code1, code2, code3)
            if StringHelper.isNotEmpty(code1) and StringHelper.isNotEmpty(code2) and StringHelper.isNotEmpty(code3):
                code = "%s-%s-%s" % (code1, code2, code3)
                return code
            return Null
        except Exception, err:
            print("MFA Recovery. getCodeFromRequest Exception: " + str(err))

    def findExistingCode(self, user):
        # get the user by user ID
        if user == None:
            print "MFA Recovery. findExistingCode. Failed to find user"
            return None

        # get the values from the user profile
        userService = CdiUtil.bean(UserService)
        user_secret_answers = userService.getCustomAttribute(user, "secretAnswer")
        if user_secret_answers == None:
            return None

        for user_secret_answer in user_secret_answers.getValues():
            return user_secret_answer

        return None

    def alternateActionRequested(self, requestParameters):
        print "MFA Recovery. alternateActionRequested called"
        try:
            toBeFetched = "loginForm:action"
            print "MFA Recovery. alternateActionRequested: fetching '%s'" % toBeFetched
            action_value = ServerUtil.getFirstValue(requestParameters, toBeFetched)

            print "MFA Recovery. alternateActionRequested: fetched action_value '%s'" % action_value
            if ( StringHelper.isNotEmpty(action_value) ):
                return action_value
            return None
        except Exception, err:
            print("MFA Recovery. alternateActionRequested Exception: " + str(err))
            return None

    def decryptAES(self, key, encryptedStr):
        # make sure key length is 16 bytes (128 bits)
        if ( len(key) != 16 ):
            return None
        # split the encrypted string into IV and ciphertext
        iv, encrypted = encryptedStr[:16], encryptedStr[16:]
        # configure IV and key specification
        skeySpec = SecretKeySpec(key, "AES")
        ivspec = IvParameterSpec(iv);
        # setup cipher
        cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", BouncyCastleProvider())
        cipher.init(Cipher.DECRYPT_MODE, skeySpec, ivspec)
        # decrypt the plaintext
        encodedBytes = base64.b64decode( b'' + encrypted )
        decodedBytes = cipher.doFinal( encodedBytes )
        plaintext    = ''.join(chr(i) for i in decodedBytes)
        return plaintext
