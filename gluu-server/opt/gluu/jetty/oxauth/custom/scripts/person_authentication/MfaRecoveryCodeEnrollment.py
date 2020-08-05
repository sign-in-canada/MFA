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
from org.gluu.oxauth.service import AuthenticationService, UserService, PairwiseIdentifierService, SessionIdService
from org.gluu.oxauth.service.fido.u2f import DeviceRegistrationService
from org.gluu.oxauth.i18n import LanguageBean
from org.gluu.oxauth.model.common import User
from org.oxauth.persistence.model import PairwiseIdentifier

from java.util import ArrayList
from java.util import Arrays
from java.security import Key
from javax.crypto import Cipher
from javax.crypto.spec import SecretKeySpec, IvParameterSpec
from org.bouncycastle.jce.provider import BouncyCastleProvider

import sys
import java
import json
import uuid
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
            print "MFA Enroll Recovery. Initialization. Failed reading AES key file for decrypting recovery code: %s" % key_file
            return False
        finally:
            f.close()

        # Load customization content from file
        content_file = configurationAttributes.get("custom_page_content_file").getValue2()
        f = open(content_file, 'r')
        try:
            self.customPageContent = json.loads(f.read())
        except:
            print "MFA Enroll Recovery. Initialization. Failed to load RP customization content from file: %s" % content_file
            return False
        finally:
            f.close()

        print "MFA Enroll Recovery. Initialized successfully"
        return True

    def destroy(self, configurationAttributes):
        print "MFA Enroll Recovery. Destroyed successfully"
        return True

    def getApiVersion(self):
        return 2

    def isValidAuthenticationMethod(self, usageType, configurationAttributes):
        print "MFA Enroll Recovery. isValidAuthenticationMethod called"
        # To do any operations we need the session variables available
        identity = CdiUtil.bean(Identity)
        authenticationFlow = identity.getSessionId().getSessionAttributes().get("authenticationFlow")
        if (authenticationFlow == "RESTART_ENROLLMENT"):
            return False
        return True

    def getAlternativeAuthenticationMethod(self, usageType, configurationAttributes):
        print "MFA Enroll Recovery. getAlternativeAuthenticationMethod called"
        # To do any operations we need the session variables available
        identity = CdiUtil.bean(Identity)
        authenticationFlow = identity.getSessionId().getSessionAttributes().get("authenticationFlow")
        if ( authenticationFlow == "RESTART_ENROLLMENT" ):
            identity.getSessionId().getSessionAttributes().put("authenticationFlow", "EXISTING_USER")
            CdiUtil.bean(SessionIdService).updateSessionId( identity.getSessionId() )
            return "select_mfa"
        return None

    def authenticate(self, configurationAttributes, requestParameters, step):
        print "MFA Enroll Recovery. authenticate called for step '%s'" % step

        # if it's the confirmation page then just get on with it and finish
        if (step == 2):
            return True

        identity = CdiUtil.bean(Identity)
        # For authentication then check if someone enrolling clicked CANCEL button
        alternateAction = self.alternateActionRequested(requestParameters)
        if ( alternateAction == 'cancel'):
            identity.getSessionId().getSessionAttributes().put("authenticationFlow", "RESTART_ENROLLMENT")
            CdiUtil.bean(SessionIdService).updateSessionId( identity.getSessionId() )
            return True

        ########################################################################################
        # 1. Make sure we have a session and a user with no existing codes in the profile
        session_id_validation = self.validateSessionId(identity)
        if not session_id_validation:
            print "MFA Enroll Recovery. prepareForStep for step %s. Failed to validate session state" % step
            return False

        authenticationService = CdiUtil.bean(AuthenticationService)
        authenticated_user = authenticationService.getAuthenticatedUser()

        if authenticated_user == None:
            print "MFA Enroll Recovery. prepareForStep. Failed to determine authenticated user from previous module"
            return False

        ########################################################################################
        # 2. Get the confirmation checkbox value
        confirmCodeBox = None
        try:
            toBeFeatched = "loginForm:confirmCodeBox"
            print "MFA Enroll Recovery. authenticate: fetching '%s'" % toBeFeatched
            confirmCodeBox = ServerUtil.getFirstValue(requestParameters, toBeFeatched)
        except Exception, err:
            print("MFA Enroll Recovery. authenticate Exception getting form checkbox: " + str(err))

        print "MFA Enroll Recovery. authenticate: fetched confirmCodeBox = '%s'" % confirmCodeBox
        if confirmCodeBox != "on":
            return False

        ########################################################################################
        # 3. Remove any old code from the user profile
        existingCode = self.findExistingCode(authenticated_user)
        userService = CdiUtil.bean(UserService)
        if existingCode != None:
            print "MFA Enroll Recovery. prepareForStep. User already has a recovery code"
            removed = userService.removeUserAttribute(authenticated_user.getUserId(), "secretAnswer", existingCode)
            if not removed:
                print "MFA Enroll Recovery. authenticate. Failed removing code"
                return False
            print "MFA Enroll Recovery. authenticate. Recovery complete, code erased."

        ########################################################################################
        # 4. Save the new recovery code in the user's profile
        #    - use "secretAnswer" for storage
        #    - encrypt using key
        new_code = identity.getWorkingParameter("new_code")
        new_code_encrypted = self.encryptAES( self.aesKey, new_code )

        savedCode = userService.addUserAttribute(authenticated_user.getUserId() , "secretAnswer", new_code_encrypted)
        if ( savedCode ):
            identity.getSessionId().getSessionAttributes().put("authenticationFlow", "ENROLLMENT_COMPLETE")
            CdiUtil.bean(SessionIdService).updateSessionId( identity.getSessionId() )
            print "MFA Enroll Recovery. authenticate. New code saved for user '%s' result = '%s'" % (authenticated_user.getUserId(), savedCode)
        else:
            return False

        username = authenticated_user.getUserId()
        logged_in = CdiUtil.bean(AuthenticationService).authenticate(username)
        print "MFA Enroll Recovery. authenticate. Authenticating user '%s' result = '%s'" % (username, logged_in)
        if ( logged_in ):
            return True

        return False

    def prepareForStep(self, configurationAttributes, requestParameters, step):
        print "MFA Enroll Recovery. prepareForStep called for step '%s'" % step

        if (step == 1):
            identity = CdiUtil.bean(Identity)
            ########################################################################################
            # 1. Make sure we have a session
            session_id_validation = self.validateSessionId(identity)
            if not session_id_validation:
                print "MFA Enroll Recovery. prepareForStep for step %s. Failed to validate session state" % step
                return False

            authenticationService = CdiUtil.bean(AuthenticationService)
            authenticated_user = authenticationService.getAuthenticatedUser()

            if authenticated_user == None:
                print "MFA Enroll Recovery. prepareForStep. Failed to determine authenticated user from previous module"
                return False

            ########################################################################################
            # 2. Generate a recovery code with 128 bit strength
            #    - use Alphanumeric (A-Z,0-9)
            #    - use size of 12 (to achieve around 61 bits of entropy)
            #    - save it in "new_code"
            if (identity.getWorkingParameter("new_code") == None):
                alphanumeric = string.ascii_lowercase + string.digits
                code1 = ''.join(random.SystemRandom().choice(alphanumeric) for _ in range( 4 ))
                code2 = ''.join(random.SystemRandom().choice(alphanumeric) for _ in range( 4 ))
                code3 = ''.join(random.SystemRandom().choice(alphanumeric) for _ in range( 4 ))
                code  = "%s-%s-%s" % (code1, code2, code3)
                identity.setWorkingParameter("new_code", code)
            else:
                print "MFA Enroll Recovery. prepareForStep. A code has already been generated and not confirmed"

            print "MFA Enroll Recovery. prepareForStep. got session '%s'"  % identity.getSessionId().toString()

        return True

    def getApiVersion(self):
        return 2

    def getNextStep(self, configurationAttributes, requestParameters, step):
        print "MFA Enroll Recovery. getNextStep called for step '%s' (returning -1)" % step
        return -1

    def getExtraParametersForStep(self, configurationAttributes, step):
        print "MFA Enroll Recovery. getExtraParametersForStep called for step '%s'" % step
        return Arrays.asList("new_code")

    def getCountAuthenticationSteps(self, configurationAttributes):
        print "MFA Enroll Recovery. getCountAuthenticationSteps called"
        return 2
        ####### THIS BLOCK IS INVALID BECAUSE WE ADDED A CONFIRMATION PAGE #########
        ## # To do any operations we need the identity variables available
        ## steps = 1
        ## authenticationFlow = CdiUtil.bean(Identity).getSessionId().getSessionAttributes().get("authenticationFlow")
        ## if ( authenticationFlow == "RESTART_ENROLLMENT" ):
        ##     steps = 2
        ## print "MFA Enroll Recovery. getCountAuthenticationSteps returning %s" % steps
        ## return steps

    def getPageForStep(self, configurationAttributes, step):
        # Get the locale/language from the browser
        locale = CdiUtil.bean(LanguageBean).getLocaleCode()[:2]
        print "MFA Enroll Recovery. getPageForStep called for step '%s' and locale '%s'" % (step, locale)
        # Make sure it matches "en" or "fr"
        if (locale != "en" and locale != "fr"):
            locale = "en"
        # determine what page to display - get the authentication flow
        authenticationFlow = CdiUtil.bean(Identity).getSessionId().getSessionAttributes().get("authenticationFlow")
        # check if it has completed
        if authenticationFlow != "ENROLLMENT_COMPLETE":
            if locale == "en":
                return "/en/register/code.xhtml"
            if locale == "fr":
                return "/fr/enregistrer/code.xhtml"
        else:
            if locale == "en":
                return "/en/register/complete.xhtml"
            if locale == "fr":
                return "/fr/enregistrer/termine.xhtml"

        return page

    def logout(self, configurationAttributes, requestParameters):
        print "MFA Enroll Recovery. logout called"
        return True

    def validateSessionId(self, identity):
        print "MFA Enroll Recovery. validateSessionId called"
        session_id = CdiUtil.bean(SessionIdService).getSessionIdFromCookie()
        if StringHelper.isEmpty(session_id):
            print "MFA Enroll Recovery. Validate session id. Failed to determine session_id"
            return False

        return True

    def findExistingCode(self, user):
        # get the user by user ID
        if user == None:
            print "MFA Enroll Recovery. findExistingCode. Failed to find user"
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
        print "MFA Enroll Recovery. alternateActionRequested called"
        try:
            toBeFetched = "loginForm:action"
            print "MFA Enroll Recovery. alternateActionRequested: fetching '%s'" % toBeFetched
            action_value = ServerUtil.getFirstValue(requestParameters, toBeFetched)

            print "MFA Enroll Recovery. alternateActionRequested: fetched action_value '%s'" % action_value
            if ( StringHelper.isNotEmpty(action_value) ):
                return action_value
            return None
        except Exception, err:
            print("MFA Enroll Recovery. alternateActionRequested Exception: " + str(err))
            return None

    def encryptAES(self, key, toEncrypt):

        # make sure key length is 16 bytes (128 bits)
        if ( len(key) != 16 ):
            return None
        # generate a random IV
        randomSource = string.ascii_letters + string.digits
        iv = ''.join(random.SystemRandom().choice(randomSource) for i in range(16))
        # configure IV and key specification
        skeySpec = SecretKeySpec(key, "AES")
        ivspec = IvParameterSpec(iv);
        # setup cipher
        cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", BouncyCastleProvider())
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec, ivspec)
        # encrypt the plaintext
        encryptedBytes = cipher.doFinal( toEncrypt.encode('utf-8') )
        encryptedValue = base64.b64encode( encryptedBytes )
        return iv.encode("ascii") + encryptedValue
