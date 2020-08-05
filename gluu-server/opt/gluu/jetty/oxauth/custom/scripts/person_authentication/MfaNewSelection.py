# oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
# Copyright (c) 2016, Gluu
#
# Authors: Pawel Pietrzynski, Doug Harris
#

from org.gluu.model.custom.script.type.auth import PersonAuthenticationType
from org.gluu.service.cdi.util import CdiUtil
from org.gluu.oxauth.security import Identity
from org.gluu.oxauth.model.util import Base64Util
from org.gluu.util import StringHelper
from org.gluu.oxauth.util import ServerUtil
from org.gluu.oxauth.service import AuthenticationService, UserService, PairwiseIdentifierService, SessionIdService
from org.gluu.oxauth.service.fido.u2f import DeviceRegistrationService
from org.gluu.oxauth.i18n import LanguageBean
from org.gluu.oxauth.model.common import User
from org.oxauth.persistence.model import PairwiseIdentifier

from java.util import ArrayList, Arrays
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
            print "MFA Chooser. Initialization. Failed reading AES key file for decrypting login_hint: %s" % key_file
            return False
        finally:
            f.close()

        # Load customization content from file
        content_file = configurationAttributes.get("custom_page_content_file").getValue2()
        f = open(content_file, 'r')
        try:
            self.customPageContent = json.loads(f.read())
        except:
            print "MFA Chooser. Initialization. Failed to load RP customization content from file: %s" % content_file
            return False
        finally:
            f.close()

            print "MFA Chooser. Initialized successfully"
        return True

    def destroy(self, configurationAttributes):
        print "MFA Chooser. Destroyed successfully"
        return True

    def getApiVersion(self):
        return 2

    def isValidAuthenticationMethod(self, usageType, configurationAttributes):
        print "MFA Chooser. isValidAuthenticationMethod called"

        identity = CdiUtil.bean(Identity)
        sessionId = identity.getSessionId()
        sessionAttributes = sessionId.getSessionAttributes()

        loginHint = sessionAttributes.get("login_hint")
        if ( loginHint == None ):
            # This will get handled in PrepareForStep
            print "MFA Chooser. isValidAuthenticationMethod: ERROR: login_hint missing, will redirect to error in prepareForStep"
            return True

        # Check to see if they are registering and therefore just made a choice
        authenticatorType = identity.getWorkingParameter("authenticatorType")
        if (authenticatorType == None):
            # Nope: Check to see if they have already registered
            user = self.getUser(loginHint)
            authenticatorType = self.getAuthenticatorType(configurationAttributes, user)

        if (authenticatorType != None):
            # Defer to the appropriate module
            identity.setWorkingParameter("authenticatorType", authenticatorType)
            return False
            
        # No, so this is a new user and they have to chose an authenticator type
        return True

    def getAlternativeAuthenticationMethod(self, usageType, configurationAttributes):
        print "MFA Chooser. getAlternativeAuthenticationMethod called"

        identity = CdiUtil.bean(Identity)
        authenticatorType = identity.getWorkingParameter("authenticatorType")
        print "MFA Chooser. getAlternativeAuthenticationMethod: authenticatorType is %s" % authenticatorType

        # Defer to the module approriate for the authenticator type
        if (authenticatorType == "TOTP"):
            return "mfa_otp"
        if (authenticatorType == "U2F"):
            return "mfa_u2f"
        if (authenticatorType == "RecoveryCode"):
            return "recovery_code"

        # We should never get this far
        print "MFA Chooser. getAlternativeAuthenticationMethod: ERROR: authenticatorType %s is missing or invalid" % authenticatorType
        return "select_mfa"

    def authenticate(self, configurationAttributes, requestParameters, step):
        print "MFA Chooser. authenticate called for step '%s'" % step

        identity = CdiUtil.bean(Identity)

        # What option did they choose?
        choice = ServerUtil.getFirstValue(requestParameters, "loginForm:mfachoice")
        print "MFA Chooser. Authenticate: %s selected." % choice
        identity.setWorkingParameter("authenticatorType", choice)

        return False

    def prepareForStep(self, configurationAttributes, requestParameters, step):
        print "MFA Chooser. prepareForStep called for step '%s'" % step

        identity = CdiUtil.bean(Identity)
        sessionAttributes = identity.getSessionId().getSessionAttributes()

        # get user from the login hint and save it in "mfaExternalUid"
        login_hint = sessionAttributes.get("login_hint")
        if (login_hint == None):
            print "ERROR: login_hint is not set, no user context for authentication"
            return False

        print "MFA Chooser. prepareForStep. got session '%s'"  % identity.getSessionId().toString()

        if (step == 1):
            return True
        else:
            return False

    def getApiVersion(self):
        return 2

    def getNextStep(self, configurationAttributes, requestParameters, step):
        print "MFA Chooser. getNextStep called for step '%s' (returns 1)" % step
        return 1

    def getExtraParametersForStep(self, configurationAttributes, step):
        print "MFA Chooser. getExtraParametersForStep called for step '%s'" % step
        return Arrays.asList("authenticatorType", "username")

    def getCountAuthenticationSteps(self, configurationAttributes):
        print "MFA Chooser. getCountAuthenticationSteps called"
        return 2

    def getPageForStep(self, configurationAttributes, step):
        # Get the locale/language from the browser
        locale = CdiUtil.bean(LanguageBean).getLocaleCode()[:2]
        print "MFA Chooser. getPageForStep called for step '%s' and locale '%s'" % (step, locale)
        # Make sure it matches "en" or "fr"
        if (locale != "en" and locale != "fr"):
            locale = "en"
        # determine what page to display
        if locale == "en":
            return "/en/register/new.xhtml"
        if locale == "fr":
            return "/fr/enregistrer/nouveau.xhtml"

    def logout(self, configurationAttributes, requestParameters):
        print "MFA Chooser. logout called"
        return True

    # Returns the user account for the provided login_hint, creating the account if necessary
    def getUser(self, loginHint):
        print "MFA Chooser. getUser() called"

        identity = CdiUtil.bean(Identity)
        sessionAttributes = identity.getSessionId().getSessionAttributes()
        userService = CdiUtil.bean(UserService)
        pairwiseIdentifierService = CdiUtil.bean(PairwiseIdentifierService)

        # Normally we would fetch by pairwise ID ... however because there is no API for that we save MFA PAI in oxExternalUid
        loginHintDecrypted = self.decryptAES(self.aesKey , Base64Util.base64urldecodeToString(loginHint))
        pairwiseId = loginHintDecrypted.split('|')[0]
        relyingParty = loginHintDecrypted.split('|')[1]

        # set APP for future reference in page customization
        sessionAttributes.put("relyingParty", relyingParty)

        # Get the user service and fetch the user
        externalUid = "sic-mfa:" + pairwiseId
        print "MFA Chooser: getUser(). Looking up user with externalUid = '%s'" % externalUid
        user = userService.getUserByAttribute( "oxExternalUid",  externalUid)

        if (user == None):
            # Create a new account
            print "MFA Chooser. authenticate. Creating new user with externalUid = '%s'" % (externalUid)
            newUser = User()
            username = uuid.uuid4().hex
            newUser.setAttribute("uid", username)
            newUser.setAttribute("oxExternalUid", externalUid)
            user = userService.addUser(newUser, True)

            # add a Pairwise Subject Identifier for the OIDC Client
            userInum = user.getAttribute("inum")
            oidcClientId = sessionAttributes.get("client_id")
            sectorIdentifierUri = sessionAttributes.get("redirect_uri")
            
            pairwiseSubject = PairwiseIdentifier(sectorIdentifierUri, oidcClientId)
            pairwiseSubject.setId(pairwiseId)
            pairwiseSubject.setDn(pairwiseIdentifierService.getDnForPairwiseIdentifier(pairwiseSubject.getId(), userInum))
            pairwiseIdentifierService.addPairwiseIdentifier( userInum, pairwiseSubject )

        return user

    # Get the type of authenticator (TOTP, U2F, or RecoveryCode) that can be used to
    # authenticate a user
    def getAuthenticatorType(self, configurationAttributes, user):
        print "MFA Chooser. getAuthenticatorType called"

        userService = CdiUtil.bean(UserService)

        # First, check the user for OTP registrations
        externalUids = userService.getCustomAttribute(user, "oxExternalUid")
        if (externalUids != None):
            # scan through the values to see if any match
            for externalUid in externalUids.getValues():
                index = externalUid.find("totp:")
                if index != -1:
                    print "MFA Chooser. getAuthenticatorType: Found a TOTP authenticator"
                    return "TOTP"

        # Second, check if user has registered U2F devices
        userInum = user.getAttribute("inum")
        u2fApplicationId = configurationAttributes.get("u2f_application_id").getValue2()

        deviceRegistrationService = CdiUtil.bean(DeviceRegistrationService)
        u2fRegistrations = deviceRegistrationService.findUserDeviceRegistrations(userInum, u2fApplicationId)
        if (u2fRegistrations.size() > 0):
            print "MFA Chooser. getAuthenticatorType: Found a U2F authenticator"
            return "UTF"

        # Third, check if the user has a recovery code
        recoveryCode = userService.getCustomAttribute(user, "secretAnswer")
        if (recoveryCode != None):
            print "MFA Chooser. getAuthenticatorType: Found a Recovery Code"
            return "RecoveryCode"

        # No authenticators were found
        print "MFA Chooser. getAuthenticatorType: No authenticators found"
        return None

    def eraseMfaRegistrationsFromProfile(self, user, configurationAttributes):
        print "MFA Chooser. eraseMfaRegistrationsFromProfile called"

        removed = 0

        #### Check the user for OTP registrations
        # Get the oxExternalUid for 'totp' token registrations
        userService = CdiUtil.bean(UserService)
        userOxExternalUid = userService.getCustomAttribute(user, "oxExternalUid")
        if (userOxExternalUid != None):
            # scan through the values to see if any match
            for user_external_uid in userOxExternalUid.getValues():
                index = user_external_uid.find("totp:")
                if index != -1:
                    # remove the totp attribute and return
                    userService = CdiUtil.bean(UserService)
                    if ( userService.removeUserAttribute(user.getUserId(), "oxExternalUid", user_external_uid) ):
                        removed += 1
                    else:
                        print "MFA Chooser. eraseMfaRegistrationsFromProfile. Cannot remove oxExternalUid for TOTP"

        #### If TOTP not found check the user for registered devices
        # Check if user have registered devices
        userInum = user.getAttribute("inum")
        u2f_application_id = configurationAttributes.get("u2f_application_id").getValue2()

        # Get the device registration persistence service to retrieve U2F devices
        deviceRegistrationService = CdiUtil.bean(DeviceRegistrationService)
        deviceRegistrationsList = deviceRegistrationService.findUserDeviceRegistrations(userInum, u2f_application_id)
        for deviceRegistration in deviceRegistrationsList:
            # remove the device registration
            if ( deviceRegistrationService.removeUserDeviceRegistration (deviceRegistration) ):
                removed += 1
            else:
                print "MFA Chooser. eraseMfaRegistrationsFromProfile. Cannot unregister device %s" % deviceRegistration.getId()

        return removed

    def decryptAES(self, key, encryptedStr):

        # make sure key length is 16 bytes (128 bits)
        if ( len(key) != 16 ):
            return None
        # split the encrypted string into IV and ciphertext
        iv, encrypted = encryptedStr[:16], encryptedStr[16:]
        # configure IV and key specification
        skeySpec = SecretKeySpec(key, "AES")
        ivspec = IvParameterSpec(iv)
        # setup cipher
        cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", BouncyCastleProvider())
        cipher.init(Cipher.DECRYPT_MODE, skeySpec, ivspec)
        # decrypt the plaintext
        encodedBytes = base64.b64decode( b'' + encrypted )
        decodedBytes = cipher.doFinal( encodedBytes )
        plaintext    = ''.join(chr(i) for i in decodedBytes)
        return plaintext


    def getMfaValueFromAuth(self, requestParameters):
        print "MFA Chooser. getMfaValueFromAuth called"
        try:
            toBeFeatched = "loginForm:mfachoice"
            print "MFA Chooser. getMfaValueFromAuth: fetching '%s'" % toBeFeatched
            new_acr_value = ServerUtil.getFirstValue(requestParameters, toBeFeatched)

            print "MFA Chooser. getMfaValueFromAuth: fetched new_acr_value '%s'" % new_acr_value
            if StringHelper.isNotEmpty(new_acr_value):
                return new_acr_value
            return Null
        except Exception, err:
            print("MFA Chooser. getMfaValueFromAuth Exception: " + str(err))
