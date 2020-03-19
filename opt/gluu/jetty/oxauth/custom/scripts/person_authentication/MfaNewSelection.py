# oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
# Copyright (c) 2016, Gluu
#
# Author: Pawel Pietrzynski
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

from java.util import ArrayList
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

        # To do any operations we need the session variables available
        identity = CdiUtil.bean(Identity)
        sessionId = identity.getSessionId()
        sessionAttributes = sessionId.getSessionAttributes()

        # Customization values for all the authentication pages
        entityId = sessionAttributes.get("mfaExternalApp")
        if (sessionAttributes.get("pageContent") == None):
            pageContent = self.customPageContent.get(entityId)
            if ( self.customPageContent.get(entityId) != None ):
                sessionAttributes.put("pageContent", self.customPageContent[entityId])
            else:
                sessionAttributes.put("pageContent", self.customPageContent["_default"])

        # - NEW REGISTRATION - select MFA credential set in "new_acr_value"
        #   - when mfaPai does not exist (set "authenticationFlow" flag to NEW_USER show recovery codes)
        #   - when mfaPai exists but there are no credentials on the account, display select page
        # - REGISTERED USER - select known MFA option
        #   - when account exists and one (or soon both) MFA credentials are registered, redirect to proper ACR

        # If there is "new_acr_value" that means a choice has been made, no checks needed
        new_acr_value = sessionAttributes.get("new_acr_value")
        if ( new_acr_value != None ):
            print "MFA Chooser. isValidAuthenticationMethod: new_acr_value retrieved from user = '%s'" % new_acr_value
            return False

        # Then check if we are coming from the recovery module with authenticationFlow already set
        if ( sessionAttributes.get("authenticationFlow") == "EXISTING_USER" ):
            # confirm the user is authenticated
            authenticationService = CdiUtil.bean(AuthenticationService)
            user = authenticationService.getAuthenticatedUser()
            if ( user != None ):
                print "MFA Chooser. isValidAuthenticationMethod: User already flagged for re-registration by the recovery module"
                return True

        #################################################################
        # DEBUG HARDCODE PAI/CLIENT
        # login_hint = "QmpLY3VqakhHem9EMVQ2bHUyeDhzQmo3bXQzMGlJRXJTOUJiMTQ1cGY1QVcySW9YUW1KVlltSUlvK2tONVRZWFlia3Z1ajFiZTd5eGdreTNKbDJ3cTRLTWJrOFRpKysrZ2lBeVRtWDQ3Tk03dmZVeE8yd05mQUh1aVhzPQ"
        # sessionAttributes.put("login_hint", login_hint)
        #################################################################
        # First check if the login hint was passed or exists as a session variable
        #################################################################
        ####### ....... UNCOMMENT LINE BELOW .......
        login_hint = sessionAttributes.get("login_hint")
        #################################################################
        if ( login_hint == None ):
            # This will get handled in PrepareForStep
            print "MFA Chooser. isValidAuthenticationMethod: ERROR: login_hint missing, will redirect to error in prepareForStep"
            return True

        # Secondly look for the user using the login_hint
        userByMfaUid = self.processLoginHint( login_hint )
        if ( userByMfaUid == None ):
            sessionAttributes.put("authenticationFlow", "NEW_USER")
            CdiUtil.bean(SessionIdService).updateSessionId(sessionId)
            print "MFA Chooser. isValidAuthenticationMethod: MFA user from hint not found, going to registration flow"
            return True

        # Thirdly check if the user has a recovery code registered
        userService = CdiUtil.bean(UserService)
        userRecoveryCode = userService.getCustomAttribute(userByMfaUid, "secretAnswer")
        if ( userRecoveryCode == None ):
            sessionAttributes.put("authenticationFlow", "EXISTING_USER")
            CdiUtil.bean(SessionIdService).updateSessionId(sessionId)
            print "MFA Chooser. isValidAuthenticationMethod: MFA user has no recovery code, going to registration flow"
            return True

        # Lastly check if the user has any tokens registered and get their ACR
        userMfaAcr = self.getUserMfaAcrFromProfile(userByMfaUid, sessionAttributes, configurationAttributes)
        if ( userMfaAcr == None ):
            sessionAttributes.put("authenticationFlow", "EXISTING_USER")
            CdiUtil.bean(SessionIdService).updateSessionId(sessionId)
            print "MFA Chooser. isValidAuthenticationMethod: The user does not have registered tokens, forwarding to registration"
            return True

        # before we redirect we need to set the username
        username = userByMfaUid.getUserId()
        logged_in = CdiUtil.bean(AuthenticationService).authenticate(username)
        print "MFA Chooser. isValidAuthenticationMethod. Authenticating user '%s' result = '%s'" % (username, logged_in)
        if ( logged_in ):
            # now redirect the user to the proper ACR if authentication is successful
            sessionAttributes.put("authenticationFlow", "MFA_VALIDATION")
            sessionAttributes.put("mfaAuthUsername", username)
            CdiUtil.bean(SessionIdService).updateSessionId(sessionId)
            return False

        CdiUtil.bean(SessionIdService).updateSessionId(sessionId)
        return True


    def getAlternativeAuthenticationMethod(self, usageType, configurationAttributes):
        print "MFA Chooser. getAlternativeAuthenticationMethod called"

        # To do any operations we need the session variables available
        identity = CdiUtil.bean(Identity)
        sessionId = identity.getSessionId()
        sessionAttributes = sessionId.getSessionAttributes()

        # get new ACR and redirect the user
        new_acr_value = sessionAttributes.get( "new_acr_value" )
        print "MFA Chooser. getAlternativeAuthenticationMethod: new_acr_value retrieved = '%s'" % new_acr_value

        # clear the session variable and redirect
        sessionAttributes.remove( "new_acr_value" )
        CdiUtil.bean(SessionIdService).updateSessionId(sessionId)
        return new_acr_value

    def authenticate(self, configurationAttributes, requestParameters, step):
        print "MFA Chooser. authenticate called for step '%s'" % step

        # process the ACR selection
        identity = CdiUtil.bean(Identity)
        sessionId = identity.getSessionId()
        sessionAttributes = sessionId.getSessionAttributes()

        new_acr_value = self.getMfaValueFromAuth(requestParameters)
        print "MFA Chooser. authenticate: setting new_acr_value = '%s'" % new_acr_value

        # retrieve the user
        username = None
        mfaPairwiseId  = sessionAttributes.get("mfaPairwiseId")
        mfaExternalUid = "sic-mfa:" + mfaPairwiseId

        # Create a shell account for the next step if the user has not been found
        userService = CdiUtil.bean(UserService)
        if ( sessionAttributes.get("authenticationFlow") == "NEW_USER" ):
            username = uuid.uuid4().hex
            # create the user
            print "MFA Chooser. authenticate. Creating new user '%s' with externalUid = '%s'" % (username, mfaExternalUid)
            newUser = User()
            newUser.setAttribute( "uid", username )
            newUser.setAttribute( "oxExternalUid", mfaExternalUid )
            newUser = userService.addUser(newUser, True)

            # now that the user is added create a PairwiseIdentifier for the OIDC Client
            pairwiseIdentifierService = userService = CdiUtil.bean(PairwiseIdentifierService)
            userInum = newUser.getAttribute("inum");
            oidcClientId = sessionAttributes.get("client_id");
            sectorIdentifierUri = sessionAttributes.get("redirect_uri");
            # Create a new pairwise ID object and add it to the user
            pairwiseIdentifier = PairwiseIdentifier( sectorIdentifierUri, oidcClientId );
            pairwiseIdentifier.setId( mfaPairwiseId );
            pairwiseIdentifier.setDn( pairwiseIdentifierService.getDnForPairwiseIdentifier( pairwiseIdentifier.getId(), userInum));
            pairwiseIdentifierService.addPairwiseIdentifier( userInum, pairwiseIdentifier );

        elif ( sessionAttributes.get("authenticationFlow") == "EXISTING_USER" ):
            print "MFA Chooser. authenticate. Fetching user with externalUid = '%s'" % mfaExternalUid
            currentUser = userService.getUserByAttribute("oxExternalUid", mfaExternalUid)
            username = currentUser.getUserId()
            removed = self.eraseMfaRegistrationsFromProfile(currentUser, configurationAttributes)

        logged_in = CdiUtil.bean(AuthenticationService).authenticate(username)
        print "MFA Chooser. authenticate. Authenticating user '%s' result = '%s'" % (username, logged_in)

        if ( step == 1 and logged_in ):
            # now redirect the user to the proper ACR if authentication is successful
            sessionAttributes.put("new_acr_value", new_acr_value)
            sessionAttributes.put("mfaAuthUsername", username)
            CdiUtil.bean(SessionIdService).updateSessionId(sessionId)
            return True

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
        return None

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


    def processLoginHint(self, login_hint):
        print "MFA Chooser. processLoginHint called"

        identity = CdiUtil.bean(Identity)
        sessionAttributes = identity.getSessionId().getSessionAttributes()

        # Normally we would fetch by pairwise ID ... however because that is impossible we save MFA PAI in oxExternalUid
        login_hint_decrypted = self.decryptAES( self.aesKey , Base64Util.base64urldecodeToString(login_hint) )
        mfaPairwiseId = login_hint_decrypted.split('|')[0]
        mfaExternalApp = login_hint_decrypted.split('|')[1]

        # set APP for future reference in page customization
        sessionAttributes.put( "mfaExternalApp", mfaExternalApp )
        # set extracted pairwise ID
        sessionAttributes.put( "mfaPairwiseId", mfaPairwiseId )

        # Get the user service and fetch the user
        mfaExternalUid = "sic-mfa:" + mfaPairwiseId
        print "MFA Chooser. processLoginHint. Fetching user with externalUid = '%s'" % mfaExternalUid
        userService = CdiUtil.bean(UserService)
        userByMfaUid = userService.getUserByAttribute( "oxExternalUid",  mfaExternalUid)

        return userByMfaUid;

    def getUserMfaAcrFromProfile(self, user, sessionAttributes, configurationAttributes):
        print "MFA Chooser. getUserMfaFromProfile called"

        #### Check the user for OTP registrations
        # Get the oxExternalUid for 'totp' token registrations
        userService = CdiUtil.bean(UserService)
        userOxExternalUid = userService.getCustomAttribute(user, "oxExternalUid")
        if (userOxExternalUid != None):
            # scan through the values to see if any match
            for user_external_uid in userOxExternalUid.getValues():
                index = user_external_uid.find("totp:")
                if index != -1:
                    # found an OTP token registered to the user
                    sessionAttributes.put( "new_acr_value" , "mfa_otp" )
                    return "mfa_otp"

        #### If not found check the user for registered devices
        # Check if user have registered devices
        userInum = user.getAttribute("inum")
        u2f_application_id = configurationAttributes.get("u2f_application_id").getValue2()

        # Get the device registration persistence service to retrieve U2F devices
        deviceRegistrationService = CdiUtil.bean(DeviceRegistrationService)
        deviceRegistrations = deviceRegistrationService.findUserDeviceRegistrations(userInum, u2f_application_id)
        if (deviceRegistrations.size() > 0):
            # found a FIDO2 token registered to the user
            sessionAttributes.put( "new_acr_value" , "mfa_u2f" )
            return "mfa_u2f"

        #### If not found return nothing
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
        ivspec = IvParameterSpec(iv);
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
