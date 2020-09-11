# oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
# Copyright (c) 2016, Gluu
#
# Author: Doug Harris
#

# This authentication script has 2 primary flows:
#
#  a) Authenticate
#  b) Register
#
# The Authenticate workflow is triggered for existing users, and has a single step.
# That step authenticates the user's TOTP, FIDO Security Key, or Recovery Code as appropriate.
#
# The Register workflow is triggered for new users, as well as existing users who
# have just completed authentication with their recovery code.
# The TOTP Register workflow has 4 steps:
#      1) Choose an authenticator type (TOTP or FIDO)
#      2) Display an information page
#      3) Register the Authenticator (and generate a new recovery code)
#      4) Display the recovery code
# The FIDO Register workflow has 3 steps:
#      1) Choose an authenticator type (TOTP or FIDO)
#      2) Register the Authenticator (and generate a new recovery code)
#      3) Display the recovery code
#
# Working Parameters
# ------------------
#
# "rpContent": Custom content identifier for the RP
# "rpShortName": A short name for the RP
#
# "flow": The active workflow. Values are "Authenticate" and "Register".
#
# # "authenticatorType": The authenticator type being verified (or registered).
#    values: "TOTP", "FIDO", or "RecoveryCode".
#
# "userid": The userid (uid) of the user
#
# "pairwiseId": The pairwise pseudonym (PAI) for the Acceptance Platform
#
# "nextStep": The next step in a registration workflow. Used to gracefully 
# recover from backwards user navigation. A value of -1 indicates a non-recoverable
# error.

from org.gluu.model.custom.script.type.auth import PersonAuthenticationType
from org.gluu.service.cdi.util import CdiUtil
from org.gluu.oxauth.security import Identity
from org.gluu.oxauth.model.util import Base64Util
from org.gluu.oxauth.model.config import Constants
from org.gluu.util import StringHelper
from org.gluu.oxauth.util import ServerUtil
from org.gluu.oxauth.service import AuthenticationService, AuthenticationProtectionService, UserService, ClientService, PairwiseIdentifierService
from javax.faces.application import FacesMessage
from org.gluu.jsf2.message import FacesMessages
from org.gluu.jsf2.service import FacesResources
from org.gluu.oxauth.service.fido.u2f import DeviceRegistrationService
from org.gluu.oxauth.client.fido.u2f import FidoU2fClientFactory
from org.gluu.oxauth.i18n import LanguageBean
from org.gluu.oxauth.model.common import User
from org.oxauth.persistence.model import PairwiseIdentifier

from org.jboss.resteasy.client import ClientResponseFailure
from org.jboss.resteasy.client.exception import ResteasyClientException

from com.google.common.io import BaseEncoding

from com.lochbridge.oath.otp import TOTP, HmacShaAlgorithm
from com.lochbridge.oath.otp.keyprovisioning import OTPAuthURIBuilder, OTPKey
from com.lochbridge.oath.otp.keyprovisioning.OTPKey import OTPType

from java.util import Arrays, ArrayList
from java.security import SecureRandom
from javax.crypto import Cipher
from javax.crypto.spec import SecretKeySpec, IvParameterSpec
from javax.servlet.http import HttpServletResponse
from java.util.concurrent import TimeUnit
from org.bouncycastle.jce.provider import BouncyCastleProvider

import sys
import java
import json
import uuid
import jarray
import base64
import random
import string

REMOTE_DEBUG = False

if REMOTE_DEBUG:
    try:
        import sys
        sys.path.append("/opt/libs/pydevd")
        import pydevd
    except ImportError as ex:
        print "Failed to import pydevd: %s" % ex
        raise

class PersonAuthentication(PersonAuthenticationType):
    def __init__(self, currentTimeMillis):
        self.currentTimeMillis = currentTimeMillis

    def init(self, configurationAttributes):
        #if REMOTE_DEBUG:
        #    pydevd.settrace('localhost', port=5678, stdoutToServer=True, stderrToServer=True)

        # Load encryption key file content
        key_file = configurationAttributes.get("encryption_key_file").getValue2()
        f = open( key_file, 'r' )
        try:
            key = f.read()
            self.aesKey = key[:16]
        except:
            print "MFA. Initialization. Failed reading AES key file for decrypting login_hint: %s" % key_file
            return False
        finally:
            f.close()

        # Load customization content from file
        content_file = configurationAttributes.get("custom_page_content_file").getValue2()
        f = open(content_file, 'r')
        try:
            self.customPageContent = json.loads(f.read())
        except:
            print "MFA. Initialization. Failed to load RP customization content from file: %s" % content_file
            return False
        finally:
            f.close()

        # Load TOTP configuration
        self.loadOtpConfiguration(configurationAttributes)

        # Load FIDO Configuration
        self.loadFIDOConfiguration(configurationAttributes)

        print "MFA. Initialized successfully"
        return True

    def destroy(self, configurationAttributes):
        print "MFA. Destroyed successfully"
        return True

    def getApiVersion(self):
        # apiVersion > 1 means we support getNextStep.
        return 2

    def isValidAuthenticationMethod(self, usageType, configurationAttributes):
        print "MFA. isValidAuthenticationMethod called."
        # This script is self-contained
        return True

    def getAlternativeAuthenticationMethod(self, usageType, configurationAttributes):
        # This should never be called
        return "mfa"

    def prepareForStep(self, configurationAttributes, requestParameters, step):
        if REMOTE_DEBUG:
            pydevd.settrace('localhost', port=5678, stdoutToServer=True, stderrToServer=True)

        # Inject dependencies
        identity = CdiUtil.bean(Identity)
        languageBean = CdiUtil.bean(LanguageBean)
                
        print "MFA. prepareForStep called for step '%s'" % step
        
        try:
            # Set up working parameters if needed
            authenticatorType = identity.getWorkingParameter("authenticatorType")
            userId = identity.getWorkingParameter("userId")
            if (userId is None): # Session was just created. Initialize the working parameters
                # Parse the login hint to get the paiwiseId
                pairwiseId, relyingParty = self.parseLoginHint()
    
                # Retrieve the user account (again)
                user = self.getUser(pairwiseId)
                userId = user.getUserId()
                
                # Check for registered authenticators
                authenticatorType = self.getAuthenticatorType(user, configurationAttributes)
                
                identity.setWorkingParameter("relyingParty", relyingParty)
                identity.setWorkingParameter("userId", userId)
                identity.setWorkingParameter("authenticatorType", authenticatorType)
    
            rpContent = identity.getWorkingParameter("rpContent")
            if (rpContent is None):
                # Load the UI customization for the RP
                rpContent = self.customPageContent.get("_default")
                for contentKey in self.customPageContent.keys():
                        if (relyingParty.find(contentKey) == 0):
                            rpContent = self.customPageContent.get(contentKey)
                            break
                identity.setWorkingParameter("rpContent", rpContent.get("content"))

                locale = languageBean.getLocaleCode()[:2]
                shortName = rpContent.get("shortName." + locale)
                identity.setWorkingParameter("rpShortName", shortName)
            
            flow = identity.getWorkingParameter("flow")
            if (flow is None):
                if (authenticatorType is None):
                    flow = "Register"
                else:
                    flow = "Authenticate"
                identity.setWorkingParameter("flow", flow)
            
            if (authenticatorType == "FIDO"):
                if (flow == "Register" and step == 2):
                    self.prepareFidoRegistration(userId, identity)
                elif (flow == "Authenticate" and step == 1):
                    self.prepareFidoAuthentication(userId, identity)

            return True
        except Exception as e:
            print(e)
            return False

    def getExtraParametersForStep(self, configurationAttributes, step):
        print "MFA. getExtraParametersForStep called for step '%s'" % step

        # Inject dependencies
        identity = CdiUtil.bean(Identity)
        flow = identity.getWorkingParameter("flow")
        authenticatorType = identity.getWorkingParameter("authenticatorType")

        # General Parameters
        parameters = ArrayList(Arrays.asList("userId", "flow", "authenticatorType",
                                             "nextStep", "rpShortName", "rpContent"))
        
        # Registration Parameters
        if (flow == "Register"):
            parameters.add("recoveryCode")
            if (authenticatorType == "TOTP" and step == 3):
                parameters.addAll(Arrays.asList("totpEnrollmentRequest", "qrLabel", "qrOptions"))
            if (authenticatorType == "FIDO" and step == 2):
                parameters.add("fido_u2f_registration_request")

        if (flow == "Authenticate" and authenticatorType == "FIDO" and step == 2):
                parameters.add("fido_u2f_authentication_request")

        return parameters

    def getPageForStep(self, configurationAttributes, step):
#        if REMOTE_DEBUG:
#            pydevd.settrace('localhost', port=5678, stdoutToServer=True, stderrToServer=True)

        # Inject dependencies
        languageBean = CdiUtil.bean(LanguageBean)
        userService = CdiUtil.bean(UserService)
        identity = CdiUtil.bean(Identity)
        
        session = identity.getSessionId()

        locale = languageBean.getLocaleCode()[:2]
        print "MFA: getPageForStep called for step '%s' and locale '%s'" % (step, locale)
        # Make sure it matches "en" or "fr"
        if (locale != "en" and locale != "fr"):
            locale = "en"

        if (session is None):
            # Parse the login hint to get the paiwiseId
            try:
                pairwiseId, _ = self.parseLoginHint()
            except:
                return "/error.xhtml"

            # Retrieve (or create if needed) the user account
            user = self.getUser(pairwiseId)
        
            # Check for existing authenticators
            authenticatorType = self.getAuthenticatorType(user, configurationAttributes)
            if (authenticatorType is None):
                flow = "Register"
            else:
                flow = "Authenticate"

        else:
            flow = identity.getWorkingParameter("flow")
            authenticatorType = identity.getWorkingParameter("authenticatorType")
            if (authenticatorType is None): # Aborted recovery
                # Go back to the user profile to determine the authenticator
                userId = identity.getWorkingParameter("userId")
                user = userService.getUser(userId, "oxExternalUid")
                authenticatorType = self.getAuthenticatorType(user, configurationAttributes)

        # See ../../i18n/oxauth_[lang].properties
        if (flow == "Authenticate"):
            page = "/%s/%s/%s" % (locale, 
                                  languageBean.getMessage("mfa.pagePath." + flow),
                                  languageBean.getMessage("mfa.authenticatePageFor" + authenticatorType))
        elif (flow == "Register"):
            if (authenticatorType is None or step == 1):
                page = "/%s/%s/%s" % (locale,
                                      languageBean.getMessage("mfa.pagePath." + flow),
                                      languageBean.getMessage("mfa.chooserPage"))
            else:
                page = "/%s/%s/%s" % (locale,
                                      languageBean.getMessage("mfa.pagePath." + flow),
                                      languageBean.getMessage("mfa.registerPageFor%sStep.%s" % (authenticatorType, step)))
        else:
            print "MFA: getPageForStep ERROR! working parameter flow is invalid: " + flow
            page = "/error.xhtml"

        print "MFA: getPageForStep returning: " + page
        return page
        
    def authenticate(self, configurationAttributes, requestParameters, step):
        print "MFA. authenticate called for step '%s'" % step

        if REMOTE_DEBUG:
            pydevd.settrace('localhost', port=5678, stdoutToServer=True, stderrToServer=True)

        # Inject dependencies
        identity = CdiUtil.bean(Identity)
        authenticationService = CdiUtil.bean(AuthenticationService)

        flow = identity.getWorkingParameter("flow")
        authenticatorType = identity.getWorkingParameter("authenticatorType")
        userId = identity.getWorkingParameter("userId")

        if (flow == "Authenticate"):
            if (requestParameters.containsKey("TOTPauthenticate")):
                if (requestParameters.containsKey("TOTPauthenticate:Recover")):
                    identity.setWorkingParameter("authenticatorType", "RecoveryCode")
                    identity.setWorkingParameter("nextStep", 1) # Start over
                else:
                    if (self.authenticateTOTP(requestParameters, userId, identity)):
                        return authenticationService.authenticate(userId)
                    else:
                        return False
            elif (requestParameters.containsKey("FIDOauthenticate:Recover")):
                    identity.setWorkingParameter("authenticatorType", "RecoveryCode")
                    identity.setWorkingParameter("nextStep", 1) # Start over
            elif (requestParameters.containsKey("tokenResponse")):
                    if (self.authenticateFIDO(requestParameters, userId, identity)):
                        return authenticationService.authenticate(userId)
            elif (requestParameters.containsKey("Recover")):
                if (requestParameters.containsKey("Recover:Cancel")):
                    if (authenticatorType != "RecoveryCode"):
                        identity.setWorkingParameter("authenticatorType", None)
                else:
                    if (self.authenticateRecoveryCode(requestParameters, userId, identity)):
                        # Recovery Trigger the registration flow
                        identity.setWorkingParameter("flow", "Register")
                    else:
                        return False
                identity.setWorkingParameter("nextStep", 1) # Start over
            else:
                print "MFA. authenticate: ERROR! unexpected form."
                identity.setWorkingParameter("flow", "Error") # Error page

        elif (flow == "Register"):
            # Step 1: Chooser page
            if (requestParameters.containsKey("MFAchooser")):
                if (step != 1): identity.setWorkingParameter("nextStep", 2)
                if (requestParameters.containsKey("MFAchooser:TOTP")):
                    authenticatorType = "TOTP"
                elif (requestParameters.containsKey("MFAchooser:FIDO")):
                    authenticatorType = "FIDO"
                else:
                    print("MFA: authenticate ERROR! Choice missing or invalid")
                    identity.setWorkingParameter("flow", "Error") # Error page
                identity.setWorkingParameter("authenticatorType", authenticatorType)
            elif (authenticatorType == "TOTP"):
                # Step 2: TOTP Info page
                if (requestParameters.containsKey("TOTPinfo")):
                    if (requestParameters.containsKey("TOTPinfo:Continue")): # Happy Path
                        if (step != 2): identity.setWorkingParameter("nextStep", 3)
                        return self.registerTOTP(requestParameters, userId, identity)
                    else: # We've gone off the happy path, restart registration
                        identity.setWorkingParameter("authenticatorType", None)
                        identity.setWorkingParameter("nextStep", 1)
                # Step 3: TOTP QR code page
                elif (requestParameters.containsKey("TOTPscanQR")):
                    if (requestParameters.containsKey("TOTPscanQR:Continue")): # Happy Path
                        if (step != 3): identity.setWorkingParameter("nextStep", 4)
                        return self.registerRecoveryCode(requestParameters, userId, identity)
                    elif (requestParameters.containsKey("TOTPscanQR:Back")): # Back Button
                        identity.setWorkingParameter("nextStep", 2)
                    else: # We've gone off the happy path, restart registration
                        identity.setWorkingParameter("authenticatorType", None)
                        identity.setWorkingParameter("nextStep", 1)
                # Step 4: Recovery Code Confirmation page
                elif (requestParameters.containsKey("RecoveryCodeConfirm")):
                    if (step != 4): identity.setWorkingParameter("nextStep", 5)
                # Step 5: Registration Successful
                elif (requestParameters.containsKey("Success")):
                    return authenticationService.authenticate(userId)
                else:
                    identity.setWorkingParameter("flow", "Error") # Error page
            elif (authenticatorType == "FIDO"):
                # Step 2: FIDO Registration page
                if (requestParameters.containsKey("FIDOregister")): # Step 2: FIDO registration
                    if (step != 2): identity.setWorkingParameter("nextStep", 3)
                    if (requestParameters.containsKey("FIDOregister:Back")): # Back Button
                        identity.setWorkingParameter("authenticatorType", None)
                        identity.setWorkingParameter("nextStep", 1)
                    elif(requestParameters.containsKey("tokenResponse")):
                        if (not self.registerRecoveryCode(requestParameters, userId, identity)):
                            return False
                        return self.registerFIDO(requestParameters, userId, identity)
                    else:
                        identity.setWorkingParameter("flow", "Error") # Error page
                # Step 3: Recovery Code Confirmation page
                elif (requestParameters.containsKey("RecoveryCodeConfirm")): # Step 3: Recovery Code Confirmation page
                    # # Registration is complete. There is no going back from here.
                    return True
                # Step 4: Registration Successful
                elif (requestParameters.containsKey("Success")):
                    return authenticationService.authenticate(userId)
                else:
                    identity.setWorkingParameter("flow", "Error") # Error page
            else:
                print "MFA. authenticate: ERROR! invalid authenticator type " + authenticatorType
                identity.setWorkingParameter("nextStep", -1)
                return True

        return True

    def getCountAuthenticationSteps(self, configurationAttributes):
        #if REMOTE_DEBUG:
        #    pydevd.settrace('localhost', port=5678, stdoutToServer=True, stderrToServer=True)

        print "MFA. getCountAuthenticationSteps called"
            
        # Inject dependencies
        identity = CdiUtil.bean(Identity)

        flow = identity.getWorkingParameter("flow")
        authenticatorType = identity.getWorkingParameter("authenticatorType")
        
        if (flow == "Authenticate"):
            return 1
        elif (authenticatorType == "FIDO"):
            return 4
        else: #TOTP
            return 5

    def getNextStep(self, configurationAttributes, requestParameters, step):
        
        print "MFA. getNextStep called for step '%s'" % step

        # Inject dependencies
        identity = CdiUtil.bean(Identity)

        nextStep = identity.getWorkingParameter("nextStep")
        if (nextStep is not None):
            identity.setWorkingParameter("nextStep", None)
            return nextStep
        else:
            return -1

    # Parses the login_hint
    def parseLoginHint(self):
        # Inject dependencies
        facesResources = CdiUtil.bean(FacesResources)
        
        facesContext = facesResources.getFacesContext()
        httpRequest = facesContext.getCurrentInstance().getExternalContext().getRequest()
        loginHint = httpRequest.getParameter("login_hint")
        if (loginHint == None):
            raise MFAError("ERROR: login_hint is not set, no user context for authentication")
    
        decryptedLoginHint = self.decryptAES(self.aesKey , Base64Util.base64urldecodeToString(loginHint))
        pairwiseId = decryptedLoginHint.split('|')[0]
        relyingParty = decryptedLoginHint.split('|')[1]
        
        return pairwiseId, relyingParty

    # Returns the user account for the provided pairwiseId, creating the account if necessary
    def getUser(self, pairwiseId):
        print "MFA. getUser() called"

        userService = CdiUtil.bean(UserService)
        clientService = CdiUtil.bean(ClientService)
        pairwiseIdentifierService = CdiUtil.bean(PairwiseIdentifierService)
        facesResources = CdiUtil.bean(FacesResources)

        # Get the user service and fetch the user
        # Normally we would fetch by pairwise ID ... however because there is no API for that we save MFA PAI in oxExternalUid
        externalUid = "sic-mfa:" + pairwiseId
        print "MFA: getUser(). Looking up user with externalUid = '%s'" % externalUid
        user = userService.getUserByAttribute("oxExternalUid", externalUid)

        if (user is None):
            # Create a new account
            print "MFA: getUser(). Creating new user with externalUid = '%s'" % (externalUid)
            newUser = User()
            userId = uuid.uuid4().hex
            newUser.setUserId(userId)
            newUser.setAttribute("oxExternalUid", externalUid)
            user = userService.addUser(newUser, True)

            # add a Pairwise Subject Identifier for the OIDC Client
            facesContext = facesResources.getFacesContext()
            httpRequest = facesContext.getCurrentInstance().getExternalContext().getRequest()
            clientId = httpRequest.getParameter("client_id")
            client = clientService.getClient(clientId)
            sectorIdentifierUri = client.getRedirectUris()[0]
            
            userInum = user.getAttribute("inum")

            pairwiseSubject = PairwiseIdentifier(sectorIdentifierUri, clientId)
            pairwiseSubject.setId(pairwiseId)
            pairwiseSubject.setDn(pairwiseIdentifierService.getDnForPairwiseIdentifier(pairwiseSubject.getId(), userInum))
            pairwiseIdentifierService.addPairwiseIdentifier(userInum, pairwiseSubject)

        return user

    # Get the type of authenticator (TOTP, U2F, or RecoveryCode) that can be used to
    # authenticate a user
    def getAuthenticatorType(self, user, configurationAttributes):
        print "MFA. getAuthenticatorType called"

        userService = CdiUtil.bean(UserService)

        # First, check the user for OTP registrations
        externalUids = userService.getCustomAttribute(user, "oxExternalUid")
        if (externalUids != None):
            # scan through the values to see if any match
            for externalUid in externalUids.getValues():
                index = externalUid.find("totp:")
                if index != -1:
                    print "MFA: getAuthenticatorType: Found a TOTP authenticator"
                    return "TOTP"

        # Second, check if user has registered U2F devices
        userInum = user.getAttribute("inum")

        deviceRegistrationService = CdiUtil.bean(DeviceRegistrationService)
        u2fRegistrations = deviceRegistrationService.findUserDeviceRegistrations(userInum, self.u2fApplicationId)
        if (u2fRegistrations.size() > 0):
            print "MFA: getAuthenticatorType: Found a U2F authenticator"
            return "FIDO"

        # Third, check if the user has a recovery code
        recoveryCode = userService.getCustomAttribute(user, "secretAnswer")
        if (recoveryCode is not None):
            print "MFA: getAuthenticatorType: Found a Recovery Code"
            return "RecoveryCode"

        # No authenticators were found
        print "MFA: getAuthenticatorType: No authenticators found"
        return None

    ####################################
    # TOTP authentication logic
    # TODO: Externalize this to an external library
    #####################################

    def loadOtpConfiguration(self, configurationAttributes):
        print "MFA. Load OTP configuration"

        if not configurationAttributes.containsKey("issuer"):
            print "MFA OTP. Initialization. Property issuer is mandatory"
            return False
        self.otpIssuer = configurationAttributes.get("issuer").getValue2()

        self.customLabel = None
        if configurationAttributes.containsKey("label"):
            self.customLabel = configurationAttributes.get("label").getValue2()

        self.customQrOptions = {}
        if configurationAttributes.containsKey("qr_options"):
            self.customQrOptions = configurationAttributes.get("qr_options").getValue2()

        self.registrationUri = None
        if configurationAttributes.containsKey("registration_uri"):
            self.registrationUri = configurationAttributes.get("registration_uri").getValue2()

        if not configurationAttributes.containsKey("otp_conf_file"):
            return False

        otp_conf_file = configurationAttributes.get("otp_conf_file").getValue2()

        # Load configuration from file
        f = open(otp_conf_file, 'r')
        try:
            otpConfiguration = json.loads(f.read())
        except:
            print "MFA OTP. Load OTP configuration. Failed to load configuration from file:", otp_conf_file
            return False
        finally:
            f.close()

        # Check configuration file settings
        try:
            self.totpConfiguration = otpConfiguration["totp"]

            hmacShaAlgorithm = self.totpConfiguration["hmacShaAlgorithm"]
            hmacShaAlgorithmType = None

            if StringHelper.equalsIgnoreCase(hmacShaAlgorithm, "sha1"):
                hmacShaAlgorithmType = HmacShaAlgorithm.HMAC_SHA_1
            elif StringHelper.equalsIgnoreCase(hmacShaAlgorithm, "sha256"):
                hmacShaAlgorithmType = HmacShaAlgorithm.HMAC_SHA_256
            elif StringHelper.equalsIgnoreCase(hmacShaAlgorithm, "sha512"):
                hmacShaAlgorithmType = HmacShaAlgorithm.HMAC_SHA_512
            else:
                print "MFA OTP. Load OTP configuration. Invalid TOTP HMAC SHA algorithm: '%s'" % hmacShaAlgorithm

            self.totpConfiguration["hmacShaAlgorithmType"] = hmacShaAlgorithmType
        except:
            print "MFA OTP. Load OTP configuration. Invalid configuration file '%s' format. Exception: '%s'" % (otp_conf_file, sys.exc_info()[1])
            return False

        return True
        
    def registerTOTP(self, requestParameters, username, identity):
        print "MFA. registerTOTP called"
        
        # Inject dependencies
        userService = CdiUtil.bean(UserService)

        user = userService.getUser(username, "oxExternalUid")
        if (user is None):
            print "MFA. Register TOTP. Failed to find user"
            return False

        # Generate a new secret
        secretKey = self.generateSecretTotpKey()

        # Generate enrollment request and add it to the session for the QR code page
        issuer = identity.getWorkingParameter("rpShortName")
        totpEnrollmentRequest = self.generateTotpSecretKeyUri(secretKey, issuer, username)
        identity.setWorkingParameter("totpEnrollmentRequest", totpEnrollmentRequest)
        if self.customLabel != None:
            identity.setWorkingParameter("qrLabel", self.customLabel)

        identity.setWorkingParameter("qrOptions", self.customQrOptions)

        # Delete any old enrollments
        externalUids = userService.getCustomAttribute(user, "oxExternalUid")
        if (externalUids is not None):
            for externalUid in externalUids.getValues():
                if (externalUid.startswith("totp:")):
                    print "MFA. Register TOTP. Removing an old TOTP enrolment"
                    updatedUser = userService.removeUserAttribute(username, "oxExternalUid", externalUid)
                    if (updatedUser is None):
                        print "MFA. Register TOTP. Failed to remove old enrollment"
                        identity.setWorkingParameter("nextStep", -1) # Trigger the error page
                        return False

        # Encrypt and add the new one
        encryptedSecretKey = self.encryptAES(self.aesKey, self.toBase64Url(secretKey))
        updatedUser = userService.addUserAttribute(username, "oxExternalUid", "totp:" + encryptedSecretKey)
        if (updatedUser is None):
            print "MFA. Register TOTP. Failed to updated user"
            identity.setWorkingParameter("nextStep", -1) # Trigger the error page
            return False
        
        self.deleteFIDO(username, identity)
        return True

    def authenticateTOTP(self, requestParameters, username, identity):
        print "MFA. authenticateTOTP called"

        # Inject dependencies
        facesMessages = CdiUtil.bean(FacesMessages)
        languageBean = CdiUtil.bean(LanguageBean)
        userService = CdiUtil.bean(UserService)
        authenticationProtectionService = CdiUtil.bean(AuthenticationProtectionService)

        facesMessages.setKeepMessages()

        if (authenticationProtectionService.isEnabled()):
            authenticationProtectionService.doDelayIfNeeded(username)

        totpCode = ServerUtil.getFirstValue(requestParameters, "TOTPauthenticate:totpCode")
        # Do some basic input validation
        if (totpCode is None or len(totpCode) != 6 or not totpCode.isdigit()):
            facesMessages.add(FacesMessage.SEVERITY_ERROR, languageBean.getMessage("mfa.otpInvalid"))
            return False

        # Find the user, retrieve and decrypt their TOTP code
        user = userService.getUser(username, "oxExternalUid")
        if (user is None):
            print "MFA. authenticateTOTP. Failed to find user"
            identity.setWorkingParameter("nextStep", -1) # Error page
            return True

        externalUids = userService.getCustomAttribute(user, "oxExternalUid")
        if (externalUids is not None):
            for externalUid in externalUids.getValues():
                if (externalUid.startswith("totp:")):
                    secretKey = self.decryptAES(self.aesKey, externalUid[5:])
                    break
        
        if (secretKey is None):
            print "MFA. authenticateTOTP. Failed to find TOTP secret"
            identity.setWorkingParameter("nextStep", -1) # Error page
            return True

        # Authenticate the TOTP code
        if (not self.validateTotpKey(self.fromBase64Url(secretKey), totpCode)):
            facesMessages.add(FacesMessage.SEVERITY_ERROR, languageBean.getMessage("mfa.otpInvalid"))
            if (authenticationProtectionService.isEnabled()):
                authenticationProtectionService.storeAttempt(username, False)
            return False

        if (authenticationProtectionService.isEnabled()):
            authenticationProtectionService.storeAttempt(username, True)
        return True

    def deleteTOTP(self, username, identity):
        # Inject dependencies
        userService = CdiUtil.bean(UserService)

        user = userService.getUser(username, "oxExternalUid")
        if (user is None):
            print "MFA. authenticateTOTP. Failed to find user"
            identity.setWorkingParameter("flow", "Error") # Error page
        else:
            externalUids = userService.getCustomAttribute(user, "oxExternalUid")
            if (externalUids is not None):
                for externalUid in externalUids.getValues():
                    if (externalUid.startswith("totp:")):
                        userService.removeUserAttribute(username, "oxExternalUid", externalUid)
                

    def generateSecretKey(self, keyLength):
        bytes = jarray.zeros(keyLength, "b")
        secureRandom = SecureRandom()
        secureRandom.nextBytes(bytes)

        return bytes

    def generateSecretTotpKey(self):
        keyLength = self.totpConfiguration["keyLength"]

        return self.generateSecretKey(keyLength)

    def generateTotpKey(self, secretKey):
        digits = self.totpConfiguration["digits"]
        timeStep = self.totpConfiguration["timeStep"]
        hmacShaAlgorithmType = self.totpConfiguration["hmacShaAlgorithmType"]

        totp = TOTP.key(secretKey).digits(digits).timeStep(TimeUnit.SECONDS.toMillis(timeStep)).hmacSha(hmacShaAlgorithmType).build()

        return totp.value()

    def validateTotpKey(self, secretKey, totpKey):
        localTotpKey = self.generateTotpKey(secretKey)
        return StringHelper.equals(localTotpKey, totpKey)
        
    def generateTotpSecretKeyUri(self, secretKey, issuer, userDisplayName):
        digits = self.totpConfiguration["digits"]
        timeStep = self.totpConfiguration["timeStep"]

        secretKeyBase32 = self.toBase32(secretKey)
        otpKey = OTPKey(secretKeyBase32, OTPType.TOTP)
        label = issuer + " %s" % userDisplayName

        otpAuthURI = OTPAuthURIBuilder.fromKey(otpKey).label(label).issuer(issuer).digits(digits).timeStep(TimeUnit.SECONDS.toMillis(timeStep)).build()

        return otpAuthURI.toUriString()


    ####################################
    # FIDO authentication logic
    # TODO: Externalize this to an external library
    #####################################
    def loadFIDOConfiguration(self, configurationAttributes):

        print "MFA. Downloading U2F metadata"

        if not configurationAttributes.containsKey("u2f_application_id"):
            print "MFA. Initialization. Property u2f_server_uri is mandatory"
            return False
        self.u2fApplicationId = configurationAttributes.get("u2f_server_uri").getValue2()

        if not configurationAttributes.containsKey("u2f_server_uri"):
            print "MFA. Initialization. Property u2f_server_uri is mandatory"
            return False
        u2f_server_uri = configurationAttributes.get("u2f_server_uri").getValue2()
        u2f_server_metadata_uri = u2f_server_uri + "/.well-known/fido-u2f-configuration"

        metaDataConfigurationService = FidoU2fClientFactory.instance().createMetaDataConfigurationService(u2f_server_metadata_uri)

        max_attempts = 20
        for attempt in range(1, max_attempts + 1):
            try:
                self.metaDataConfiguration = metaDataConfigurationService.getMetadataConfiguration()
                break
            except ClientResponseFailure, ex:
                # Detect if last try or we still get Service Unavailable HTTP error
                if (attempt == max_attempts) or (ex.getResponse().getResponseStatus() != HttpServletResponse.SC_SERVICE_UNAVAILABLE):
                    raise ex

                java.lang.Thread.sleep(3000)
                print "Attempting to load metadata: %d" % attempt
            except ResteasyClientException, ex:
                # Detect if last try or we still get Service Unavailable HTTP error
                if attempt == max_attempts:
                    raise ex

                java.lang.Thread.sleep(3000)
                print "Attempting to load metadata: %d" % attempt

        print "MFA. U2F Initialized successfully"
        return True

    def prepareFidoRegistration(self, username, identity):
        registrationRequestService = FidoU2fClientFactory.instance().createRegistrationRequestService(self.metaDataConfiguration)
        session = identity.getSessionId()

        identity.getSessionId().getSessionAttributes().put(Constants.AUTHENTICATED_USER, username)
        self.deleteFIDO(username, identity)
        registrationRequest = registrationRequestService.startRegistration(username, self.u2fApplicationId, session.getId())
        identity.setWorkingParameter("fido_u2f_registration_request", ServerUtil.asJson(registrationRequest))

    def registerFIDO(self, requestParameters, username, identity):
        print "MFA. registerFIDO called"

        registrationRequestService = FidoU2fClientFactory.instance().createRegistrationRequestService(self.metaDataConfiguration)

        token_response = ServerUtil.getFirstValue(requestParameters, "tokenResponse")
        registrationStatus = registrationRequestService.finishRegistration(username, token_response)

        if (registrationStatus.getStatus() != Constants.RESULT_SUCCESS):
            print "MFA. Register FIDO. Failed to register U2F device"
            identity.setWorkingParameter("flow", "Error") # Trigger the error page
            return False
        
        self.deleteTOTP(username, identity)
        return True

    def prepareFidoAuthentication(self, username, identity):
        authenticationRequestService = FidoU2fClientFactory.instance().createAuthenticationRequestService(self.metaDataConfiguration)
        session = identity.getSessionId()
        
        identity.getSessionId().getSessionAttributes().put(Constants.AUTHENTICATED_USER, username)
        authenticationRequest = authenticationRequestService.startAuthentication(username, None, self.u2fApplicationId, session.getId())
        identity.setWorkingParameter("fido_u2f_authentication_request", ServerUtil.asJson(authenticationRequest))

    def authenticateFIDO(self, requestParameters, username, identity):
        facesMessages = CdiUtil.bean(FacesMessages)
        languageBean = CdiUtil.bean(LanguageBean)
        authenticationProtectionService = CdiUtil.bean(AuthenticationProtectionService)

        facesMessages.setKeepMessages()

        if (authenticationProtectionService.isEnabled()):
            authenticationProtectionService.doDelayIfNeeded(username)

        token_response = ServerUtil.getFirstValue(requestParameters, "tokenResponse")
        authenticationRequestService = FidoU2fClientFactory.instance().createAuthenticationRequestService(self.metaDataConfiguration)
        authenticationStatus = authenticationRequestService.finishAuthentication(username, token_response)

        if (authenticationStatus.getStatus() != Constants.RESULT_SUCCESS):
            print "MFA. Authenticate FIDO. Failed to authenticate  U2F device"
            facesMessages.add(FacesMessage.SEVERITY_ERROR, languageBean.getMessage("mfa.FIDOInvalid"))
            if (authenticationProtectionService.isEnabled()):
                authenticationProtectionService.storeAttempt(username, False)
            return False
        
        if (authenticationProtectionService.isEnabled()):
            authenticationProtectionService.storeAttempt(username, True)
        return True

    def deleteFIDO(self, username, identity):
        # Inject dependencies
        deviceRegistrationService = CdiUtil.bean(DeviceRegistrationService)
        userService = CdiUtil.bean(UserService)

        userInum = userService.getUserInum(username)
        if (userInum is None):
            print "MFA. deleteFIDO: failed to retrieve userInum"
            identity.setWorkingParameter("flow", "Error")

        deviceRegistrationsList = deviceRegistrationService.findUserDeviceRegistrations(userInum, self.u2fApplicationId)
        for deviceRegistration in deviceRegistrationsList:
            deviceRegistrationService.removeUserDeviceRegistration(deviceRegistration)

    #####################################
    # Recovery Code authentication logic
    # TODO: Externalize this to an external library
    #####################################

    def registerRecoveryCode(self,requestParameters, username, identity):
        # Inject dependencies
        userService = CdiUtil.bean(UserService)

        alphanumeric = string.ascii_lowercase + string.digits
        code1 = ''.join(random.SystemRandom().choice(alphanumeric) for _ in range( 4 ))
        code2 = ''.join(random.SystemRandom().choice(alphanumeric) for _ in range( 4 ))
        code3 = ''.join(random.SystemRandom().choice(alphanumeric) for _ in range( 4 ))
        code  = "%s-%s-%s" % (code1, code2, code3)
        identity.setWorkingParameter("recoveryCode", code)

        encryptedCode = self.encryptAES(self.aesKey, code)
        user = userService.getUser(username, "uid", "secretAnswer")
        userService.setCustomAttribute(user, "secretAnswer", encryptedCode)
        user = userService.updateUser(user)

        return user is not None

    def authenticateRecoveryCode(self,requestParameters, username, identity):
        # Inject dependencies
        userService = CdiUtil.bean(UserService)
        authenticationProtectionService = CdiUtil.bean(AuthenticationProtectionService)
        facesMessages = CdiUtil.bean(FacesMessages)
        languageBean = CdiUtil.bean(LanguageBean)

        if (authenticationProtectionService.isEnabled()):
            authenticationProtectionService.doDelayIfNeeded(username)

        givenCode = ServerUtil.getFirstValue(requestParameters, "Recover:recoveryCode")

        user = userService.getUser(username, "secretAnswer")
        secretAnswers = userService.getCustomAttribute(user, "secretAnswer")

        if (secretAnswers is not None):
            for secretAnswer in secretAnswers.getValues():
                code = self.decryptAES(self.aesKey, secretAnswer)
                if (StringHelper.equals(code, givenCode)):
                    if (authenticationProtectionService.isEnabled()):
                        authenticationProtectionService.storeAttempt(username, True)
                    return True

        if (authenticationProtectionService.isEnabled()):
            authenticationProtectionService.storeAttempt(username, False)

        facesMessages.add( FacesMessage.SEVERITY_ERROR, languageBean.getMessage("mfa.invalidRecoveryCode"))
        return False

    # Utility methods
    def toBase32(self, bytes):
        return BaseEncoding.base32().omitPadding().encode(bytes)

    def toBase64Url(self, bytes):
        return BaseEncoding.base64Url().encode(bytes)

    def fromBase64Url(self, chars):
        return BaseEncoding.base64Url().decode(chars)

    def encryptAES(self, key, toEncrypt):
        # make sure key length is 16 bytes (128 bits)
        if ( len(key) != 16 ):
            return None
        # generate a random IV
        randomSource = string.ascii_letters + string.digits
        iv = ''.join(random.SystemRandom().choice(randomSource) for i in range(16))
        # configure IV and key specification
        skeySpec = SecretKeySpec(key, "AES")
        ivspec = IvParameterSpec(iv)
        # setup cipher
        cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", BouncyCastleProvider())
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec, ivspec)
        # encrypt the plaintext
        encryptedBytes = cipher.doFinal( toEncrypt.encode('utf-8') )
        encryptedValue = base64.b64encode( encryptedBytes )
        return iv.encode("ascii") + encryptedValue

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

class MFAError(Exception):
    pass

    