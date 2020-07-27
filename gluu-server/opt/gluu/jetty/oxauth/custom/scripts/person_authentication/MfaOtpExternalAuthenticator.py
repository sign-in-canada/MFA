# oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
# Copyright (c) 2016, Gluu
#
# Author: Yuriy Movchan
#

# Requires the following custom properties and values:
#   otp_type: totp/hotp
#   issuer: Gluu Inc
#   otp_conf_file: /etc/certs/otp_configuration.json
#
# These are non mandatory custom properties and values:
#   label: Gluu OTP
#   qr_options: { width: 400, height: 400 }
#   registration_uri: https://ce-dev.gluu.org/identity/register

import jarray
import json
import sys
from com.google.common.io import BaseEncoding
from com.lochbridge.oath.otp import HOTP
from com.lochbridge.oath.otp import HOTPValidator
from com.lochbridge.oath.otp import HmacShaAlgorithm
from com.lochbridge.oath.otp import TOTP
from com.lochbridge.oath.otp.keyprovisioning import OTPAuthURIBuilder
from com.lochbridge.oath.otp.keyprovisioning import OTPKey
from com.lochbridge.oath.otp.keyprovisioning.OTPKey import OTPType
from java.security import SecureRandom
from java.util import Arrays
from java.util.concurrent import TimeUnit
from javax.faces.application import FacesMessage
from org.gluu.jsf2.message import FacesMessages
from org.gluu.model.custom.script.type.auth import PersonAuthenticationType
from org.gluu.oxauth.security import Identity
from org.gluu.oxauth.service import UserService, AuthenticationService, SessionIdService
from org.gluu.oxauth.i18n import LanguageBean
from org.gluu.oxauth.util import ServerUtil
from org.gluu.service.cdi.util import CdiUtil
from org.gluu.util import StringHelper

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
        print "MFA OTP. Initialization"

        # Load encryption key file content
        key_file = configurationAttributes.get("encryption_key_file").getValue2()
        f = open( key_file, 'r' )
        try:
            key = f.read()
            self.aesKey = key[:16]
        except:
            print "MFA OTP. Initialization. Failed reading AES key file for encrypting/decrypting OTP seends: %s" % key_file
            return False
        finally:
            f.close()

        # Load customization content from file
        content_file = configurationAttributes.get("custom_page_content_file").getValue2()
        f = open(content_file, 'r')
        try:
            self.customPageContent = json.loads(f.read())
        except:
            print "MFA OTP. Initialization. Failed to load RP customization content from file: %s" % content_file
            return False
        finally:
            f.close()

        if not configurationAttributes.containsKey("otp_type"):
            print "MFA OTP. Initialization. Property otp_type is mandatory"
            return False
        self.otpType = configurationAttributes.get("otp_type").getValue2()

        if not self.otpType in ["hotp", "totp"]:
            print "MFA OTP. Initialization. Property value otp_type is invalid"
            return False

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

        validOtpConfiguration = self.loadOtpConfiguration(configurationAttributes)
        if not validOtpConfiguration:
            return False

        print "MFA OTP. Initialized successfully"
        return True

    def destroy(self, configurationAttributes):
        print "MFA OTP. Destroy"
        print "MFA OTP. Destroyed successfully"
        return True

    def getApiVersion(self):
        return 2

    def isValidAuthenticationMethod(self, usageType, configurationAttributes):
        # To do any operations we need the session variables available
        identity = CdiUtil.bean(Identity)
        authenticationFlow = identity.getSessionId().getSessionAttributes().get("authenticationFlow")
        print "MFA OTP. isValidAuthenticationMethod called, authenticationFlow = %s" % authenticationFlow
        if (authenticationFlow == "NEW_RECOVERY_CODE" or authenticationFlow == "ATTEMPT_RECOVERY" or authenticationFlow == "RESTART_ENROLLMENT"):
            return False
        return True

    def getAlternativeAuthenticationMethod(self, usageType, configurationAttributes):
        print "MFA OTP. getAlternativeAuthenticationMethod called"
        # To do any operations we need the session variables available
        identity = CdiUtil.bean(Identity)
        authenticationFlow = identity.getSessionId().getSessionAttributes().get("authenticationFlow")
        new_acr = None
        if   ( authenticationFlow == "NEW_RECOVERY_CODE" ):
            new_acr = "new_recovery_code"
        elif ( authenticationFlow == "RESTART_ENROLLMENT" ):
            new_acr = "select_mfa"
        elif ( authenticationFlow == "ATTEMPT_RECOVERY" ):
            new_acr = "recovery_code"

        print "MFA OTP. getAlternativeAuthenticationMethod returning ACR = %s" % new_acr
        return new_acr

    def authenticate(self, configurationAttributes, requestParameters, step):
        print "MFA OTP. authenticate called"
        authenticationService = CdiUtil.bean(AuthenticationService)

        identity = CdiUtil.bean(Identity)
        credentials = identity.getCredentials()

        self.setRequestScopedParameters(identity)

        session_id_validation = self.validateSessionId(identity)
        if not session_id_validation:
            print "MFA OTP. Authenticate for step %s. Failed to validate session state" % step
            return False

        # For authentication first check if recovery was chosen, set value to ATTEMPT_RECOVERY
        otp_auth_method = identity.getWorkingParameter("otp_auth_method")
        print "MFA OTP. Authenticate for step %s. otp_auth_method: '%s'" % (step, otp_auth_method)

        alternateAction = self.alternateActionRequested(requestParameters)
        authenticationFlow = identity.getSessionId().getSessionAttributes().get("authenticationFlow")
        if ( alternateAction == 'recover' and authenticationFlow == 'MFA_VALIDATION'):
            identity.getSessionId().getSessionAttributes().put("validationAcr", "mfa_otp")
            identity.getSessionId().getSessionAttributes().put("authenticationFlow", "ATTEMPT_RECOVERY")
            identity.setWorkingParameter("otp_count_login_steps", 3)
            CdiUtil.bean(SessionIdService).updateSessionId( identity.getSessionId() )
            return True
        # For authentication then check if someone enrolling clicked CANCEL button
        elif ( alternateAction == 'cancel' and authenticationFlow != 'MFA_VALIDATION'):
            identity.getSessionId().getSessionAttributes().put("authenticationFlow", "RESTART_ENROLLMENT")
            identity.setWorkingParameter("otp_count_login_steps", 3)
            CdiUtil.bean(SessionIdService).updateSessionId( identity.getSessionId() )
            return True
        # The info page has been accepted and continue to QR generation
        elif ( alternateAction == 'continue' and authenticationFlow != 'MFA_VALIDATION' and step == 1):
            identity.setWorkingParameter("otp_info_submitted", 'yes')
            CdiUtil.bean(SessionIdService).updateSessionId( identity.getSessionId() )
            return True
        else:
            identity.setWorkingParameter("otp_info_submitted", None)

        # Get the authenticated user
        authenticationService = CdiUtil.bean(AuthenticationService)
        authenticated_user = authenticationService.getAuthenticatedUser()

        if step == 1:
            print "MFA OTP. Authenticate for step 1"

            if authenticated_user == None:
                print "MFA OTP. Authenticate for step 1. Failed to determine user from incoming mfa PAI"
                return False

            # Do enrollment if the enrollment flow is active
            if otp_auth_method == 'enroll':
                auth_result = ServerUtil.getFirstValue(requestParameters, "auth_result")
                if not StringHelper.isEmpty(auth_result):
                    print "MFA OTP. Authenticate for step 2. User not enrolled OTP"
                    return False

                print "MFA OTP. Authenticate for step 1. Skipping this step during enrollment"
                return True

            otp_auth_result = self.processOtpAuthentication(requestParameters, authenticated_user.getUserId(), identity, otp_auth_method)
            print "MFA OTP. Authenticate for step 1. OTP authentication result: '%s'" % otp_auth_result

            return otp_auth_result
        elif step == 2:
            print "MFA OTP. Authenticate for step 2"

            if authenticated_user == None:
                print "MFA OTP. Authenticate for step 2. Failed to determine user name"
                return False

            session_id_validation = self.validateSessionId(identity)
            if not session_id_validation:
                return False

            # Restore state from session
            otp_auth_method = identity.getWorkingParameter("otp_auth_method")
            if otp_auth_method != 'enroll':
                return False

            otp_auth_result = self.processOtpAuthentication(requestParameters, authenticated_user.getUserId(), identity, otp_auth_method)
            print "MFA OTP. Authenticate for step 2. OTP authentication result: '%s'" % otp_auth_result

            # Set tne registration for to redirect to code generation
            identity.getSessionId().getSessionAttributes().put("authenticationFlow", "NEW_RECOVERY_CODE")
            CdiUtil.bean(SessionIdService).updateSessionId( identity.getSessionId() )

            return otp_auth_result
        else:
            return False

    def prepareForStep(self, configurationAttributes, requestParameters, step):
        print "MFA OTP. prepareForStep called"
        identity = CdiUtil.bean(Identity)
        credentials = identity.getCredentials()
        authenticationFlow = identity.getSessionId().getSessionAttributes().get("authenticationFlow")

        self.setRequestScopedParameters(identity)

        if step == 1:

            authenticationService = CdiUtil.bean(AuthenticationService)
            authenticated_user = authenticationService.getAuthenticatedUser()
            if ( authenticated_user == None ):
                print "MFA OTP. Authenticate for step 1. There is no authenticated user"
                return False

            print "MFA OTP. Prepare for step 1"
            otp_auth_method = "authenticate"

            user_enrollments = self.findEnrollments(authenticated_user.getUserId())
            if len(user_enrollments) == 0:
                otp_auth_method = "enroll"
                print "MFA OTP. Prepare for step 1. There is no OTP enrollment for user '%s'. Changing otp_auth_method to '%s'" % (authenticated_user.getUserId(), otp_auth_method)

            if otp_auth_method == "enroll":
                enrollmentSteps = 2
                if (authenticationFlow != None):
                    enrollmentSteps = 3
                print "MFA OTP. Prepare for step 1. Setting count steps: '%s'" % enrollmentSteps
                identity.setWorkingParameter("otp_count_login_steps", enrollmentSteps)

            print "MFA OTP. Prepare for step 1. otp_auth_method: '%s'" % otp_auth_method
            identity.setWorkingParameter("otp_auth_method", otp_auth_method)

            session_id_validation = self.validateSessionId(identity)
            if not session_id_validation:
                return False

            if otp_auth_method == 'enroll':
                authenticationService = CdiUtil.bean(AuthenticationService)
                user = authenticationService.getAuthenticatedUser()
                if user == None:
                    print "MFA OTP. Prepare for step 1. Failed to load user entity"
                    return False

                infoPageSubmitted = identity.getWorkingParameter("otp_info_submitted")
                if (infoPageSubmitted != 'yes'):
                    return True

                if self.otpType == "hotp":
                    otp_secret_key = self.generateSecretHotpKey()
                    otp_enrollment_request = self.generateHotpSecretKeyUri(otp_secret_key, self.otpIssuer, user.getAttribute("displayName"))
                elif self.otpType == "totp":
                    otp_secret_key = self.generateSecretTotpKey()
                    otp_enrollment_request = self.generateTotpSecretKeyUri(otp_secret_key, self.otpIssuer, user.getAttribute("displayName"))
                else:
                    print "MFA OTP. Prepare for step 1. Unknown OTP type: '%s'" % self.otpType
                    return False

                print "MFA OTP. Prepare for step 1. Prepared enrollment request for user: '%s'" % user.getUserId()
                identity.setWorkingParameter("otp_secret_key", self.toBase64Url(otp_secret_key))
                identity.setWorkingParameter("otp_enrollment_request", otp_enrollment_request)

            return True
        elif step == 2:
            print "MFA OTP. Prepare for step 2"

            session_id_validation = self.validateSessionId(identity)
            if not session_id_validation:
                return False

            otp_auth_method = identity.getWorkingParameter("otp_auth_method")
            print "MFA OTP. Prepare for step 2. otp_auth_method: '%s'" % otp_auth_method

            if otp_auth_method == 'enroll':
                return True

        return False

    def getNextStep(self, configurationAttributes, requestParameters, step):
        print "MFA OTP. getNextStep called for step '%s' (returns -1 or 1)" % step
        identity = CdiUtil.bean(Identity)
        authenticationFlow = identity.getSessionId().getSessionAttributes().get("authenticationFlow")
        infoPageSubmitted = identity.getWorkingParameter("otp_info_submitted")
        # during enrollment, step 1 is executed twice to display two different pages: (1) App Info and (2) QR Code
        if (infoPageSubmitted == 'yes' and step == 1):
            return 1

        return -1

    def getExtraParametersForStep(self, configurationAttributes, step):
        print "MFA OTP. getExtraParametersForStep called"
        return Arrays.asList("otp_auth_method", "otp_count_login_steps", "otp_secret_key", "otp_enrollment_request", "otp_info_submitted")

    def getCountAuthenticationSteps(self, configurationAttributes):
        print "MFA OTP. getCountAuthenticationSteps called"
        identity = CdiUtil.bean(Identity)
        if identity.isSetWorkingParameter("otp_count_login_steps"):
            return StringHelper.toInteger("%s" % identity.getWorkingParameter("otp_count_login_steps"))
        else:
            return 1

    def getPageForStep(self, configurationAttributes, step):
        # Get the locale/language from the browser
        locale = CdiUtil.bean(LanguageBean).getLocaleCode()[:2]
        print "MFA OTP. getPageForStep called for step '%s' and locale '%s'" % (step, locale)
        # Make sure it matches "en" or "fr"
        if (locale != "en" and locale != "fr"):
            locale = "en"

        # get the registration flow setting from the selector
        identity = CdiUtil.bean(Identity)
        authenticationFlow = identity.getSessionId().getSessionAttributes().get("authenticationFlow")
        # determine what page to display
        if authenticationFlow == 'MFA_VALIDATION':
            if locale == "en":
                return "/en/verify/app.xhtml"
            if locale == "fr":
                return "/fr/verifier/app.xhtml"

        # continue onto registration pages
        if step == 1:
            # check if we have gone past the info page
            infoPageSubmitted = identity.getWorkingParameter("otp_info_submitted")
            if infoPageSubmitted != 'yes':
                if locale == "en":
                    return "/en/register/appinfo.xhtml"
                if locale == "fr":
                    return "/fr/enregistrer/appinfo.xhtml"
            else:
                if locale == "en":
                    return "/en/register/appscan.xhtml"
                if locale == "fr":
                    return "/fr/enregistrer/appscan.xhtml"
        else:
            if locale == "en":
                return "/en/register/appcode.xhtml"
            if locale == "fr":
                return "/fr/enregistrer/appcode.xhtml"

    def logout(self, configurationAttributes, requestParameters):
        return True

    def alternateActionRequested(self, requestParameters):
        print "MFA OTP. alternateActionRequested called"
        try:
            toBeFetched = "loginForm:action"
            print "MFA OTP. alternateActionRequested: fetching '%s'" % toBeFetched
            action_value = ServerUtil.getFirstValue(requestParameters, toBeFetched)

            print "MFA OTP. alternateActionRequested: fetched action_value '%s'" % action_value
            if ( StringHelper.isNotEmpty(action_value) ):
                return action_value
            return None
        except Exception, err:
            print("OTP. alternateActionRequested Exception: " + str(err))
            return None

    def setRequestScopedParameters(self, identity):
        if self.registrationUri != None:
            identity.setWorkingParameter("external_registration_uri", self.registrationUri)

        if self.customLabel != None:
            identity.setWorkingParameter("qr_label", self.customLabel)

        identity.setWorkingParameter("qr_options", self.customQrOptions)

    def loadOtpConfiguration(self, configurationAttributes):
        print "MFA OTP. Load OTP configuration"
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
            self.hotpConfiguration = otpConfiguration["hotp"]
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

    def findEnrollments(self, user_name, skipPrefix = True):
        print "MFA OTP. findEnrollments called"
        result = []

        userService = CdiUtil.bean(UserService)
        user = userService.getUser(user_name, "oxExternalUid")
        if user == None:
            print "MFA OTP. Find enrollments. Failed to find user"
            return result

        user_custom_ext_attribute = userService.getCustomAttribute(user, "oxExternalUid")
        if user_custom_ext_attribute == None:
            return result

        otp_prefix = "%s:" % self.otpType

        otp_prefix_length = len(otp_prefix)
        for user_external_uid in user_custom_ext_attribute.getValues():
            index = user_external_uid.find(otp_prefix)
            if index != -1:
                if skipPrefix:
                    enrollment_uid = user_external_uid[otp_prefix_length:]
                    # Decrypt the OATH seed for TOTP
                    if self.otpType == "totp":
                        enrollment_uid = self.decryptAES( self.aesKey, enrollment_uid )
                else:
                    enrollment_uid = user_external_uid

                result.append(enrollment_uid)

        return result

    def validateSessionId(self, identity):
        print "MFA OTP. validateSessionId called"
        session_id = CdiUtil.bean(SessionIdService).getSessionIdFromCookie()
        if StringHelper.isEmpty(session_id):
            print "MFA OTP. Validate session id. Failed to determine session_id"
            return False

        otp_auth_method = identity.getWorkingParameter("otp_auth_method")
        if not otp_auth_method in ['enroll', 'authenticate']:
            print "MFA OTP. Validate session id. Failed to authenticate user. otp_auth_method: '%s'" % otp_auth_method
            return False

        return True

    def processOtpAuthentication(self, requestParameters, user_name, identity, otp_auth_method):
        print "MFA OTP. processOtpAuthentication called"
        facesMessages = CdiUtil.bean(FacesMessages)
        facesMessages.setKeepMessages()

        userService = CdiUtil.bean(UserService)
        languageBean = CdiUtil.bean(LanguageBean)

        otpCode = ServerUtil.getFirstValue(requestParameters, "loginForm:otpCode")
        if StringHelper.isEmpty(otpCode):
            facesMessages.add(FacesMessage.SEVERITY_ERROR, languageBean.getMessage("mfa.otpEmpty"))
            print "MFA OTP. Process OTP authentication. otpCode is empty"

            return False

        if otp_auth_method == "enroll":
            # Get key from session
            otp_secret_key_encoded = identity.getWorkingParameter("otp_secret_key")
            if otp_secret_key_encoded == None:
                print "MFA OTP. Process OTP authentication. OTP secret key is invalid"
                return False

            otp_secret_key = self.fromBase64Url(otp_secret_key_encoded)

            if self.otpType == "hotp":
                validation_result = self.validateHotpKey(otp_secret_key, 1, otpCode)

                if (validation_result != None) and validation_result["result"]:
                    print "MFA OTP. Process HOTP authentication during enrollment. otpCode is valid"
                    # Store HOTP Secret Key and moving factor in user entry
                    otp_user_external_uid = "hotp:%s;%s" % ( otp_secret_key_encoded, validation_result["movingFactor"] )

                    # Add otp_user_external_uid to user's external GUID list
                    find_user_by_external_uid = userService.addUserAttribute(user_name, "oxExternalUid", otp_user_external_uid)
                    if find_user_by_external_uid != None:
                        return True

                    print "MFA OTP. Process HOTP authentication during enrollment. Failed to update user entry"
            elif self.otpType == "totp":
                validation_result = self.validateTotpKey(otp_secret_key, otpCode)
                if (validation_result != None) and validation_result["result"]:
                    print "MFA OTP. Process TOTP authentication during enrollment. otpCode is valid"
                    # encrypt the TOTP
                    otp_secret_key_encrypted = self.encryptAES( self.aesKey, otp_secret_key_encoded )
                    # Store TOTP Secret Key and moving factor in user entry
                    otp_user_external_uid = "totp:%s" % otp_secret_key_encrypted

                    # Add otp_user_external_uid to user's external GUID list
                    find_user_by_external_uid = userService.addUserAttribute(user_name, "oxExternalUid", otp_user_external_uid)
                    if find_user_by_external_uid != None:
                        return True

                    print "MFA OTP. Process TOTP authentication during enrollment. Failed to update user entry"
        elif otp_auth_method == "authenticate":
            user_enrollments = self.findEnrollments(user_name)

            if len(user_enrollments) == 0:
                print "MFA OTP. Process OTP authentication. There is no OTP enrollment for user '%s'" % user_name
                facesMessages.add(FacesMessage.SEVERITY_ERROR, languageBean.getMessage("mfa.otpMissing"))
                return False

            if self.otpType == "hotp":
                for user_enrollment in user_enrollments:
                    user_enrollment_data = user_enrollment.split(";")
                    otp_secret_key_encoded = user_enrollment_data[0]

                    # Get current moving factor from user entry
                    moving_factor = StringHelper.toInteger(user_enrollment_data[1])
                    otp_secret_key = self.fromBase64Url(otp_secret_key_encoded)

                    # Validate TOTP
                    validation_result = self.validateHotpKey(otp_secret_key, moving_factor, otpCode)
                    if (validation_result != None) and validation_result["result"]:
                        print "MFA OTP. Process HOTP authentication during authentication. otpCode is valid"
                        otp_user_external_uid = "hotp:%s;%s" % ( otp_secret_key_encoded, moving_factor )
                        new_otp_user_external_uid = "hotp:%s;%s" % ( otp_secret_key_encoded, validation_result["movingFactor"] )

                        # Update moving factor in user entry
                        find_user_by_external_uid = userService.replaceUserAttribute(user_name, "oxExternalUid", otp_user_external_uid, new_otp_user_external_uid)
                        if find_user_by_external_uid != None:
                            return True

                        print "MFA OTP. Process HOTP authentication during authentication. Failed to update user entry"
            elif self.otpType == "totp":
                for user_enrollment in user_enrollments:
                    otp_secret_key = self.fromBase64Url(user_enrollment)

                    # Validate TOTP
                    validation_result = self.validateTotpKey(otp_secret_key, otpCode)
                    if (validation_result != None) and validation_result["result"]:
                        print "MFA OTP. Process TOTP authentication during authentication. otpCode is valid"
                        return True

        facesMessages.add(FacesMessage.SEVERITY_ERROR, languageBean.getMessage("mfa.otpInvalid"))
        print "MFA OTP. Process OTP authentication. OTP code is invalid"

        return False

    # Shared HOTP/TOTP methods
    def generateSecretKey(self, keyLength):
        bytes = jarray.zeros(keyLength, "b")
        secureRandom = SecureRandom()
        secureRandom.nextBytes(bytes)

        return bytes

    # HOTP methods
    def generateSecretHotpKey(self):
        keyLength = self.hotpConfiguration["keyLength"]

        return self.generateSecretKey(keyLength)

    def generateHotpKey(self, secretKey, movingFactor):
        digits = self.hotpConfiguration["digits"]

        hotp = HOTP.key(secretKey).digits(digits).movingFactor(movingFactor).build()

        return hotp.value()

    def validateHotpKey(self, secretKey, movingFactor, totpKey):
        lookAheadWindow = self.hotpConfiguration["lookAheadWindow"]
        digits = self.hotpConfiguration["digits"]

        htopValidationResult = HOTPValidator.lookAheadWindow(lookAheadWindow).validate(secretKey, movingFactor, digits, totpKey)
        if htopValidationResult.isValid():
            return { "result": True, "movingFactor": htopValidationResult.getNewMovingFactor() }

        return { "result": False, "movingFactor": None }

    def generateHotpSecretKeyUri(self, secretKey, issuer, userDisplayName):
        digits = self.hotpConfiguration["digits"]

        secretKeyBase32 = self.toBase32(secretKey)
        otpKey = OTPKey(secretKeyBase32, OTPType.HOTP)
        label = issuer + " %s" % userDisplayName

        otpAuthURI = OTPAuthURIBuilder.fromKey(otpKey).label(label).issuer(issuer).digits(digits).build()

        return otpAuthURI.toUriString()

    # TOTP methods
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
        if StringHelper.equals(localTotpKey, totpKey):
            return { "result": True }

        return { "result": False }

    def generateTotpSecretKeyUri(self, secretKey, issuer, userDisplayName):
        digits = self.totpConfiguration["digits"]
        timeStep = self.totpConfiguration["timeStep"]

        secretKeyBase32 = self.toBase32(secretKey)
        otpKey = OTPKey(secretKeyBase32, OTPType.TOTP)
        label = issuer + " %s" % userDisplayName

        otpAuthURI = OTPAuthURIBuilder.fromKey(otpKey).label(label).issuer(issuer).digits(digits).timeStep(TimeUnit.SECONDS.toMillis(timeStep)).build()

        return otpAuthURI.toUriString()

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
