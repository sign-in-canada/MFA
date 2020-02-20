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
from org.gluu.oxauth.util import ServerUtil
from org.gluu.service.cdi.util import CdiUtil
from org.gluu.util import StringHelper


class PersonAuthentication(PersonAuthenticationType):
    def __init__(self, currentTimeMillis):
        self.currentTimeMillis = currentTimeMillis

    def init(self, configurationAttributes):
        print "OTP. Initialization"

        if not configurationAttributes.containsKey("otp_type"):
            print "OTP. Initialization. Property otp_type is mandatory"
            return False
        self.otpType = configurationAttributes.get("otp_type").getValue2()

        if not self.otpType in ["hotp", "totp"]:
            print "OTP. Initialization. Property value otp_type is invalid"
            return False

        if not configurationAttributes.containsKey("issuer"):
            print "OTP. Initialization. Property issuer is mandatory"
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

        print "OTP. Initialized successfully"
        return True

    def destroy(self, configurationAttributes):
        print "OTP. Destroy"
        print "OTP. Destroyed successfully"
        return True

    def getApiVersion(self):
        return 2

    def isValidAuthenticationMethod(self, usageType, configurationAttributes):
        print "OTP. isValidAuthenticationMethod called"
        # To do any operations we need the session variables available
        identity = CdiUtil.bean(Identity)
        registrationFlow = identity.getSessionId().getSessionAttributes().get("registrationFlow")
        if (registrationFlow == "NEW_RECOVERY_CODE" or registrationFlow == "ATTEMPT_RECOVERY"):
            return False
        return True

    def getAlternativeAuthenticationMethod(self, usageType, configurationAttributes):
        print "OTP. getAlternativeAuthenticationMethod called"
        # To do any operations we need the session variables available
        identity = CdiUtil.bean(Identity)
        registrationFlow = identity.getSessionId().getSessionAttributes().get("registrationFlow")
        if   ( registrationFlow == "NEW_RECOVERY_CODE" ):
            return "new_recovery_code"
        elif ( registrationFlow == "ATTEMPT_RECOVERY" ):
            return "recovery_code"

    def authenticate(self, configurationAttributes, requestParameters, step):
        print "OTP. authenticate called"
        authenticationService = CdiUtil.bean(AuthenticationService)

        identity = CdiUtil.bean(Identity)
        credentials = identity.getCredentials()

        self.setRequestScopedParameters(identity)

        session_id_validation = self.validateSessionId(identity)
        if not session_id_validation:
            print "OTP. Authenticate for step %s. Failed to validate session state" % step
            return False
            
        if step == 1:
            print "OTP. Authenticate for step 1"

            authenticationService = CdiUtil.bean(AuthenticationService)
            authenticated_user = authenticationService.getAuthenticatedUser()

            if authenticated_user == None:
                print "OTP. Authenticate for step 1. Failed to determine user from incoming mfa PAI"
                return False

            otp_auth_method = identity.getWorkingParameter("otp_auth_method")
            print "OTP. Authenticate for step 1. otp_auth_method: '%s'" % otp_auth_method

            # Do enrollment if the enrollment flow is active
            if otp_auth_method == 'enroll':
                auth_result = ServerUtil.getFirstValue(requestParameters, "auth_result")
                if not StringHelper.isEmpty(auth_result):
                    print "OTP. Authenticate for step 2. User not enrolled OTP"
                    return False

                print "OTP. Authenticate for step 1. Skipping this step during enrollment"
                return True
                
            # For authentication first check if recovery was chosen, set value to ATTEMPT_RECOVERY
            if ( self.isRecoveryRequested (requestParameters) ):
                identity.getSessionId().getSessionAttributes().put("registrationFlow", "ATTEMPT_RECOVERY")
                identity.setWorkingParameter("otp_count_login_steps", 2)
                CdiUtil.bean(SessionIdService).updateSessionId( identity.getSessionId() )
                return True

            otp_auth_result = self.processOtpAuthentication(requestParameters, authenticated_user.getUserId(), identity, otp_auth_method)
            print "OTP. Authenticate for step 1. OTP authentication result: '%s'" % otp_auth_result

            return otp_auth_result
        elif step == 2:
            print "OTP. Authenticate for step 2"

            authenticationService = CdiUtil.bean(AuthenticationService)
            authenticated_user = authenticationService.getAuthenticatedUser()
            if authenticated_user == None:
                print "OTP. Authenticate for step 2. Failed to determine user name"
                return False

            session_id_validation = self.validateSessionId(identity)
            if not session_id_validation:
                return False

            # Restore state from session
            otp_auth_method = identity.getWorkingParameter("otp_auth_method")
            if otp_auth_method != 'enroll':
                return False

            otp_auth_result = self.processOtpAuthentication(requestParameters, authenticated_user.getUserId(), identity, otp_auth_method)
            print "OTP. Authenticate for step 2. OTP authentication result: '%s'" % otp_auth_result

            # Set tne registration for to redirect to code generation
            identity.getSessionId().getSessionAttributes().put("registrationFlow", "NEW_RECOVERY_CODE")
            CdiUtil.bean(SessionIdService).updateSessionId( identity.getSessionId() )

            return otp_auth_result
        else:
            return False

    def prepareForStep(self, configurationAttributes, requestParameters, step):
        print "OTP. prepareForStep called"
        identity = CdiUtil.bean(Identity)
        credentials = identity.getCredentials()
        registrationFlow = identity.getSessionId().getSessionAttributes().get("registrationFlow")

        self.setRequestScopedParameters(identity)

        if step == 1:
        
            authenticationService = CdiUtil.bean(AuthenticationService)
            authenticated_user = authenticationService.getAuthenticatedUser()
            if ( authenticated_user == None ):
                print "OTP. Authenticate for step 1. There is no authenticated user"
                return False

            print "OTP. Prepare for step 1"
            otp_auth_method = "authenticate"

            user_enrollments = self.findEnrollments(authenticated_user.getUserId())
            if len(user_enrollments) == 0:
                otp_auth_method = "enroll"
                print "OTP. Prepare for step 1. There is no OTP enrollment for user '%s'. Changing otp_auth_method to '%s'" % (authenticated_user.getUserId(), otp_auth_method)

            if otp_auth_method == "enroll":
                enrollmentSteps = 2
                if (registrationFlow != None):
                    enrollmentSteps = 3
                print "OTP. Prepare for step 1. Setting count steps: '%s'" % enrollmentSteps
                identity.setWorkingParameter("otp_count_login_steps", enrollmentSteps)

            print "OTP. Prepare for step 1. otp_auth_method: '%s'" % otp_auth_method
            identity.setWorkingParameter("otp_auth_method", otp_auth_method)

            session_id_validation = self.validateSessionId(identity)
            if not session_id_validation:
                return False

            if otp_auth_method == 'enroll':
                authenticationService = CdiUtil.bean(AuthenticationService)
                user = authenticationService.getAuthenticatedUser()
                if user == None:
                    print "OTP. Prepare for step 1. Failed to load user entity"
                    return False

                if self.otpType == "hotp":
                    otp_secret_key = self.generateSecretHotpKey()
                    otp_enrollment_request = self.generateHotpSecretKeyUri(otp_secret_key, self.otpIssuer, user.getAttribute("displayName"))
                elif self.otpType == "totp":
                    otp_secret_key = self.generateSecretTotpKey()
                    otp_enrollment_request = self.generateTotpSecretKeyUri(otp_secret_key, self.otpIssuer, user.getAttribute("displayName"))
                else:
                    print "OTP. Prepare for step 1. Unknown OTP type: '%s'" % self.otpType
                    return False

                print "OTP. Prepare for step 1. Prepared enrollment request for user: '%s'" % user.getUserId()
                identity.setWorkingParameter("otp_secret_key", self.toBase64Url(otp_secret_key))
                identity.setWorkingParameter("otp_enrollment_request", otp_enrollment_request)

            return True
        elif step == 2:
            print "OTP. Prepare for step 2"

            session_id_validation = self.validateSessionId(identity)
            if not session_id_validation:
                return False

            otp_auth_method = identity.getWorkingParameter("otp_auth_method")
            print "OTP. Prepare for step 2. otp_auth_method: '%s'" % otp_auth_method

            if otp_auth_method == 'enroll':
                return True

        return False

    def getNextStep(self, configurationAttributes, requestParameters, step):
        print "OTP. getNextStep called for step '%s' (returns -1)" % step
        return -1

    def getExtraParametersForStep(self, configurationAttributes, step):
        print "OTP. getExtraParametersForStep called"
        return Arrays.asList("otp_auth_method", "otp_count_login_steps", "otp_secret_key", "otp_enrollment_request")

    def getCountAuthenticationSteps(self, configurationAttributes):
        print "OTP. getCountAuthenticationSteps called"
        identity = CdiUtil.bean(Identity)
        if identity.isSetWorkingParameter("otp_count_login_steps"):
            return StringHelper.toInteger("%s" % identity.getWorkingParameter("otp_count_login_steps"))
        else:
            return 1

    def getPageForStep(self, configurationAttributes, step):
        print "OTP. getPageForStep called"
    
        # To do any operations we need the session variables available
        print "OTP. Get page for step %s." % step

        if step == 1:
            # get the registration flow setting from the selector
            identity = CdiUtil.bean(Identity)
            registrationFlow = identity.getSessionId().getSessionAttributes().get("registrationFlow")
            
            # choose appropriate page
            if registrationFlow != None:
                return "/otpenroll.xhtml"
            else:
                return "/otplogin.xhtml"
        else:
            return "/otplogin.xhtml"

    def logout(self, configurationAttributes, requestParameters):
        return True

    def isRecoveryRequested(self, requestParameters):
        print "OTP. isRecoveryRequested called"
        try:
            toBeFeatched = "loginForm:recover"
            print "OTP. isRecoveryRequested: fetching '%s'" % toBeFeatched
            recovery_value = ServerUtil.getFirstValue(requestParameters, toBeFeatched)

            print "OTP. isRecoveryRequested: fetched recovery_value '%s'" % recovery_value
            if ( StringHelper.isNotEmpty(recovery_value) and recovery_value == "yes" ):
                return True
            return False
        except Exception, err:
            print("OTP. isRecoveryRequested Exception: " + str(err))
            return False

    def setRequestScopedParameters(self, identity):
        if self.registrationUri != None:
            identity.setWorkingParameter("external_registration_uri", self.registrationUri)

        if self.customLabel != None:
            identity.setWorkingParameter("qr_label", self.customLabel)

        identity.setWorkingParameter("qr_options", self.customQrOptions)

    def loadOtpConfiguration(self, configurationAttributes):
        print "OTP. Load OTP configuration"
        if not configurationAttributes.containsKey("otp_conf_file"):
            return False

        otp_conf_file = configurationAttributes.get("otp_conf_file").getValue2()

        # Load configuration from file
        f = open(otp_conf_file, 'r')
        try:
            otpConfiguration = json.loads(f.read())
        except:
            print "OTP. Load OTP configuration. Failed to load configuration from file:", otp_conf_file
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
                print "OTP. Load OTP configuration. Invalid TOTP HMAC SHA algorithm: '%s'" % hmacShaAlgorithm
                 
            self.totpConfiguration["hmacShaAlgorithmType"] = hmacShaAlgorithmType
        except:
            print "OTP. Load OTP configuration. Invalid configuration file '%s' format. Exception: '%s'" % (otp_conf_file, sys.exc_info()[1])
            return False

        return True

    def findEnrollments(self, user_name, skipPrefix = True):
        print "OTP. findEnrollments called"
        result = []

        userService = CdiUtil.bean(UserService)
        user = userService.getUser(user_name, "oxExternalUid")
        if user == None:
            print "OTP. Find enrollments. Failed to find user"
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
                else:
                    enrollment_uid = user_external_uid

                result.append(enrollment_uid)
        
        return result

    def validateSessionId(self, identity):
        print "OTP. validateSessionId called"
        session_id = CdiUtil.bean(SessionIdService).getSessionIdFromCookie()
        if StringHelper.isEmpty(session_id):
            print "OTP. Validate session id. Failed to determine session_id"
            return False

        otp_auth_method = identity.getWorkingParameter("otp_auth_method")
        if not otp_auth_method in ['enroll', 'authenticate']:
            print "OTP. Validate session id. Failed to authenticate user. otp_auth_method: '%s'" % otp_auth_method
            return False

        return True

    def processOtpAuthentication(self, requestParameters, user_name, identity, otp_auth_method):
        print "OTP. processOtpAuthentication called"
        facesMessages = CdiUtil.bean(FacesMessages)
        facesMessages.setKeepMessages()

        userService = CdiUtil.bean(UserService)

        otpCode = ServerUtil.getFirstValue(requestParameters, "loginForm:otpCode")
        if StringHelper.isEmpty(otpCode):
            facesMessages.add(FacesMessage.SEVERITY_ERROR, "Failed to authenticate. OTP code is empty")
            print "OTP. Process OTP authentication. otpCode is empty"

            return False
        
        if otp_auth_method == "enroll":
            # Get key from session
            otp_secret_key_encoded = identity.getWorkingParameter("otp_secret_key")
            if otp_secret_key_encoded == None:
                print "OTP. Process OTP authentication. OTP secret key is invalid"
                return False
            
            otp_secret_key = self.fromBase64Url(otp_secret_key_encoded)

            if self.otpType == "hotp":
                validation_result = self.validateHotpKey(otp_secret_key, 1, otpCode)
                
                if (validation_result != None) and validation_result["result"]:
                    print "OTP. Process HOTP authentication during enrollment. otpCode is valid"
                    # Store HOTP Secret Key and moving factor in user entry
                    otp_user_external_uid = "hotp:%s;%s" % ( otp_secret_key_encoded, validation_result["movingFactor"] )

                    # Add otp_user_external_uid to user's external GUID list
                    find_user_by_external_uid = userService.addUserAttribute(user_name, "oxExternalUid", otp_user_external_uid)
                    if find_user_by_external_uid != None:
                        return True

                    print "OTP. Process HOTP authentication during enrollment. Failed to update user entry"
            elif self.otpType == "totp":
                validation_result = self.validateTotpKey(otp_secret_key, otpCode)
                if (validation_result != None) and validation_result["result"]:
                    print "OTP. Process TOTP authentication during enrollment. otpCode is valid"
                    # Store TOTP Secret Key and moving factor in user entry
                    otp_user_external_uid = "totp:%s" % otp_secret_key_encoded

                    # Add otp_user_external_uid to user's external GUID list
                    find_user_by_external_uid = userService.addUserAttribute(user_name, "oxExternalUid", otp_user_external_uid)
                    if find_user_by_external_uid != None:
                        return True

                    print "OTP. Process TOTP authentication during enrollment. Failed to update user entry"
        elif otp_auth_method == "authenticate":
            user_enrollments = self.findEnrollments(user_name)

            if len(user_enrollments) == 0:
                print "OTP. Process OTP authentication. There is no OTP enrollment for user '%s'" % user_name
                facesMessages.add(FacesMessage.SEVERITY_ERROR, "There is no valid OTP user enrollments")
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
                        print "OTP. Process HOTP authentication during authentication. otpCode is valid"
                        otp_user_external_uid = "hotp:%s;%s" % ( otp_secret_key_encoded, moving_factor )
                        new_otp_user_external_uid = "hotp:%s;%s" % ( otp_secret_key_encoded, validation_result["movingFactor"] )
    
                        # Update moving factor in user entry
                        find_user_by_external_uid = userService.replaceUserAttribute(user_name, "oxExternalUid", otp_user_external_uid, new_otp_user_external_uid)
                        if find_user_by_external_uid != None:
                            return True
    
                        print "OTP. Process HOTP authentication during authentication. Failed to update user entry"
            elif self.otpType == "totp":
                for user_enrollment in user_enrollments:
                    otp_secret_key = self.fromBase64Url(user_enrollment)

                    # Validate TOTP
                    validation_result = self.validateTotpKey(otp_secret_key, otpCode)
                    if (validation_result != None) and validation_result["result"]:
                        print "OTP. Process TOTP authentication during authentication. otpCode is valid"
                        return True

        facesMessages.add(FacesMessage.SEVERITY_ERROR, "Failed to authenticate. OTP code is invalid")
        print "OTP. Process OTP authentication. OTP code is invalid"

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
