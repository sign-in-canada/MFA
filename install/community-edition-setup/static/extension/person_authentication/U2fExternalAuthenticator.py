# oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
# Copyright (c) 2016, Gluu
#
# Author: Yuriy Movchan
#

import java
import sys
from javax.ws.rs.core import Response
from java.util import Arrays
from org.jboss.resteasy.client import ClientResponseFailure
from org.jboss.resteasy.client.exception import ResteasyClientException
from org.gluu.model.custom.script.type.auth import PersonAuthenticationType
from org.gluu.oxauth.client.fido.u2f import FidoU2fClientFactory
from org.gluu.oxauth.model.config import Constants
from org.gluu.oxauth.security import Identity
from org.gluu.oxauth.service import UserService, AuthenticationService, SessionIdService
from org.gluu.oxauth.service.fido.u2f import DeviceRegistrationService
from org.gluu.oxauth.util import ServerUtil
from org.gluu.service.cdi.util import CdiUtil
from org.gluu.util import StringHelper


class PersonAuthentication(PersonAuthenticationType):
    def __init__(self, currentTimeMillis):
        self.currentTimeMillis = currentTimeMillis

    def init(self, configurationAttributes):
        print "U2F. Initialization"

        print "U2F. Initialization. Downloading U2F metadata"
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
                if (attempt == max_attempts) or (ex.getResponse().getResponseStatus() != Response.Status.SERVICE_UNAVAILABLE):
                    raise ex

                java.lang.Thread.sleep(3000)
                print "Attempting to load metadata: %d" % attempt
            except ResteasyClientException, ex:
                # Detect if last try or we still get Service Unavailable HTTP error
                if attempt == max_attempts:
                    raise ex

                java.lang.Thread.sleep(3000)
                print "Attempting to load metadata: %d" % attempt
        
        print "U2F. Initialized successfully"
        return True   

    def destroy(self, configurationAttributes):
        print "U2F. Destroy"
        print "U2F. Destroyed successfully"
        return True

    def getApiVersion(self):
        return 2

    def getNextStep(self, configurationAttributes, requestParameters, step):
        print "U2F. getNextStep called for step '%s' (returns -1)" % step
        return -1

    def isValidAuthenticationMethod(self, usageType, configurationAttributes):
        # To do any operations we need the session variables available
        identity = CdiUtil.bean(Identity)
        registrationFlow = identity.getSessionId().getSessionAttributes().get("registrationFlow")
        print "U2F. isValidAuthenticationMethod called, registrationFlow = %s" % registrationFlow
        if (registrationFlow == "NEW_RECOVERY_CODE" or registrationFlow == "ATTEMPT_RECOVERY"):
            return False
        return True

    def getAlternativeAuthenticationMethod(self, usageType, configurationAttributes):
        # To do any operations we need the session variables available
        identity = CdiUtil.bean(Identity)
        registrationFlow = identity.getSessionId().getSessionAttributes().get("registrationFlow")
        print "U2F. getAlternativeAuthenticationMethod called, registrationFlow = %s" % registrationFlow
        if   ( registrationFlow == "NEW_RECOVERY_CODE" ):
            return "new_recovery_code"
        elif ( registrationFlow == "ATTEMPT_RECOVERY" ):
            return "recovery_code"

    def authenticate(self, configurationAttributes, requestParameters, step):
        print "U2F. authenticate called for step %s" % step

        if (step == 1):
            # For authentication first check if recovery was chosen, set value to ATTEMPT_RECOVERY
            identity = CdiUtil.bean(Identity)
            if ( self.isRecoveryRequested (requestParameters) ):
                identity.getSessionId().getSessionAttributes().put("registrationFlow", "ATTEMPT_RECOVERY")
                identity.setWorkingParameter("otp_count_login_steps", 2)
				CdiUtil.bean(SessionIdService).updateSessionId( identity.getSessionId() )
                return True

            token_response = ServerUtil.getFirstValue(requestParameters, "tokenResponse")
            if token_response == None:
                print "U2F. Authenticate for step 1. tokenResponse is empty"
                return False

            auth_method = ServerUtil.getFirstValue(requestParameters, "authMethod")
            if auth_method == None:
                print "U2F. Authenticate for step 1. authMethod is empty"
                return False

            user = CdiUtil.bean(AuthenticationService).getAuthenticatedUser()
            if (user == None):
                print "U2F. Authenticate for step 1. Failed to determine user name"
                return False

            if (auth_method == 'authenticate'):
                print "U2F. Authenticate for step 1. Call FIDO U2F in order to finish authentication workflow"
                authenticationRequestService = FidoU2fClientFactory.instance().createAuthenticationRequestService(self.metaDataConfiguration)
                authenticationStatus = authenticationRequestService.finishAuthentication(user.getUserId(), token_response)

                if (authenticationStatus.getStatus() != Constants.RESULT_SUCCESS):
                    print "U2F. Authenticate for step 1. Get invalid authentication status from FIDO U2F server"
                    return False

                return True
            elif (auth_method == 'enroll'):
                print "U2F. Authenticate for step 1. Call FIDO U2F in order to finish registration workflow"
                registrationRequestService = FidoU2fClientFactory.instance().createRegistrationRequestService(self.metaDataConfiguration)
                registrationStatus = registrationRequestService.finishRegistration(user.getUserId(), token_response)

                if (registrationStatus.getStatus() != Constants.RESULT_SUCCESS):
                    print "U2F. Authenticate for step 1. Get invalid registration status from FIDO U2F server"
                    return False

                identity.getSessionId().getSessionAttributes().put("registrationFlow", "NEW_RECOVERY_CODE")
                identity.setWorkingParameter("otp_count_login_steps", 2)
				CdiUtil.bean(SessionIdService).updateSessionId( identity.getSessionId() )
                print "U2F. Authenticate for step 1. Call FIDO U2F in order to finish registration workflow"
                return True
            else:
                print "U2F. Authenticate for step 1. Authentication method is invalid"
                return False

            return False
        else:
            return False

    def prepareForStep(self, configurationAttributes, requestParameters, step):
        print "U2F. prepareForStep called for step %s" % step
        identity = CdiUtil.bean(Identity)

        if (step == 1):
            session_id = CdiUtil.bean(SessionIdService).getSessionIdFromCookie()
            if StringHelper.isEmpty(session_id):
                print "U2F. Prepare for step 1. Failed to determine session_id"
                return False

            authenticationService = CdiUtil.bean(AuthenticationService)
            user = authenticationService.getAuthenticatedUser()
            if (user == None):
                print "U2F. Prepare for step 1. Failed to determine user name"
                return False

            u2f_application_id = configurationAttributes.get("u2f_application_id").getValue2()

            # Check if user have registered devices
            deviceRegistrationService = CdiUtil.bean(DeviceRegistrationService)

            userInum = user.getAttribute("inum")

            registrationRequest = None
            authenticationRequest = None

            deviceRegistrations = deviceRegistrationService.findUserDeviceRegistrations(userInum, u2f_application_id)
            if (deviceRegistrations.size() > 0):
                print "U2F. Prepare for step 1. Call FIDO U2F in order to start authentication workflow"

                try:
                    authenticationRequestService = FidoU2fClientFactory.instance().createAuthenticationRequestService(self.metaDataConfiguration)
                    authenticationRequest = authenticationRequestService.startAuthentication(user.getUserId(), None, u2f_application_id, session_id)
                except ClientResponseFailure, ex:
                    if (ex.getResponse().getResponseStatus() != Response.Status.NOT_FOUND):
                        print "U2F. Prepare for step 1. Failed to start authentication workflow. Exception:", sys.exc_info()[1]
                        return False
            else:
                print "U2F. Prepare for step 1. Call FIDO U2F in order to start registration workflow"
                registrationRequestService = FidoU2fClientFactory.instance().createRegistrationRequestService(self.metaDataConfiguration)
                registrationRequest = registrationRequestService.startRegistration(user.getUserId(), u2f_application_id, session_id)

            identity.setWorkingParameter("fido_u2f_authentication_request", ServerUtil.asJson(authenticationRequest))
            identity.setWorkingParameter("fido_u2f_registration_request", ServerUtil.asJson(registrationRequest))

            return True
        elif (step == 2):
            print "U2F. Prepare for step 2"

            return True
        else:
            return False

    def getExtraParametersForStep(self, configurationAttributes, step):
        return Arrays.asList("otp_count_login_steps")

    def getCountAuthenticationSteps(self, configurationAttributes):
        # To do any operations we need the session variables available
        identity = CdiUtil.bean(Identity)
        if identity.isSetWorkingParameter("otp_count_login_steps"):
            return StringHelper.toInteger("%s" % identity.getWorkingParameter("otp_count_login_steps"))
        else:
            return 1

    def getPageForStep(self, configurationAttributes, step):
        return "/u2flogin.xhtml"

    def logout(self, configurationAttributes, requestParameters):
        return True

    def isRecoveryRequested(self, requestParameters):
        print "U2F. isRecoveryRequested called"
        try:
            toBeFeatched = "loginForm:recover"
            print "U2F. isRecoveryRequested: fetching '%s'" % toBeFeatched
            recovery_value = ServerUtil.getFirstValue(requestParameters, toBeFeatched)

            print "U2F. isRecoveryRequested: fetched recovery_value '%s'" % recovery_value
            if ( StringHelper.isNotEmpty(recovery_value) and recovery_value == "yes" ):
                return True
            return False
        except Exception, err:
            print("U2F. isRecoveryRequested Exception: " + str(err))
            return False
