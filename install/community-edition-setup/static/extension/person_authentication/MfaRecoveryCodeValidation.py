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
from org.gluu.oxauth.model.common import User
from org.oxauth.persistence.model import PairwiseIdentifier
 
from java.util import ArrayList
from java.util import Arrays

import sys
import java
import json
import uuid

class PersonAuthentication(PersonAuthenticationType):
    def __init__(self, currentTimeMillis):
        self.currentTimeMillis = currentTimeMillis

    def init(self, configurationAttributes):
        print "MFA Recovery. Initialized successfully"
        return True   

    def destroy(self, configurationAttributes):
        print "MFA Recovery. Destroyed successfully"
        return True

    def getApiVersion(self):
        return 2

    def isValidAuthenticationMethod(self, usageType, configurationAttributes):
        print "MFA Recovery. isValidAuthenticationMethod called"
        
        # check if the flow has completed successfully
        identity = CdiUtil.bean(Identity)
        if ( identity.getWorkingParameter("user_code_success") ):
            print "MFA Recovery. isValidAuthenticationMethod return False, recovery complete"
            return False
        return True

    def getAlternativeAuthenticationMethod(self, usageType, configurationAttributes):
        print "MFA Recovery. getAlternativeAuthenticationMethod: redirecting to 'mfa_select'"
        return "select_mfa"

    def authenticate(self, configurationAttributes, requestParameters, step):
        print "MFA Recovery. authenticate called for step '%s'" % step

        ########################################################################################
        # 1. Make sure we have a session
        identity = CdiUtil.bean(Identity)
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
        # 3. get the code from the user profile and validate the recovery code
        userCode = identity.getWorkingParameter("user_code")
        if (userCode != requestCode.upper()):
            print "MFA Recovery. authenticate. Recovery codes do not match"
            return False
        else:
            print "MFA Recovery. authenticate. Recovery code successfully verified."
            identity.setWorkingParameter("user_code", None)

        ########################################################################################        
        # 4. Remove the recovery code from the user profile and redirect
        #    to mfa selection module to erase MFA enrollments and start over
        userService = CdiUtil.bean(UserService)
        removed = userService.removeUserAttribute( authenticated_user.getUserId(), "secretAnswer", userCode)
        if not removed:
            print "MFA Recovery. authenticate. Failed removing code"
            return False

        print "MFA Recovery. authenticate. Recovery complete, code erased."
        identity.getSessionId().getSessionAttributes().put("registrationFlow", "EXISTING_USER")
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
            print "MFA Recovery. prepareForStep. Did not receive code from user, cannot recover"
            return False
        else:
            identity.setWorkingParameter("user_code", userCode)

        return True

    def getNextStep(self, configurationAttributes, requestParameters, step):
        print "MFA Recovery. getNextStep called for step '%s' (returns -1)" % step
        return -1

    def getExtraParametersForStep(self, configurationAttributes, step):
        print "MFA Recovery. getExtraParametersForStep called for step '%s'" % step
        return Arrays.asList("user_code", "user_code_success")

    def getCountAuthenticationSteps(self, configurationAttributes):
        print "MFA Recovery. getCountAuthenticationSteps called"
        return 2

    def getPageForStep(self, configurationAttributes, step):
        print "MFA Recovery. getPageForStep called for step '%s'" % step
        return "/recover.xhtml"

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
            toBeFetched = "input_loginForm:recoveryCode"
            print "MFA Recovery. getCodeFromRequest: fetching '%s'" % toBeFetched
            code = ServerUtil.getFirstValue(requestParameters, toBeFetched)

            print "MFA Recovery. getCodeFromRequest: fetched code '%s'" % code
            if StringHelper.isNotEmpty(code):
                return code
            return Null
        except Exception, err:
            print("MFA Recovery. getCodeFromRequest Exception: " + str(err))

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
