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
import string
import random

class PersonAuthentication(PersonAuthenticationType):
    def __init__(self, currentTimeMillis):
        self.currentTimeMillis = currentTimeMillis

    def init(self, configurationAttributes):
        print "MFA Enroll Recovery. Initialized successfully"
        return True   

    def destroy(self, configurationAttributes):
        print "MFA Enroll Recovery. Destroyed successfully"
        return True

    def getApiVersion(self):
        return 2

    def isValidAuthenticationMethod(self, usageType, configurationAttributes):
        print "MFA Enroll Recovery. isValidAuthenticationMethod called"
        
        return True
        

    def getAlternativeAuthenticationMethod(self, usageType, configurationAttributes):
        print "MFA Enroll Recovery. getAlternativeAuthenticationMethod called"

        return None

    def authenticate(self, configurationAttributes, requestParameters, step):
        print "MFA Enroll Recovery. authenticate called for step '%s'" % step

        identity = CdiUtil.bean(Identity)
        
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
        try:
            toBeFeatched = "loginForm:confirmCodeBox"
            print "MFA Enroll Recovery. authenticate: fetching '%s'" % toBeFeatched
            confirmCodeBox = ServerUtil.getFirstValue(requestParameters, toBeFeatched)

            print "MFA Enroll Recovery. authenticate: fetched confirmCodeBox = '%s'" % confirmCodeBox
            if confirmCodeBox != "on":
                return False
        except Exception, err:
            print("MFA Enroll Recovery. authenticate Exception getting form checkbox: " + str(err))

        ########################################################################################
        # 3. Save the recovery code in the user's profile
        #    - use "secretAnswer" for storage
        new_code = identity.getWorkingParameter("new_code")
        userService = CdiUtil.bean(UserService)
        savedCode = userService.addUserAttribute( authenticated_user.getUserId() , "secretAnswer", new_code)
        if ( savedCode ):
            print "MFA Enroll Recovery. authenticate. New code %s saved for user '%s' result = '%s'" % (new_code, authenticated_user.getUserId(), savedCode)
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

        identity = CdiUtil.bean(Identity)

        if (identity.getWorkingParameter("new_code") != None):
            print "MFA Enroll Recovery. prepareForStep. A code has already been generated and not confirmed"
            return False

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
        # 2. Make sure we have no existing codes in the user profile
        existingCode = self.findExistingCode(authenticated_user)
        if existingCode != None:
            print "MFA Enroll Recovery. prepareForStep. User already has a recovery code"
            return False

        ########################################################################################
        # 3. Generate a recovery code with 128 bit strength
        #    - use Alphanumeric (A-Z,0-9)
        #    - use size of 25 (to achieve 128 bits of entropy)
        #    - save it in "new_code"
        alphanumeric = string.ascii_uppercase + string.digits
        code = ''.join(random.SystemRandom().choice(alphanumeric) for _ in range( 25 ))
        identity.setWorkingParameter("new_code", code)

        print "MFA Enroll Recovery. prepareForStep. got session '%s'"  % identity.getSessionId().toString()

        return True

    def getApiVersion(self):
        return 2

    def getNextStep(self, configurationAttributes, requestParameters, step):
        print "MFA Enroll Recovery. getNextStep called for step '%s' (returns step+1)" % step
        return (step + 1)

    def getExtraParametersForStep(self, configurationAttributes, step):
        print "MFA Enroll Recovery. getExtraParametersForStep called for step '%s'" % step
        return Arrays.asList("new_code")

    def getCountAuthenticationSteps(self, configurationAttributes):
        print "MFA Enroll Recovery. getCountAuthenticationSteps called"
        return 1

    def getPageForStep(self, configurationAttributes, step):
        print "MFA Enroll Recovery. getPageForStep called for step '%s'" % step
        return "/newrecovery.xhtml"

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