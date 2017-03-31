/*
 * Copyright © 2017 ForgeRock, AS.
 *
 * This is unsupported code made available by ForgeRock for community development subject to the license detailed below.
 * The code is provided on an "as is" basis, without warranty of any kind, to the fullest extent permitted by law.
 *
 * ForgeRock does not warrant or guarantee the individual success developers may have in implementing the code on their
 * development platforms or in production configurations.
 *
 * ForgeRock does not warrant, guarantee or make any representations regarding the use, results of use, accuracy, timeliness
 * or completeness of any data or information relating to the alpha release of unsupported code. ForgeRock disclaims all
 * warranties, expressed or implied, and in particular, disclaims all warranties of merchantability, and warranties related
 * to the code, or any service or software related thereto.
 *
 * ForgeRock shall not be liable for any direct, indirect or consequential damages or costs of any type arising out of any
 * action taken by you or others related to the code.
 *
 * The contents of this file are subject to the terms of the Common Development and Distribution License (the License).
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the License at https://forgerock.org/cddlv1-0/. See the License for the specific language governing
 * permission and limitations under the License.
 *
 * Portions Copyrighted 2012-2015 ForgeRock AS.
 * Portions Copyrighted 2014 Nomura Research Institute, Ltd
 * Portions Copyrighted 2017 Charan Mann
 *
 * OpenAM-HOTP-Extended: Created by Charan Mann on 03/29/17 , 2:45 PM.
 */

package com.sun.identity.authentication.modules.hotp;

import com.iplanet.dpro.session.service.InternalSession;
import com.iplanet.sso.SSOException;
import com.iplanet.sso.SSOToken;
import com.iplanet.sso.SSOTokenManager;
import com.sun.identity.authentication.service.AMAuthErrorCode;
import com.sun.identity.authentication.spi.AuthErrorCodeException;
import com.sun.identity.authentication.spi.AuthLoginException;
import com.sun.identity.authentication.spi.InvalidPasswordException;
import com.sun.identity.authentication.util.ISAuthConstants;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.shared.datastruct.CollectionHelper;
import com.sun.identity.shared.debug.Debug;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.ConfirmationCallback;
import javax.security.auth.callback.PasswordCallback;
import java.util.Collections;
import java.util.Map;
import java.util.ResourceBundle;
import java.util.Set;

/**
 * Extension of {@link HOTP} authentication module
 */
public class HOTPExt extends HOTP {

    protected static final String amAuthHOTPExt = "amAuthHOTPExt";
    protected static final Debug debug = Debug.getInstance(amAuthHOTPExt);
    private static final String FROM_ADDRESS = "sunAMAuthHOTPSMTPFromAddress";
    // Module specific properties
    private static final String AUTHLEVEL = "sunAMAuthHOTPAuthLevel";
    private static final String GATEWAYSMSImplCLASS = "sunAMAuthHOTPSMSGatewayImplClassName";
    private static final String CODEVALIDITYDURATION = "sunAMAuthHOTPPasswordValidityDuration";
    private static final String CODELENGTH = "sunAMAuthHOTPPasswordLength";
    private static final String CODEDELIVERY = "sunAMAuthHOTPasswordDelivery";
    private static final String ATTRIBUTEPHONE = "openamTelephoneAttribute";
    private static final String ATTRIBUTECARRIER = "openamSMSCarrierAttribute";
    private static final String ATTRIBUTEEMAIL = "openamEmailAttribute";
    private static final String AUTO_CLICKING = "sunAMAuthHOTPAutoClicking";
    private static final String SKIP_HOTP = "skipHOTP";
    public Map currentConfig;
    ResourceBundle bundle = null;
    private String userName = null;
    private String userUUID = null;
    private int currentState;
    private Map sharedState;
    private String enteredHOTPCode = null;
    private String gatewaySMSImplClass = null;
    private String codeValidityDuration = null;
    private String codeLength = null;
    private String codeDelivery = null;
    private String telephoneAttribute = null;
    private String carrierAttribute = null;
    private String emailAttribute = null;
    private boolean skip = false;
    private boolean hotpAutoClicking = false;

    private int START_STATE = 2;

    private HOTPServiceExt hotpServiceExt;

    private Set<String> userSearchAttributes = Collections.emptySet();

    @Override
    public void init(Subject subject, Map sharedState, Map options) {
        currentConfig = options;
        String authLevel = CollectionHelper.getMapAttr(options, AUTHLEVEL);
        if (authLevel != null) {
            try {
                setAuthLevel(Integer.parseInt(authLevel));
            } catch (Exception e) {
                debug.error("HOTP.init() : " + "Unable to set auth level " + authLevel, e);
            }
        }

        gatewaySMSImplClass = CollectionHelper.getMapAttr(options,
                GATEWAYSMSImplCLASS);
        codeValidityDuration = CollectionHelper.getMapAttr(options,
                CODEVALIDITYDURATION);
        codeLength = CollectionHelper.getMapAttr(options, CODELENGTH);
        codeDelivery = CollectionHelper.getMapAttr(options, CODEDELIVERY);

        telephoneAttribute = CollectionHelper.getMapAttr(options, ATTRIBUTEPHONE);
        carrierAttribute = CollectionHelper.getMapAttr(options, ATTRIBUTECARRIER);
        emailAttribute = CollectionHelper.getMapAttr(options, ATTRIBUTEEMAIL);

        try {
            userSearchAttributes = getUserAliasList();
        } catch (final AuthLoginException ale) {
            debug.warning("HOTP.init: unable to retrieve search attributes", ale);
        }

        if (debug.messageEnabled()) {
            debug.message("HOTP.init() : " + "telephone attribute=" + telephoneAttribute
                    + " carrier attribute=" + carrierAttribute
                    + " email attribute=" + emailAttribute
                    + " user search attributes=" + userSearchAttributes);
        }

        java.util.Locale locale = getLoginLocale();
        bundle = amCache.getResBundle(amAuthHOTPExt, locale);
        if (debug.messageEnabled()) {
            debug.message("HOTP.init() : " + "HOTP resouce bundle locale=" + locale);
        }

        userName = (String) sharedState.get(getUserKey());
        if (userName == null || userName.isEmpty()) {
            try {
                //Session upgrade case. Need to find the user ID from the old session.
                SSOTokenManager mgr = SSOTokenManager.getInstance();
                InternalSession isess = getLoginState("HOTP").getOldSession();
                if (isess == null) {
                    throw new AuthLoginException("amAuth", "noInternalSession", null);
                }
                SSOToken token = mgr.createSSOToken(isess.getID().toString());
                userUUID = token.getPrincipal().getName();
                userName = token.getProperty("UserToken");
                if (debug.messageEnabled()) {
                    debug.message("HOTP.init() : UserName in SSOToken : " + userName);
                }
            } catch (SSOException ssoe) {
                debug.error("HOTP.init() : Unable to retrieve userName from existing session", ssoe);
            } catch (AuthLoginException ale) {
                debug.error("HOTP.init() : Unable to retrieve userName from existing session", ale);
            }
        }
        this.sharedState = sharedState;

        if (sharedState.containsKey(SKIP_HOTP)) {
            skip = (Boolean) sharedState.get(SKIP_HOTP);
        }

        hotpAutoClicking = CollectionHelper.getMapAttr(options, AUTO_CLICKING).equals("true");

        HOTPParams hotpParams = new HOTPParams(gatewaySMSImplClass, Long.parseLong(codeValidityDuration),
                telephoneAttribute, carrierAttribute, emailAttribute, codeDelivery, currentConfig,
                Integer.parseInt(codeLength), bundle.getString("messageSubject"), bundle.getString("messageContent"),
                FROM_ADDRESS, userSearchAttributes);
        hotpServiceExt = new HOTPServiceExt(getAMIdentityRepository(getRequestOrg()), userName, hotpParams);
    }

    @Override
    public int process(Callback[] callbacks, int state) throws AuthLoginException {
        if (skip) {
            debug.message("Skipping HOTP module");
            return ISAuthConstants.LOGIN_SUCCEED;
        }
        if (userName == null || userName.length() == 0) {
            throw new AuthLoginException("amAuth", "noUserName", null);
        }

        if (state == 1) {
            if (hotpAutoClicking) {
                debug.message("Auto sending OTP code");
                try {
                    AMIdentity amIdentity = hotpServiceExt.getAMIdentity();
                    hotpServiceExt.sendHOTP(amIdentity);
                    substituteHeader(START_STATE, bundle.getString("send.success") + hotpServiceExt.getContactDetails(amIdentity));
                } catch (AuthLoginException ale) {
                    throw new AuthErrorCodeException(AMAuthErrorCode.AUTH_ERROR, amAuthHOTPExt, "send.failure");
                }
            }
            return START_STATE;
        }

        currentState = state;
        int action = 0;
        try {
            if (currentState == START_STATE) {
                // callback[0] is OTP code
                // callback[1] is user selected button index
                // action = 0 is Submit HOTP Code Button
                // action = 1 is Request HOTP Code Button
                if (callbacks != null && callbacks.length == 2) {
                    action =
                            ((ConfirmationCallback)
                                    callbacks[1]).getSelectedIndex();
                    if (debug.messageEnabled()) {
                        debug.message("HOTP.process() : " + "LOGIN page button index: " + action);
                    }

                    if (action == 0) { //Submit HOTP Code
                        enteredHOTPCode = String.valueOf(((PasswordCallback) callbacks[0]).getPassword());
                        if (enteredHOTPCode == null || enteredHOTPCode.length() == 0) {
                            if (debug.messageEnabled()) {
                                debug.message("HOTP.process() : " + "invalid HOTP code");
                            }
                            setFailureID(userName);
                            throw new InvalidPasswordException("amAuth", "invalidPasswd", null);
                        }

                        // Enforce the code validate time HOTP module config
                        if (hotpServiceExt.isValidHOTP(enteredHOTPCode)) {
                            return ISAuthConstants.LOGIN_SUCCEED;
                        } else {
                            setFailureID(userName);
                            throw new InvalidPasswordException("amAuth", "invalidPasswd", null);
                        }
                    } else { // Send HOTP Code
                        try {
                            AMIdentity amIdentity = hotpServiceExt.getAMIdentity();
                            hotpServiceExt.sendHOTP(amIdentity);
                            substituteHeader(START_STATE, bundle.getString("send.success") + hotpServiceExt.getContactDetails(amIdentity));
                        } catch (AuthLoginException ale) {
                            throw new AuthErrorCodeException(AMAuthErrorCode.AUTH_ERROR, amAuthHOTPExt, "send.failure");
                        }
                        return START_STATE;
                    }
                } else {
                    setFailureID(userName);
                    throw new AuthLoginException(amAuthHOTPExt, "authFailed", null);
                }

            } else {
                setFailureID(userName);
                throw new AuthLoginException(amAuthHOTPExt, "authFailed", null);
            }
        } catch (NumberFormatException ex) {
            debug.error("HOTP.process() : NumberFormatException Exception", ex);
            if (userName != null && userName.length() != 0) {
                setFailureID(userName);
            }
            throw new AuthLoginException(amAuthHOTPExt, "authFailed", null, ex);
        }
    }

}
