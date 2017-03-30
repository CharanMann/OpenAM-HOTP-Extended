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

package com.sun.identity.authentication.modules.hotp.ext;

import com.iplanet.sso.SSOException;
import com.sun.identity.authentication.spi.AuthLoginException;
import com.sun.identity.idm.*;
import com.sun.identity.shared.datastruct.CollectionHelper;
import com.sun.identity.shared.debug.Debug;
import org.forgerock.openam.utils.CollectionUtils;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.*;

/**
 * Provides the functionality to send OTP codes to a users Telephone and email.
 */
public class HOTPService {

    private static final Debug DEBUG = Debug.getInstance(HOTPExt.amAuthHOTPExt);

    // TODO : the moving factor should be retrieved from user's profile
    private static int movingFactor = 0;

    private final AMIdentityRepository amIdentityRepo;
    private final String gatewaySMSImplClass;
    private final long codeValidityDuration;
    private final String carrierAttribute;
    private final String codeDelivery;
    private final Map<?, ?> currentConfig;
    private final String userName;
    private final int codeLength;
    private final String messageSubject;
    private final String messageContent;
    private final String fromAddressAttributeName;
    private final Set<String> userSearchAttributes;
    private String telephoneAttribute;
    private String emailAttribute;
    private SecureRandom secureRandom;
    private String sentHOTPCode;
    private long sentHOTPCodeTime;

    /**
     * Constructs an instance of the HOTPService.
     *
     * @param amIdentityRepo An instance of the AMIdentityRepository.
     * @param userName       The user's name.
     * @param hotpParams     The authentication modules configuration settings.
     */
    public HOTPService(AMIdentityRepository amIdentityRepo, String userName, HOTPParams hotpParams) {
        this.amIdentityRepo = amIdentityRepo;
        this.userName = userName;
        this.gatewaySMSImplClass = hotpParams.getGatewaySMSImplClass();
        this.codeValidityDuration = hotpParams.getCodeValidityDuration();
        this.codeLength = hotpParams.getCodeLength();
        this.codeDelivery = hotpParams.getCodeDelivery();
        this.telephoneAttribute = hotpParams.getTelephoneLdapAttributeName();
        this.carrierAttribute = hotpParams.getCarrierLdapAttributeName();
        this.emailAttribute = hotpParams.getEmailLdapAttributeName();
        this.currentConfig = hotpParams.getConfig();
        this.messageSubject = hotpParams.getMessageSubject();
        this.messageContent = hotpParams.getMessageContent();
        this.fromAddressAttributeName = hotpParams.getFromAddressAttributeName();
        this.userSearchAttributes = hotpParams.getUserSearchAttributes();
        try {
            secureRandom = SecureRandom.getInstance("SHA1PRNG");
        } catch (NoSuchAlgorithmException ex) {
            DEBUG.error("HOTP.HOTP() : HOTP : Initialization Failed", ex);
            secureRandom = null;
        }
    }

    /**
     * Sends a otp code to the users telephone number and/or email address, based on the authentication module's
     * configuration settings.
     *
     * @throws AuthLoginException If there is a problem sending the OTP code.
     */
    public void sendHOTP(AMIdentity amIdentity) throws AuthLoginException {
        try {
            sentHOTPCode = HOTPAlgorithm.generateOTP(getSharedSecret(), getMovingFactor(), codeLength, false, 16);
        } catch (NoSuchAlgorithmException e) {
            DEBUG.error("HOTP.sendHOTPCode() : " + "no such algorithm", e);
            throw new AuthLoginException("amAuth", "noSuchAlgorithm", null);
        } catch (InvalidKeyException e) {
            DEBUG.error("HOTP.sendHOTPCode() : " + "invalid key", e);
            throw new AuthLoginException("amAuth", "invalidKey", null);
        }
        sendHOTP(amIdentity, sentHOTPCode, messageSubject, messageContent);
        sentHOTPCodeTime = System.currentTimeMillis();
    }

    private byte[] getSharedSecret() {
        return Long.toHexString(secureRandom.nextLong()).getBytes();
    }

    private int getMovingFactor() {
        return movingFactor++;
    }

    /**
     * Determines if the given OTP code matches the OTP code that was sent previously.
     *
     * @param enteredHOTPCode The OTP code to verify.
     * @return Whether the OTP code matches the OTP code that was sent to the user.
     */
    public boolean isValidHOTP(String enteredHOTPCode) {

        if (sentHOTPCode != null && sentHOTPCode.equals(enteredHOTPCode)) {
            long timePassed = System.currentTimeMillis() - sentHOTPCodeTime;
            if (timePassed <= (codeValidityDuration * 60000)) {
                // one time use only
                sentHOTPCode = null;
                return true;
            } else {
                if (DEBUG.messageEnabled()) {
                    DEBUG.message("HOTP.process() : HOTP code has expired");
                }
                return false;
            }
        } else {
            if (DEBUG.messageEnabled()) {
                DEBUG.message("HOTP.process() : HOTP code is not valid");
            }
            return false;
        }
    }

    /**
     * Sends the otp code to the users telephone number and/or email address, based on the authentication module's
     * configuration settings.
     *
     * @param otpCode The OTP code to send.
     * @param subject The subject of the message.
     * @param message The body of the message.
     * @throws AuthLoginException If there is a problem sending the OTP code.
     */
    private void sendHOTP(AMIdentity amIdentity, String otpCode, String subject, String message) throws AuthLoginException {

        Exception cause = null;
        try {
            String phone = getTelephoneNumber(amIdentity);
            String mail = getEmailAddress(amIdentity);

            boolean delivered = false;
            if (phone != null || mail != null) {
                String from = CollectionHelper.getMapAttr(currentConfig, fromAddressAttributeName);
                SMSGateway gateway = Class.forName(gatewaySMSImplClass).asSubclass(SMSGateway.class).newInstance();
                if (codeDelivery.equals("SMS and E-mail")) {
                    try {
                        if (phone != null) {
                            gateway.sendSMSMessage(from, phone, subject, message, otpCode, currentConfig);
                            delivered = true;
                        }
                    } catch (AuthLoginException ale) {
                        DEBUG.error("Error while sending HOTP code to user via SMS", ale);
                        cause = ale;
                    }
                    try {
                        if (mail != null) {
                            gateway.sendEmail(from, mail, subject, message, otpCode, currentConfig);
                            delivered = true;
                        }
                    } catch (AuthLoginException ale) {
                        DEBUG.error("Error while sending HOTP code to user via e-mail", ale);
                        cause = ale;
                    }
                    if (!delivered && cause != null) {
                        throw cause;
                    }
                } else if (codeDelivery.equals("SMS")) {
                    gateway.sendSMSMessage(from, phone, subject, message, otpCode, currentConfig);
                } else if (codeDelivery.equals("E-mail")) {
                    gateway.sendEmail(from, mail, subject, message, otpCode, currentConfig);
                }
            } else {
                if (DEBUG.messageEnabled()) {
                    DEBUG.message("HOTP.sendSMS() : IdRepo: no phone or email found with username : " + userName);
                }
                throw new AuthLoginException("No phone or e-mail found for user: " + userName);
            }
        } catch (ClassNotFoundException ee) {
            DEBUG.error("HOTP.sendSMS() : " + "class not found SMSGateway class", ee);
            cause = ee;
        } catch (InstantiationException ie) {
            DEBUG.error("HOTP.sendSMS() : " + "can not instantiate SMSGateway class", ie);
            cause = ie;
        } catch (IdRepoException e) {
            DEBUG.error("HOTP.sendSMS() : error searching Identities with username : " + userName, e);
            cause = e;
        } catch (Exception e) {
            DEBUG.error("HOTP.sendSMS() : HOTP module exception : ", e);
            cause = e;
        }
        if (cause != null) {
            throw new AuthLoginException("HOTP.sendSMS() : Unable to send OTP code", cause);
        }
    }

    /**
     * Get correspoding {@link AMIdentity}
     *
     * @return AMIdentity
     * @throws AuthLoginException
     */
    AMIdentity getAMIdentity() throws AuthLoginException {
        IdSearchControl idsc = new IdSearchControl();
        idsc.setRecursive(true);
        idsc.setTimeOut(0);
        final Set<String> returnAttributes = getReturnAttributes();
        idsc.setReturnAttributes(returnAttributes);
        // search for the identity
        Set<AMIdentity> results = Collections.emptySet();
        Exception cause = null;
        try {
            idsc.setMaxResults(0);

            IdSearchResults searchResults = amIdentityRepo.searchIdentities(IdType.USER, userName, idsc);
            if (searchResults.getSearchResults().isEmpty() && !userSearchAttributes.isEmpty()) {
                if (DEBUG.messageEnabled()) {
                    DEBUG.message("HOTP.sendHOTP() searching user identity "
                            + "with alternative attributes " + userSearchAttributes);
                }
                final Map<String, Set<String>> searchAVP = CollectionUtils.toAvPairMap(userSearchAttributes, userName);
                idsc.setSearchModifiers(IdSearchOpModifier.OR, searchAVP);
                //workaround as data store always adds 'user-naming-attribute' to searchfilter
                searchResults = amIdentityRepo.searchIdentities(IdType.USER, "*", idsc);
            }

            if (searchResults != null) {
                results = searchResults.getSearchResults();
            }

            if (results.isEmpty()) {
                throw new IdRepoException("HTOP:sendSMS : User " + userName
                        + " is not found");
            } else if (results.size() > 1) {
                throw new IdRepoException(
                        "HTOP:sendSMS : More than one user found for the userName "
                                + userName);
            }

            Object[] identities = results.toArray();
            AMIdentity identity = (AMIdentity) identities[0];
            return identity;
        } catch (IdRepoException | SSOException e) {
            DEBUG.error("HOTP.sendSMS() : error searching Identities with username : " + userName, e);
            cause = e;
        }
        if (cause != null) {
            throw new AuthLoginException("HOTP.sendSMS() : Unable to send OTP code", cause);
        }
        return null;
    }

    /**
     * Get user contact details to be set as Header
     * @param amIdentity
     * @return
     */
    String getContactDetails(AMIdentity amIdentity) throws AuthLoginException {
        String email;
        String phone;
        try {
            email = getEmailAddress(amIdentity);
            phone = getTelephoneNumber(amIdentity);
        } catch (IdRepoException | SSOException e) {
            throw new AuthLoginException("HOTP.getContactDetails() : Unable to get user contact details", e);
        }

        String contactDetails;
        if (codeDelivery.equals("SMS and E-mail")) {
            contactDetails = " Email " + email + " and Phone: " + phone;
        } else if (codeDelivery.equals("SMS")) {
            contactDetails = " Phone: " + phone;
        } else if (codeDelivery.equals("E-mail")) {
            contactDetails = " Email: " + email;
        } else{
            contactDetails = "No user info found";
        }

        return contactDetails;
    }

    /**
     * Gets the Telephone number of the user.
     *
     * @param identity The user's identity.
     * @return The user's telephone number.
     * @throws IdRepoException If there is a problem getting the user's telephone number.
     * @throws SSOException    If there is a problem getting the user's telephone number.
     */
    private String getTelephoneNumber(AMIdentity identity) throws IdRepoException, SSOException {

        if (telephoneAttribute == null || telephoneAttribute.trim().length() == 0) {
            telephoneAttribute = "telephoneNumber";
        }
        if (DEBUG.messageEnabled()) {
            DEBUG.message("HOTP.sendSMS() : Using phone attribute of " + telephoneAttribute);
        }
        Set telephoneNumbers = identity.getAttribute(telephoneAttribute);

        String phone = null;
        Iterator itor = null;
        if (telephoneNumbers != null && !telephoneNumbers.isEmpty()) {
            // use the first number in the set
            itor = telephoneNumbers.iterator();
            phone = (String) itor.next();
            if (carrierAttribute != null && carrierAttribute.trim().length() > 0) {
                // add in the carrier
                Set carriers = identity.getAttribute(carrierAttribute);
                if (carriers != null && !carriers.isEmpty()) {
                    Iterator itca = carriers.iterator();
                    String carrier = (String) itca.next();
                    if (carrier.startsWith("@")) {
                        phone = phone.concat(carrier);
                    } else {
                        phone = phone.concat("@" + carrier);
                    }
                    if (DEBUG.messageEnabled()) {
                        DEBUG.message("HOTP.sendSMS() : Using carrier attribute of " + carrierAttribute);
                    }
                }
            }
            if (DEBUG.messageEnabled()) {
                DEBUG.message("HOTP.sendSMS() : " + "IdRepoException : phone number found " + phone
                        + " with username : " + userName);
                    /*
                     * Log a message if the carrier is unknown.  The SMSGateway module is designed to use AT&T's SMS gateway
                     * as default.  Not sure why the product uses a default in this situation instead of simply not attempting 
                     * to send a text message but we don't want to break any existing installations so just log it for debug
                     * purposes.
                     * 
                     */
                if (!phone.contains("@")) {
                    DEBUG.message("HOTP.sendSMS() : No carrier detected - SMSGateway module will use default of "
                            + "@txt.att.net ");
                }
            }
        } else {
            if (DEBUG.messageEnabled()) {
                DEBUG.message("HOTP.sendSMS() : " + "IdRepoException : no phone number found with username : "
                        + userName);
            }
        }

        return phone;
    }

    /**
     * Gets the Email address of the user.
     *
     * @param identity The user's identity.
     * @return The user's email address.
     * @throws IdRepoException If there is a problem getting the user's email address.
     * @throws SSOException    If there is a problem getting the user's email address.
     */
    private String getEmailAddress(AMIdentity identity) throws IdRepoException, SSOException {

        if (emailAttribute == null || emailAttribute.trim().length() == 0) {
            emailAttribute = "mail";
        }
        if (DEBUG.messageEnabled()) {
            DEBUG.message("HOTP.sendSMS() : " + "Using email attribute of " + emailAttribute);
        }
        Set emails = identity.getAttribute(emailAttribute);

        Iterator itor = null;
        String mail = null;
        if (emails != null && !emails.isEmpty()) {
            itor = emails.iterator();
            mail = (String) itor.next();
            if (DEBUG.messageEnabled()) {
                DEBUG.message("HOTP.sendSMS() : IdRepo: email address found " + mail + " with username : " + userName);
            }
        } else {
            if (DEBUG.messageEnabled()) {
                DEBUG.message("HOTP.sendSMS() : IdRepo: no email found with username : " + userName);
            }
        }

        return mail;
    }

    /**
     * @return the attributes to be returned when querying the data store
     */
    private Set<String> getReturnAttributes() {
        Set<String> returnAttributes = new HashSet<String>(2);
        if ((emailAttribute != null) && (emailAttribute.trim().length() != 0)) {
            returnAttributes.add(emailAttribute);
        }

        if ((telephoneAttribute != null) && (telephoneAttribute.trim().length() != 0)) {
            returnAttributes.add(telephoneAttribute);
        }

        return returnAttributes;
    }
}