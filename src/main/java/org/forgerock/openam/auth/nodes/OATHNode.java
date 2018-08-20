/*
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2017 ForgeRock AS.
 */
/**
 * jon.knight@forgerock.com
 *
 * An HOTP OATH authentication node.
 */


package org.forgerock.openam.auth.nodes;

import com.google.inject.assistedinject.Assisted;
import com.iplanet.sso.SSOException;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.idm.IdRepoException;
import com.sun.identity.shared.debug.Debug;
import com.sun.identity.sm.RequiredValueValidator;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.*;
import org.forgerock.openam.core.CoreWrapper;
import org.forgerock.openam.utils.CollectionUtils;
import org.forgerock.openam.utils.StringUtils;


import javax.inject.Inject;
import javax.xml.bind.DatatypeConverter;
import java.util.*;

import static org.forgerock.openam.auth.node.api.SharedStateConstants.REALM;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.USERNAME;


import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;

/**
 * An HOTP OATH authentication node.
 */
@Node.Metadata(outcomeProvider = AbstractDecisionNode.OutcomeProvider.class,
        configClass = OATHNode.Config.class)
public class OATHNode extends AbstractDecisionNode {

    /**
     * Configuration for the node.
     */
    public interface Config {
        @Attribute(order = 100, validators = {RequiredValueValidator.class})
        default String OTPSharedStateName() { return "otp"; }
        @Attribute(order = 200, validators = {RequiredValueValidator.class})
        default int OTPPasswordLength() { return 6; }
        @Attribute(order = 300, validators = {RequiredValueValidator.class})
        default int MinSecretKeyLength() { return 32; }
        @Attribute(order = 400, validators = {RequiredValueValidator.class})
        String SecretKeyAttrName();
        @Attribute(order = 500, validators = {RequiredValueValidator.class})
        default int HOTPWindowSize() { return 100; }
        @Attribute(order = 600, validators = {RequiredValueValidator.class})
        String CounterAttrName();
        @Attribute(order = 700, validators = {RequiredValueValidator.class})
        default boolean Checksum() { return false; }
        @Attribute(order = 800, validators = {RequiredValueValidator.class})
        default int TruncationOffset() { return -1; }
    }

    private final Config config;
    private final CoreWrapper coreWrapper;
    private final static String DEBUG_FILE = "OATHNode";
    protected Debug debug = Debug.getInstance(DEBUG_FILE);

    private static final int MIN_PASSWORD_LENGTH = 6;

    /**
     * Guice constructor.
     * @param config The node configuration.
     * @throws NodeProcessException If there is an error reading the configuration.
     */
    @Inject
    public OATHNode(@Assisted Config config, CoreWrapper coreWrapper) throws NodeProcessException {
        this.config = config;
        this.coreWrapper = coreWrapper;
    }

    @Override
    public Action process(TreeContext context) throws NodeProcessException {
        debug.error("[" + DEBUG_FILE + "]: Starting");

        // Get user id from shared state
        AMIdentity id = coreWrapper.getIdentity(context.sharedState.get(USERNAME).asString(), context.sharedState.get(REALM).asString());

        // Get OTP from shared state
        String OTP = context.sharedState.get(config.OTPSharedStateName()).asString();

        boolean result = checkOTP(id, OTP);
        return goTo(result).build();
    }


    // Checks the input OTP
    private boolean checkOTP(AMIdentity id, String otp) {

        String secretKey = null;
        Set<String> secretKeySet = null;

        // Get user's secret from profile
        try {
            secretKeySet = id.getAttribute(config.SecretKeyAttrName());
        } catch (IdRepoException e) {
            debug.error("[" + DEBUG_FILE + "]: checkOTP: error getting secret key attribute: ", e);
            return false;
        } catch (SSOException e) {
            debug.error("[" + DEBUG_FILE + "]: checkOTP: error invalid repo id: " + id, e);
            return false;
        }
        // check secretKey attribute
        if (!CollectionUtils.isEmpty(secretKeySet)) {
            secretKey = secretKeySet.iterator().next();
        }
        // check size of key
        if (StringUtils.isEmpty(secretKey)) {
            debug.error("[" + DEBUG_FILE + "]: checkOTP: Secret key is empty");
            return false;
        }

        // get rid of white space in string (messes with the data converter)
        secretKey = secretKey.replaceAll("\\s+", "");
        // make sure secretkey is even length
        if ((secretKey.length() % 2) != 0) {
            secretKey = "0" + secretKey;
        }
        byte[] secretKeyBytes = DatatypeConverter.parseHexBinary(secretKey);

        if (null == secretKeyBytes) {
            debug.error("[" + DEBUG_FILE + "]: checkOTP: SharedSecretProvider returned null value");
            return false;
        }

        // since the minkeyLength accounts is for a hex encoded format, we need to adjust the byte length
        if ((secretKeyBytes.length * 2) < config.MinSecretKeyLength()) {
            debug.error("[" + DEBUG_FILE + "]: checkOTP: Secret key of length " + (secretKeyBytes.length * 2)
                    + " is less than the minimum secret key length of " + config.MinSecretKeyLength());
            return false;
        }


        String otpGen = null;
        // Get HOTP counter from user's profile
        int counter = 0;
        Set<String> counterSet = null;
        try {
            counterSet = id.getAttribute(config.CounterAttrName());
        } catch (IdRepoException e) {
            debug.error("[" + DEBUG_FILE + "]: checkOTP: error getting counter attribute : ", e);
            //return false;
        } catch (SSOException e) {
            debug.error("[" + DEBUG_FILE + "]: checkOTP: error invalid repo id : ", e);
            //return false;
        }
        //check counter value
        if (counterSet == null || counterSet.isEmpty()) {
            //throw exception
            debug.error("[" + DEBUG_FILE + "]: checkOTP: Counter value is empty or null, starting with 0");
            //return false;
        } else {
            try {
                counter = Integer.parseInt((String) (counterSet.iterator().next()));
            } catch (NumberFormatException e) {
                debug.error("[" + DEBUG_FILE + "]: checkOTP: Counter is not a valid number, starting with 0", e);
                return false;
            }
        }

        //check window size
        if (config.HOTPWindowSize() < 0) {
            debug.error("[" + DEBUG_FILE + "]: checkOTP: Window size is not valid");
            return false;
        }

        // we have to do counter+1 because counter is the last previous accepted counter
        counter++;

        //test the counter in the lookahead window
        for (int i = 0; i <= config.HOTPWindowSize(); i++) {
            otpGen = generateOTP(secretKeyBytes,
                    counter + i,
                    config.OTPPasswordLength(),
                    config.Checksum(),
                    config.TruncationOffset());

            if (MessageDigest.isEqual(otpGen.getBytes(), otp.getBytes())) {
                //OTP is correct set the counter value to counter+i
                setCounterAttr(id, counter + i);
                return true;
            }
        }
        return false;
    }


     // Sets the HOTP counter for a user.
    private void setCounterAttr(AMIdentity id, int counter) {
        Map<String, Set> map = new HashMap<String, Set>();
        Set<String> values = new HashSet<String>();
        String counterS = Integer.toString(counter);
        values.add(counterS);
        map.put(config.CounterAttrName(), values);
        try {
            id.setAttributes(map);
            id.store();
        } catch (IdRepoException e) {
            debug.error("[" + DEBUG_FILE + "]: checkOTP: error setting counter attribute to : " + counter, e);
        } catch (SSOException e) {
            debug.error("[" + DEBUG_FILE + "]: checkOTP: error invalid token for id : " +  id, e);
        }
        return;
    }

    // HOTP generation
    public static byte[] hmac_sha1(byte[] keyBytes, byte[] text) {
        Mac hmacSha1;
        try {
            hmacSha1 = Mac.getInstance("HmacSHA1");
        } catch (NoSuchAlgorithmException nsae) {
            try {
                hmacSha1 = Mac.getInstance("HMAC-SHA-1");
            } catch (NoSuchAlgorithmException nsae2) {
                return null;
            }
        }
        SecretKeySpec macKey = new SecretKeySpec(keyBytes, "RAW");
        try {
            hmacSha1.init(macKey);
        } catch (InvalidKeyException ike) {
            return null;
        }
        return hmacSha1.doFinal(text);
    }

    private static final int[] DIGITS_POWER = {1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000};
    private static final int[] doubleDigits = {0, 2, 4, 6, 8, 1, 3, 5, 7, 9};

    public static int calcChecksum(long num, int digits) {
        boolean doubleDigit = true;
        int total = 0;
        while (0 < digits--) {
            int digit = (int) (num % 10);
            num /= 10;
            if (doubleDigit) {
                digit = doubleDigits[digit];
            }
            total += digit;
            doubleDigit = !doubleDigit;
        }
        int result = total % 10;
        if (result > 0) {
            result = 10 - result;
        }
        return result;
    }

    static public String generateOTP(byte[] secret, long movingFactor, int codeDigits, boolean addChecksum, int truncationOffset) {
        // put movingFactor value into text byte array
        String result = null;
        int digits = addChecksum ? (codeDigits + 1) : codeDigits;
        byte[] text = new byte[8];
        for (int i = text.length - 1; i >= 0; i--) {
            text[i] = (byte) (movingFactor & 0xff);
            movingFactor >>= 8;
        }

        byte[] hash = hmac_sha1(secret, text);

        // put selected bytes into result int
        int offset = hash[hash.length - 1] & 0xf;
        if ((0 <= truncationOffset) && (truncationOffset < (hash.length - 4))) {
            offset = truncationOffset;
        }
        int binary = ((hash[offset] & 0x7f) << 24) |
                        ((hash[offset + 1] & 0xff) << 16) |
                        ((hash[offset + 2] & 0xff) << 8) |
                        (hash[offset + 3] & 0xff);

        int otp = binary % DIGITS_POWER[codeDigits];
        if (addChecksum) {
            otp = (otp * 10) + calcChecksum(otp, codeDigits);
        }
        result = Integer.toString(otp);
        while (result.length() < digits) {
            result = "0" + result;
        }
        return result;
    }
}
