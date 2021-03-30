/*
 * Copyright (c) 2020-2021 Kentyou.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Contributors:
 *    Kentyou - initial API and implementation
 */
package org.eclipse.sensinact.gateway.security.signature.internal;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * Cryptographic helper methods
 *
 * @author <a href="mailto:cmunilla@kentyou.com">Christophe Munilla</a>
 */
public class CryptoUtils {

    public static final SecureRandom SECURE_RANDOM;
    public static final MessageDigest SHA1;
    public static final MessageDigest SHA256;
    public static final MessageDigest MD5;

    static {
        SecureRandom random = null;
        MessageDigest sha1Digest = null;
        MessageDigest sha256Digest = null;
        MessageDigest md5Digest = null;
        try {
            //Initialize SecureRandom
            //This is a lengthy operation, to be done only upon
            //initialization of the application
            random = SecureRandom.getInstance("SHA1PRNG");
            sha1Digest = MessageDigest.getInstance("SHA-1");
            sha256Digest = MessageDigest.getInstance("SHA-256");
            md5Digest = MessageDigest.getInstance("MD5");
        } catch (NoSuchAlgorithmException ex) {
            ex.printStackTrace(System.err);
        }
        SECURE_RANDOM = random;
        SHA1 = sha1Digest;
        SHA256 = sha256Digest;
        MD5 = md5Digest;

        random = null;
        sha1Digest = null;
        sha256Digest = null;
        md5Digest = null;
    }

    public static final String cryptWithMD5(String pass) throws InvalidKeyException {
        if (MD5 == null) 
            throw new InvalidKeyException("Algorithm MD5 not implemented");
        try {
            MessageDigest mydigest = (MessageDigest) MD5.clone();
            mydigest.reset();
            byte[] digested = mydigest.digest(pass.getBytes());
            return String.format("%032X", new BigInteger(1, digested)).toLowerCase();
        } catch (CloneNotSupportedException e) {
            throw new InvalidKeyException(e);
        }
    }

    public static MessageDigest getDigest(String algo) {
        // "SHA1-Digest" should not be necessary. Extensive tests should be
        // available to allow for its removal
        if ("SHA1-Digest".equals(algo) || "SHA-1".equals(algo) || "SHA1".equals(algo)) {
            return CryptoUtils.SHA1;

        } else if ("SHA-256".equals(algo) || "SHA-256-Digest".equals(algo) || "SHA256".equals(algo)) {
            return CryptoUtils.SHA256;

        } else if ("MD5".equals(algo) || "MD5-Digest".equals(algo) || "MD-5".equals(algo)) {
            return CryptoUtils.MD5;
        }
        return null;
    }
}
