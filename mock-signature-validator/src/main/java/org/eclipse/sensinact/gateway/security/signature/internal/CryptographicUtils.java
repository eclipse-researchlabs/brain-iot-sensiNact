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

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 * Implementation class of the CryptographicUtils service, using Bouncy Castle
 * Cryptography provider.
 */
public class CryptographicUtils {

    /**
     * Constructor
     */
    public CryptographicUtils() throws NoSuchAlgorithmException {
    }

    private boolean checkHashValue(final String realHash, final String pretendedHash) {
        boolean validated = false;
        if (realHash.equals(pretendedHash))  
            validated = true;        
        return validated;
    }

    public boolean checkHashValue(URL entry, String hashValue, String algo) throws IOException, NoSuchAlgorithmException {
        final String realHash = this.getHashValue(entry.openStream(), algo);
        final boolean checked = this.checkHashValue(realHash, hashValue);
        return checked;
    }

    public String getHashValue(InputStream input, final String algo) throws IOException, NoSuchAlgorithmException {
        byte[] content = IOUtils.read(input);        
        String hash = this.getHashValue(content, algo);
        return hash;
    }

    public boolean checkHashValue(final byte[] data, final String hashValue, final String algo) throws NoSuchAlgorithmException {
        boolean validated = false;
        final String realHash = this.getHashValue(data, algo);
        if (realHash.equals(hashValue)) {
            validated = true;
        }
        return validated;
    }

    public byte[] digest(byte[] data, String algo) throws NoSuchAlgorithmException {
        MessageDigest messageDigest = null;
        if ((messageDigest = CryptoUtils.getDigest(algo)) != null) {
            return messageDigest.digest(data);
        } else {
            throw new NoSuchAlgorithmException();
        }
    }

    public String getHashValue(byte[] data, String algo) throws NoSuchAlgorithmException {
        return new String(Base64.getEncoder().encode(digest(data, algo)));
    }
    
    public boolean checkCMSDataValidity(final byte[] data, final byte[] cmsData, String algo) throws Exception {
        return true;
    }
}
