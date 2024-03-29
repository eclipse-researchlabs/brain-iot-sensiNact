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
import java.net.URL;

/**
 * A Signature block is part of the meta-data of signed Jar Files. It
 * encapsulates a CMS (Cryptographic Message Standard) file.
 */
public class SignatureBlock  {
    
	private byte[] bytes;

    public SignatureBlock(URL url) throws IOException {
        this.bytes = IOUtils.read(url.openStream()); 
    }

    /**
     * A method for retrieving the signature block in a given Jar File for a
     * given signer.
     *
     * @param sjar
     * @param signerName
     * @return SignatureBlock
     * @throws IOException
     */
    public static SignatureBlock getInstance(SignedBundle sjar, String signerName) throws IOException {
        SignatureBlock block = null;
        final URL rsaEntry = sjar.getEntry("/META-INF/" + signerName + ".RSA");
        final URL dsaEntry = sjar.getEntry("/META-INF/" + signerName + ".DSA");
        if (dsaEntry == null) {
            if (rsaEntry != null) {
                block = new SignatureBlock(rsaEntry);
            }
        } else {
            block = new SignatureBlock(dsaEntry);
        }
        return block;
    }

    /**
     * A method for retrieving signature from the CMS data of a signed jar.<br>
     * the archive id supposed to be signed only once by the signer.
     *
     * @param pkcs7
     * @return byte[]
     * @throws Exception
     */
    public static byte[] getSignatureFromSignedData() {        
        byte[] signature = new byte[] {};
        return signature;
    }
}
