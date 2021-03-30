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
package org.eclipse.sensinact.gateway.security.signature.test;

import org.eclipse.sensinact.gateway.security.signature.internal.CryptographicUtils;
import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Base64;

@Ignore
public class CryptographicUtilsTest {
    static CryptographicUtils cutils = null;
    String fileName4hash = "src/test/resources/textFile.txt.bis";
    String trueHashValue = "c00148f586db109ffaca3724102e69e2e7996bf0";
    String falseHashValue = "swzWklBmNJVD4/8+hpCT6b3L7WY=";
    String defaultAlgo = "SHA-1";
    String fileName4CMS = "src/test/resources/textFile.txt";
    String alias = "selfsigned";
    String passwd = "sensiNact_team";
    String keyStoreType = "jks";
    String defaultKeystoreFile = "./cert/keystore.jks";
    String signatureFileName = "src/test/resources/JUNITTES.SF";
    String signatureBlockName = "src/test/resources/JUNITTES.DSA";
    KeyStore ks = null;

    public CryptographicUtilsTest() throws NoSuchAlgorithmException {
        cutils = new CryptographicUtils();
    }

    KeyStore getKeyStore() throws KeyStoreException, FileNotFoundException, NoSuchAlgorithmException, IOException, CertificateException {
        KeyStore ks = KeyStore.getInstance(keyStoreType);
        ks.load(new FileInputStream(defaultKeystoreFile), passwd.toCharArray());
        return ks;
    }

    byte[] getData(String fileName) throws IOException {
        FileInputStream fis = new FileInputStream(fileName);
        byte[] data = new byte[fis.available()];
        fis.read(data);
        return data;
    }

    String getTrueHashValue(byte[] data, String algo) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance(algo);
        digest.update(data);
        return new String(Base64.getEncoder().encode(digest.digest()));
    }


    protected boolean dataWithSameContent(byte[] d1, byte[] d2) {
        boolean result = false;
        if (d1.length == d2.length) {
            byte[] data1 = new byte[d1.length];
            byte[] data2 = new byte[d2.length];
            boolean sameContent = true;
            for (int i = 0; i < d1.length; i++) {
                sameContent = sameContent && (data1[i] == data2[i]);
            }
            result = sameContent;
        }
        return result;
    }

    @Test
    public void testCheckHashValueOK() throws Exception {
        byte[] data = getData(fileName4hash);
        String trueHashValue = this.getTrueHashValue(data, defaultAlgo);
        boolean result = cutils.checkHashValue(data, trueHashValue, "SHA1-Digest");
        Assert.assertTrue(result);
    }

    @Test
    public void testGetHashValueOK() throws Exception {
        byte[] data = getData(fileName4hash);
        String trueHashValue = getTrueHashValue(data, defaultAlgo);
        String result = cutils.getHashValue(data, "SHA1-Digest");
        ;
        Assert.assertTrue(result.equals(trueHashValue));
    }

    @Ignore
    @Test
    public void testCheckCMSDataValidity() throws Exception {
        try {
            byte[] signatureFileData = this.getData(signatureFileName);
            byte[] signatureBlockData = this.getData(signatureBlockName);
            boolean res = cutils.checkCMSDataValidity(signatureFileData, signatureBlockData, "SHA1-Digest");
            Assert.assertTrue(res);
        } catch (Exception e) {
            e.printStackTrace();
        } catch (Error e) {
            e.printStackTrace();
        }
    }
}
