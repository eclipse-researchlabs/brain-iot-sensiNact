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


import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.Iterator;
import java.util.Map;
import java.util.jar.Attributes;
import java.util.jar.Manifest;

/**
 * A Signature file is part of the meta-data of signed Jar Files. It mainly
 * contains the hash value of the Manifest file of the Jar File. <br>
 * Only SHA-1/SHA-256 hash protocols are currently supported.
 *
 */
public class SignatureFile {

    private Attributes mainAttributes = null;
    private Map<String, Attributes> resourcesEntries = null;
    private byte[] data;
    private String hashHeader = null;
    private String hashAlgo = null;

    private static final String SHA1_ALGO = "SHA-1";
    private static final String SHA1_DIGEST_MF = "SHA1-Digest-Manifest";
    private static final String SHA256_ALGO = "SHA-256";
    private static final String SHA256_DIGEST_MF = "SHA-256-Digest-Manifest";

    /**
     * Constructor, for retrieving existing signature file.<br>
     * All attributes are not present (e.g. : attributes with hash value of
     * resources of the archive).<br>
     * By default, only SHA1 digest are supported
     *
     * @param JarFile
     * @param ZipEntry
     */
    SignatureFile(URL url) throws IOException {
        this.data = IOUtils.read(url.openStream());
        ByteArrayInputStream binput = new ByteArrayInputStream(this.data);
        this.mainAttributes = this.getMainAttributes(binput);
        this.initAlgo();
        binput.reset();
        this.resourcesEntries = this.getEntries(binput);
    }

    public final Attributes getMainAttributes() {
        return mainAttributes;
    }

    protected final Attributes getMainAttributes(final InputStream iStream) throws IOException {
        return new Manifest(iStream).getMainAttributes();
    }

    public final Map<String, Attributes> getEntries() {
        return resourcesEntries;
    }

    protected final Map<String, Attributes> getEntries(final InputStream iStream) throws IOException {
        return new Manifest(iStream).getEntries();
    }

    private void initAlgo() {
        if (mainAttributes.getValue(SHA1_DIGEST_MF) == null) {
            this.hashAlgo = SHA256_ALGO;
            this.hashHeader = SHA256_DIGEST_MF;

        } else {
            this.hashAlgo = SHA1_ALGO;
            this.hashHeader = SHA1_DIGEST_MF;
        }
    }

    /**
     * A method for retrieving Hash Value for the manifest
     *
     * @return hashValue
     */
    public String getManifestHash() {
        return mainAttributes.getValue(this.hashHeader);
    }

    /**
     * A method for retrieving the Hash algorithm used int this Signature File.
     *
     * @return String
     */
    public String getHashAlgo() {
        return hashAlgo;
    }

    /**
     * A method for retrieving data of this signature File as an array of
     * bytes.<br>
     * Beware, this method is (currently) valid only for a Signature File that
     * is built from an existing signed jar file.<br>
     * suitable code is to be integrated for newly created signature file
     *
     * @return byte[]
     */
    public final byte[] getBytes() throws IOException {
        byte[] dataCopy = new byte[data.length];
        System.arraycopy(data, 0, dataCopy, 0, data.length);
        return dataCopy;
    }

    public String toString() {
        String stringValue = "";
        try {
            stringValue = new String(this.getBytes());
        } catch (IOException e) {
            e.printStackTrace();
        }
        return stringValue;
    }

    public void show() {
        Map.Entry entry;
        String value;
        // mainAttributes
        for (final Iterator iter = mainAttributes.entrySet().iterator(); iter.hasNext(); ) {
            entry = (Map.Entry) iter.next();
        }
        // resourcesEntries
        for (final Iterator iter = resourcesEntries.entrySet().iterator(); iter.hasNext(); ) {
            entry = (Map.Entry) iter.next();
            value = (String) ((Map.Entry) ((Attributes) entry.getValue()).entrySet().iterator().next()).getValue();
        }
    }
}
