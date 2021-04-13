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

import org.eclipse.sensinact.gateway.security.signature.api.BundleValidation;
import org.eclipse.sensinact.gateway.security.signature.exception.BundleValidationException;
import org.osgi.framework.Bundle;
import org.osgi.framework.BundleContext;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;

import java.io.IOException;
import java.net.URL;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

/**
 * An implementation of the BundleValidation service
 */
@Component(immediate=true,service=BundleValidation.class)
public class BundleValidationImpl implements BundleValidation {
	
    private final class ValidBundleKey {
        public final int hashcode;
        public final String name;
        public final String key;

        public ValidBundleKey(int hashcode, String name, String key) {
            this.hashcode = hashcode;
            this.name = name;
            this.key = key;
        }
    }

    private static final String FILE = "file";

    private Map<String, ValidBundleKey> validated;
    private CryptographicUtils cryptoUtils;
    private KeyStoreManager ksm;

	private BundleContext bundleContext;

    @Activate
    public void activate (ComponentContext context) throws KeyStoreManagerException, NoSuchAlgorithmException {
        this.bundleContext = context.getBundleContext();
        this.validated = Collections.<String, ValidBundleKey>synchronizedMap(new HashMap<>());
        this.cryptoUtils = new CryptographicUtils();
        this.ksm = new KeyStoreManager(this.getKeyStoreFileName(), this.getKeyStorePassword());
    }

    protected URL getKeyStoreFileName() {
        String path = (String) bundleContext.getProperty("org.eclipse.sensinact.gateway.security.jks.filename");
        return bundleContext.getBundle().getEntry(path);
    }

    protected String getKeyStorePassword() {
        return (String) bundleContext.getProperty("org.eclipse.sensinact.gateway.security.jks.password");
    }

    protected String getSignerPassword() {
        return (String) bundleContext.getProperty("org.eclipse.sensinact.gateway.security.signer.password");
    }

    public String check(Bundle bundle) throws BundleValidationException {
        if (bundle == null) 
            return null;

        int hashcode = bundle.hashCode();
        String bundleName = bundle.getSymbolicName();

        ValidBundleKey validBundleKey = this.validated.get(bundleName);

        if (validBundleKey != null && validBundleKey.hashcode == hashcode) {
            return validBundleKey.key;
        }
        boolean isSigned = false;

        final Enumeration<URL> entries = bundle.findEntries("/META-INF", "*", true);

        while (entries.hasMoreElements()) {
            URL url = entries.nextElement();
            if (url.toExternalForm().endsWith(".RSA") || url.toExternalForm().endsWith("DSA")) {
                isSigned = true;
                break;
            }
        }
        if(!isSigned) {
        	return null;
        }
        SignedBundle sjar;
		try {
			sjar = new SignedBundle(bundle, cryptoUtils);
	        sjar.setKeyStoreManager(ksm);
	        SignatureFile signatureFile = sjar.getSignatureFile();
	        String sha1 = signatureFile.getManifestHash();
	        this.validated.put(bundleName, new ValidBundleKey(hashcode, bundleName, sha1));
	        return sha1;
		} catch (IOException e) {
			e.printStackTrace();
		}
		return bundleName;
    }
}
