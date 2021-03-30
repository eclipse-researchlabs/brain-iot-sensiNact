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

import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.jar.Attributes;

public class SignatureFileChecker {

    private SignatureFileChecker() {
        // no action
    }

    private static boolean checkAbsenceOfModification(final SignedBundle signedJar, final SignatureFile pretendedSigFile) throws IOException {
        final Set sigEntries = pretendedSigFile.getEntries().keySet();
        final Set mfEntries = signedJar.getManifest().getEntries().keySet();
        boolean noAddition = false;
        boolean noRemoval = false;
        if (sigEntries.containsAll(mfEntries)) 
            noRemoval = true;
        
        if (mfEntries.containsAll(sigEntries)) 
            noAddition = true;
        
        return noAddition && noRemoval;
    }

    private static boolean checkHashValuesValid(SignedBundle signedBundle, SignatureFile pretendedSigFile, CryptographicUtils cryptoUtils) throws FileNotFoundException, IOException, NoSuchAlgorithmException {
        boolean manifestEntriesValid = true;
        final Attributes pretendedMainAttributes = pretendedSigFile.getMainAttributes();

        final Map pretendedEntries = pretendedSigFile.getEntries();

        final Map<String, String> dataMap = ManifestChecker.extractEntryHashes(signedBundle.getEntry("/META-INF/MANIFEST.MF").openStream(), cryptoUtils, pretendedSigFile.getHashAlgo());
      
        String entryName, currentHash, pretendedHash;
        Map.Entry entry;
        boolean currentEntryValid;
        for (final Iterator iter = dataMap.entrySet().iterator(); iter.hasNext() && manifestEntriesValid; ) {
            entry = (Map.Entry) iter.next();
            entryName = (String) entry.getKey();
            currentHash = (String) entry.getValue();
            if ("SHA1-Digest-Manifest-Main-Attributes".equals(entryName)) 
                pretendedHash = (String) pretendedMainAttributes.getValue(entryName);
            else if ("SHA-256-Digest-Manifest-Main-Attributes".equals(entryName)) 
                pretendedHash = (String) pretendedMainAttributes.getValue(entryName);
            else
                pretendedHash = ManifestChecker.getEntryHash((Attributes) pretendedEntries.get(entryName));
            
            if (pretendedHash == null) 
                manifestEntriesValid = false;
            else {
                currentEntryValid = pretendedHash.equals(currentHash);
                manifestEntriesValid &= currentEntryValid;
            }
        }
        return manifestEntriesValid;
    }

    protected static boolean checkEntriesValidity(SignedBundle signedJar, SignatureFile pretendedSigFile, CryptographicUtils cryptoUtils) throws FileNotFoundException, IOException, NoSuchAlgorithmException {
    	final boolean absenceOfModifications = SignatureFileChecker.checkAbsenceOfModification(signedJar, pretendedSigFile);
        final boolean hashesValid = SignatureFileChecker.checkHashValuesValid( signedJar, pretendedSigFile, cryptoUtils);
        return absenceOfModifications && hashesValid;
    }
}
