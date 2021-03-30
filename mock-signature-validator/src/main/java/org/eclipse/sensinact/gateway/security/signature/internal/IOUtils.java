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
import java.io.OutputStream;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Helper methods for InputStream and OutputStream accesses
 *
 * @author <a href="mailto:christophe.munilla@cea.fr">Christophe Munilla</a>
 */
public abstract class IOUtils {
    private static final Logger LOGGER = Logger.getLogger(IOUtils.class.getCanonicalName());
    private static final int BUFFER_SIZE = 64 * 1024;
    private static final int UNLIMITED = -1;

    /**
     * @param input the InputStream to read
     * @return
     */
    public static byte[] read(InputStream input) {
        int read = 0;
        int length = 0;
        int size = UNLIMITED;
        byte[] content = new byte[length];
        byte[] buffer = new byte[BUFFER_SIZE];
        
        try {
            while (true) {
                if (size > UNLIMITED && length >= size) {
                    break;
                }
                read = input.read(buffer);
                if (read == -1) {
                    break;
                }
                byte[] newContent = new byte[length + read];
                if (length > 0) {
                    System.arraycopy(content, 0, newContent, 0, length);
                }
                System.arraycopy(buffer, 0, newContent, length, read);
                content = newContent;
                newContent = null;
                length += read;
            }
        } catch (IOException e) {
            LOGGER.log(Level.CONFIG, e.getMessage(), e);

        } finally {            
            try {
                input.close();

            } catch (Exception e) {
                LOGGER.log(Level.CONFIG, e.getMessage(), e);
            }
        }
        return content;
    }
}
