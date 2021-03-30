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

import org.apache.felix.framework.FrameworkFactory;
import org.eclipse.sensinact.gateway.security.signature.api.BundleValidation;
import org.eclipse.sensinact.gateway.security.signature.internal.BundleValidationImpl;
import org.eclipse.sensinact.gateway.security.signature.internal.KeyStoreManagerException;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.osgi.framework.Bundle;
import org.osgi.framework.BundleException;
import org.osgi.framework.launch.Framework;
import org.osgi.service.component.ComponentContext;

import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

public class BundleValidationTest {
    private static final Map<String, String> CONFIGURATION = new HashMap<String, String>();

    static {
        CONFIGURATION.put("felix.cache.rootdir", "./target/felix");
        CONFIGURATION.put("org.osgi.framework.storage", "felix-cache");
        CONFIGURATION.put("felix.auto.deploy.dir", "./target/felix/bundle");
        CONFIGURATION.put("felix.auto.deploy.action", "install,start");
        CONFIGURATION.put("felix.log.level", "4");
        CONFIGURATION.put("org.osgi.framework.system.packages.extra", "org.eclipse.sensinact.gateway.generic.core;version= \"2.0.0\"," + "org.eclipse.sensinact.gateway.generic.core.impl;version= \"2.0.0\"," + "org.eclipse.sensinact.gateway.generic.core.packet;version=\"2.0.0\"," + "org.eclipse.sensinact.gateway.generic.stream;version= \"2.0.0\"," + "org.eclipse.sensinact.gateway.generic.uri;version= \"2.0.0\"," + "org.eclipse.sensinact.gateway.generic.parser;version= \"2.0.0\"," + "org.eclipse.sensinact.gateway.generic.automata;version= \"2.0.0\"," + "org.eclipse.sensinact.gateway.generic.annotation;version= \"2.0.0\"," + "org.eclipse.sensinact.gateway.generic.local;version= \"2.0.0\"," + "org.eclipse.sensinact.gateway.util;version= \"2.0.0\"," + "org.eclipse.sensinact.gateway.util.constraint;version= \"2.0.0\"," + "org.eclipse.sensinact.gateway.util.crypto;version= \"2.0.0\"," + "org.eclipse.sensinact.gateway.util.json;version= \"2.0.0\"," + "org.eclipse.sensinact.gateway.util.mediator;version= \"2.0.0\"," + "org.eclipse.sensinact.gateway.util.properties;version= \"2.0.0\"," + "org.eclipse.sensinact.gateway.util.reflect;version= \"2.0.0\"," + "org.eclipse.sensinact.gateway.util.rest;version= \"2.0.0\"," + "org.eclipse.sensinact.gateway.util.xml;version= \"2.0.0\"," + "json-20140107.jar;version= \"2.0.0\"," + "org.json;version;version= \"2.0.0\"," + "org.json.zip;version=\"2.0.0\"");
    }

    private Framework felix = new FrameworkFactory().newFramework(CONFIGURATION);
    private BundleValidation jval = null;
    private Bundle fan = null;
    private Bundle button = null;
    private static final String DEFAULT_KEYSTORE_FILE_PATH = "./cert/keystore.jks";
    private static final String DEFAULT_KEYSTORE_PASSWORD = "sensiNact_team";

    private ComponentContext context = Mockito.mock(ComponentContext.class);
    
    @Before
    public void init() throws NoSuchAlgorithmException, KeyStoreManagerException, BundleException {
        
    	
    	felix = new FrameworkFactory().newFramework(CONFIGURATION);
        felix.init();
        felix.start();

        Assert.assertTrue(felix.getState() == Bundle.ACTIVE);

    	Mockito.when(context.getBundleContext()).thenReturn(felix.getBundleContext());
    	
        this.jval = new BundleValidationImpl() {
            @Override
            protected String getKeyStoreFileName() {
                return BundleValidationTest.DEFAULT_KEYSTORE_FILE_PATH;
            }

            @Override
            protected String getKeyStorePassword() {
                return BundleValidationTest.DEFAULT_KEYSTORE_PASSWORD;
            }

            @Override
            protected String getSignerPassword() {
                return BundleValidationTest.DEFAULT_KEYSTORE_PASSWORD;
            }
        };
        
        ((BundleValidationImpl)this.jval).activate(context);
    }

    @After
    public void tearDown() {
        try {
            felix.stop();
        } catch (BundleException e) {
            e.printStackTrace();
        }
        this.jval = null;
        this.fan = null;
        this.button = null;
    }

    @Test
    public void testCheckFanOK() throws BundleException {
        this.fan = felix.getBundleContext().installBundle("file:./target/extra/fan.jar");
        String result = null;
        try {
            result = jval.check(this.fan);
        } catch (Exception e) {
            e.printStackTrace();

        } finally {
            this.fan.uninstall();
        }
        Assert.assertTrue(result != null);
    }

    @Test
    public void testCheckButtonOK() throws BundleException {
        this.button = felix.getBundleContext().installBundle("file:./target/extra/button.jar");
        String result = null;
        try {
            result = jval.check(this.button);
        } catch (Exception e) {
            e.printStackTrace();

        } finally {
            this.button.uninstall();
        }
        Assert.assertTrue(result != null);
    }
}
