/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.cassandra.auth;

import org.apache.cassandra.exceptions.AuthenticationException;
import org.apache.cassandra.exceptions.ConfigurationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.Set;

/**
 * LdapAuthenticator is an IAuthenticator implementation
 * that enables LDAP authentication against Windows AD.
 * It utilizes the Apache Directory LDAP API.
 */
public class LdapAuthenticator implements IAuthenticator{

    private static final Logger logger = LoggerFactory.getLogger(PasswordAuthenticator.class);

    // Do not allow anonymous access.
    public boolean requireAuthentication() {return true;}

    @Override
    public Set<? extends IResource> protectedResources() {
        return null;
    }

    @Override
    public void validateConfiguration() throws ConfigurationException {

    }

    @Override
    public void setup() {

    }

    @Override
    public SaslNegotiator newSaslNegotiator() {
        return null;
    }

    @Override
    public AuthenticatedUser legacyAuthenticate(Map<String, String> credentials) throws AuthenticationException {
        return null;
    }
}
