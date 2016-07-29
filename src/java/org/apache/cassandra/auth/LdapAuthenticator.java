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


import java.util.Map;
import java.util.Set;

import com.google.common.collect.ImmutableSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.apache.cassandra.exceptions.*;

import org.apache.directory.ldap.client.api.LdapConnection;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;


/**
 * LdapAuthenticator is an IAuthenticator implementation
 * that enables LDAP authentication against Windows AD.
 * It utilizes the Apache Directory LDAP API.
 */
public class LdapAuthenticator implements IAuthenticator{

    private static final Logger logger = LoggerFactory.getLogger(LdapAuthenticator.class);

    public void setupLdapConnection () throws Exception {
        LdapConnection connection = new LdapNetworkConnection("192.168.1.200", 389 );
        connection.setTimeOut(30);
        connection.bind("uid=cassandra,ou=people,dc=klevi,dc=local", "cassandra");
        connection.unBind();
        connection.close();
    }

    // Do not allow anonymous access.
    public boolean requireAuthentication() { return true; }

    public Set<DataResource> protectedResources()
    {
        // Also protected by CassandraRoleManager, but the duplication doesn't hurt and is more explicit
        return ImmutableSet.of(DataResource.table(AuthKeyspace.NAME, AuthKeyspace.ROLES));
    }

    public void validateConfiguration() throws ConfigurationException {

    }

    public void setup() {
        try
        {
            setupLdapConnection();
        }
        catch (Exception e)
        {
            logger.trace("Error performing internal authentication", e);
            throw new AuthenticationException(e.toString());
        }
    }

    public SaslNegotiator newSaslNegotiator() {
        return new PlainTextSaslAuthenticator();
    }

    private class PlainTextSaslAuthenticator implements SaslNegotiator {

        public byte[] evaluateResponse(byte[] clientResponse) throws AuthenticationException
        {
            return null;
        }

        public boolean isComplete() { return true; }

        public AuthenticatedUser getAuthenticatedUser() throws AuthenticationException
        {
            return null;
        }

    }


    @Override
    public AuthenticatedUser legacyAuthenticate(Map<String, String> credentials) throws AuthenticationException {
        return null;
    }
}
