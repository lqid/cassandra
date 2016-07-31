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


import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Map;
import java.util.Set;

import com.google.common.collect.ImmutableSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.apache.cassandra.exceptions.*;

import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.ldap.client.api.LdapConnection;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;


/**
 * LdapAuthenticator is an IAuthenticator implementation
 * that enables LDAP authentication against Windows AD.
 * It utilizes the Apache Directory LDAP API.
 */
public class LdapAuthenticator implements IAuthenticator{

    private static final Logger logger = LoggerFactory.getLogger(LdapAuthenticator.class);
    private static final byte NUL = 0;

    public LdapConnection ldapConnection = new LdapNetworkConnection("192.168.1.200", 389 );

    private void setupLdapConnection () throws Exception {
        ldapConnection.setTimeOut(30);
        ldapConnection.bind("uid=cassandra,ou=people,dc=klevi,dc=local","cassandra");
        //connection.unBind();
        //connection.close();
    }

    // Do not allow anonymous access.
    public boolean requireAuthentication() { return true; }

    private AuthenticatedUser authenticate(String username) throws AuthenticationException
    {
        System.out.println("Made it to authenticate!");
        System.out.println("LDAP is connected? " + ldapConnection.isConnected());
        System.out.println("LDAP is authenticated? " + ldapConnection.isAuthenticated());

        try
        {
            ldapConnection.bind("uid=cassandra,ou=people,dc=klevi,dc=local","cassandra");
            Entry authenticatingLdapUser = ldapConnection.lookup("uid="+username+",ou=people,dc=klevi,dc=local");
            if (authenticatingLdapUser != null)
            {
                System.out.println(authenticatingLdapUser);
                allowAuthentication(username);
            }
            else {
                System.out.println("User is not found.");
            }
        }
        catch (LdapException e){
            System.out.println(e);
            logger.trace("Error performing LDAP authentication", e);
            throw new AuthenticationException(e.toString());
        }
        return new AuthenticatedUser("cassandra");
    }

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
            logger.trace("Error setting up LDAP connection.", e);
            throw new AuthenticationException(e.toString());
        }
    }

    public SaslNegotiator newSaslNegotiator() {
        return new PlainTextSaslAuthenticator();
    }

    // Allows authentication of user.
    private AuthenticatedUser allowAuthentication(String username)
    throws RequestExecutionException, AuthenticationException
    {
        System.out.println("User found: " + username);
        return new AuthenticatedUser(AuthenticatedUser.SYSTEM_USERNAME);
    }

    private class PlainTextSaslAuthenticator implements SaslNegotiator {

        private boolean complete = false;
        private String username;
        private String password;

        public byte[] evaluateResponse(byte[] clientResponse) throws AuthenticationException
        {
            decodeCredentials(clientResponse);
            complete = true;
            return null;
        }

        public boolean isComplete() { return complete; }

        public AuthenticatedUser getAuthenticatedUser() throws AuthenticationException
        {
            if (!complete)
                throw new AuthenticationException("SASL negotiation not complete");
            return authenticate(username);
        }

        /**
         * SASL PLAIN mechanism specifies that credentials are encoded in a
         * sequence of UTF-8 bytes, delimited by 0 (US-ASCII NUL).
         * The form is : {code}authzId<NUL>authnId<NUL>password<NUL>{code}
         * authzId is optional, and in fact we don't care about it here as we'll
         * set the authzId to match the authnId (that is, there is no concept of
         * a user being authorized to act on behalf of another with this IAuthenticator).
         *
         * @param bytes encoded credentials string sent by the client
         * @return map containing the username/password pairs in the form an IAuthenticator
         * would expect
         * @throws javax.security.sasl.SaslException
         */
        private void decodeCredentials(byte[] bytes) throws AuthenticationException
        {
            logger.trace("Decoding credentials from client token");
            byte[] user = null;
            byte[] pass = null;
            int end = bytes.length;
            for (int i = bytes.length - 1 ; i >= 0; i--)
            {
                if (bytes[i] == NUL)
                {
                    if (pass == null)
                        pass = Arrays.copyOfRange(bytes, i + 1, end);
                    else if (user == null)
                        user = Arrays.copyOfRange(bytes, i + 1, end);
                    end = i;
                }
            }

            if (user == null)
                throw new AuthenticationException("Authentication ID must not be null");
            if (pass == null)
                throw new AuthenticationException("Password must not be null");

            username = new String(user, StandardCharsets.UTF_8);
            password = new String(pass, StandardCharsets.UTF_8);
            System.out.println(username + password);
        }

    }


    @Override
    public AuthenticatedUser legacyAuthenticate(Map<String, String> credentials) throws AuthenticationException {
        return null;
    }
}
