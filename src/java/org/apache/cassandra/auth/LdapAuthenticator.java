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
