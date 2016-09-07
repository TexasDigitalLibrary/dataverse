package edu.harvard.iq.dataverse.authorization.providers.duoweb;

import edu.harvard.iq.dataverse.authorization.AuthenticationProvider;
import edu.harvard.iq.dataverse.authorization.exceptions.AuthorizationSetupException;
import edu.harvard.iq.dataverse.authorization.providers.AuthenticationProviderFactory;
import edu.harvard.iq.dataverse.authorization.providers.AuthenticationProviderRow;
import edu.harvard.iq.dataverse.authorization.providers.builtin.BuiltinUserServiceBean;

/**
 * Creates the built in authentication provider. There is only one, so calling
 * "build" twice will return the same instance.
 * 
 * @author michael
 */
public class DuoWebAuthenticationProviderFactory implements AuthenticationProviderFactory {
    
    private final DuoWebAuthenticationProvider provider;

    public DuoWebAuthenticationProviderFactory( BuiltinUserServiceBean busBean ) {
        provider = new DuoWebAuthenticationProvider( busBean );
    }
    
    @Override
    public String getAlias() {
        return "DuoWebAuthenticationProvider";
    }

    @Override
    public String getInfo() {
        return "DuoWebAuthenticationProvider - the provider bundled with Dataverse including Duo Web's 2FA";
    }

    @Override
    public AuthenticationProvider buildProvider(AuthenticationProviderRow aRow) throws AuthorizationSetupException {
        return provider;
    }
    
}
