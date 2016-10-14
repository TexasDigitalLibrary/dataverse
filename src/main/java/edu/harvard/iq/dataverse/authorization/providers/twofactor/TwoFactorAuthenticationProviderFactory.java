package edu.harvard.iq.dataverse.authorization.providers.twofactor;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

import edu.harvard.iq.dataverse.authorization.AuthenticationProvider;
import edu.harvard.iq.dataverse.authorization.exceptions.AuthorizationSetupException;
import edu.harvard.iq.dataverse.authorization.providers.AuthenticationProviderFactory;
import edu.harvard.iq.dataverse.authorization.providers.AuthenticationProviderRow;
import edu.harvard.iq.dataverse.authorization.providers.builtin.BuiltinUserServiceBean;
import edu.harvard.iq.dataverse.authorization.providers.twofactor.providers.DuoWebTwoFactorIdp;

/**
 * Creates the built in authentication provider. There is only one, so calling
 * "build" twice will return the same instance.
 * 
 * @author Nicholas
 */
public class TwoFactorAuthenticationProviderFactory implements AuthenticationProviderFactory {

    private static interface ProviderBuilder {
        AbstractTwoFactorAuthenticationProvider build(AuthenticationProviderRow aRow, Map<String, String> factoryData);
    }
    
    private final Map<String, ProviderBuilder> builders = new HashMap<>();
    
    public TwoFactorAuthenticationProviderFactory(BuiltinUserServiceBean busBean) {
        builders.put("duoweb", (row, data) -> readRow(row, new DuoWebTwoFactorIdp(busBean)));
    }

    @Override
    public String getAlias() {
        return "TwoFactorAuthentication";
    }

    @Override
    public String getInfo() {
        return "Factory for Two-Factor Authentication Providers";
    }

    @Override
    public AuthenticationProvider buildProvider(AuthenticationProviderRow aRow) throws AuthorizationSetupException {
        Map<String,String> factoryData = parseFactoryData(aRow.getFactoryData());
        final String type = factoryData.get("type");
        if ( type == null ) {
            throw new AuthorizationSetupException("Authentication provider row with id " + aRow.getId() 
                    + " describes a Two Factor provider but does not provide a type. Available types are " + builders.keySet() );
        }
        ProviderBuilder pb = builders.get(type);
        if ( pb == null ) {
            throw new AuthorizationSetupException("Authentication provider row with id " + aRow.getId() 
                    + " describes an Two Factor provider of type " + type +". This type is not supported."
                    + " Available types are " + builders.keySet() );
        }
        return pb.build(aRow, factoryData);
    }
    
    /**
     * Expected map format.: {@code name: value|name: value|...}
     *
     * @param factoryData
     * @return A map of the factory data.
     */
    protected Map<String, String> parseFactoryData(String factoryData) {
        return Arrays.asList(factoryData.split("\\|")).stream()
                .map(s -> s.split(":", 2))
                .filter(p -> p.length == 2)
                .collect(Collectors.toMap(kv -> kv[0].trim(), kv -> kv[1].trim()));
    }
    
    protected AbstractTwoFactorAuthenticationProvider readRow(AuthenticationProviderRow row, AbstractTwoFactorAuthenticationProvider prv) {
        prv.setId(row.getId());
        prv.setTitle(row.getTitle());
        prv.setSubTitle(row.getSubtitle());

        return prv;
    }
    
}
