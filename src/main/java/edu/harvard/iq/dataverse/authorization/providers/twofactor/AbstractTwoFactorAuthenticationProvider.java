package edu.harvard.iq.dataverse.authorization.providers.twofactor;

import edu.harvard.iq.dataverse.authorization.AuthenticationProvider;
import edu.harvard.iq.dataverse.authorization.AuthenticationProviderDisplayInfo;
import edu.harvard.iq.dataverse.authorization.AuthenticationRequest;
import edu.harvard.iq.dataverse.authorization.AuthenticationResponse;
import edu.harvard.iq.dataverse.authorization.providers.builtin.BuiltinUserServiceBean;

import java.util.Arrays;
import java.util.List;
import static edu.harvard.iq.dataverse.authorization.CredentialsAuthenticationProvider.Credential;
import edu.harvard.iq.dataverse.util.BundleUtil;

/**
 * An authentication provider built into the application. Uses JPA and the 
 * local database to store the users.
 * 
 * @author Nicholas
 */
public class AbstractTwoFactorAuthenticationProvider implements AuthenticationProvider {
    
    protected static String KEY_USERNAME_OR_EMAIL;
    protected static String KEY_PASSWORD;
    private static List<Credential> CREDENTIALS_LIST;
      
    final BuiltinUserServiceBean bean;
    
    protected String id;
    protected String title;
    protected String subTitle;
    protected String clientId;
    protected String clientSecret;
    protected String userEndpoint;
    protected String redirectUrl;
    protected String scope;

    public AbstractTwoFactorAuthenticationProvider( BuiltinUserServiceBean aBean ) {
        bean = aBean;
        KEY_USERNAME_OR_EMAIL = BundleUtil.getStringFromBundle("login.builtin.credential.usernameOrEmail");
        KEY_PASSWORD = BundleUtil.getStringFromBundle("login.builtin.credential.password");
        CREDENTIALS_LIST = Arrays.asList(new Credential(KEY_USERNAME_OR_EMAIL), new Credential(KEY_PASSWORD, true));
    }

    @Override
    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }
    
    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public void setSubTitle(String subtitle) {
        this.subTitle = subtitle;
    }

    public String getSubTitle() {
        return subTitle;
    }
    
    @Override
    public AuthenticationProviderDisplayInfo getInfo() {
        return new AuthenticationProviderDisplayInfo(getId(), "Two Factor Provider", "Internal user repository");
    }
    
    @Override
    public AuthenticationResponse authenticate(AuthenticationRequest request) {
	    return new AuthenticationResponse();
    }
}
