package edu.harvard.iq.dataverse.authorization.providers.twofactor;

import edu.harvard.iq.dataverse.authorization.AuthenticationProviderDisplayInfo;
import edu.harvard.iq.dataverse.authorization.AuthenticationRequest;
import edu.harvard.iq.dataverse.authorization.AuthenticationResponse;
import edu.harvard.iq.dataverse.authorization.CredentialsAuthenticationProvider;
import edu.harvard.iq.dataverse.authorization.providers.builtin.BuiltinUserServiceBean;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;

import edu.harvard.iq.dataverse.util.BundleUtil;

/**
 * An authentication provider built into the application. Uses JPA and the 
 * local database to store the users.
 * 
 * @author Nicholas
 */
public class AbstractTwoFactorAuthenticationProvider implements CredentialsAuthenticationProvider {
    
	private static final Logger logger = Logger.getLogger(AbstractTwoFactorAuthenticationProvider.class.getName());
	
    protected static String KEY_USERNAME_OR_EMAIL;
    protected static String KEY_PASSWORD;
    private static List<Credential> CREDENTIALS_LIST;
      
    BuiltinUserServiceBean bean;
    
    protected String id;
    protected String title;
    protected String subTitle;
    protected String clientId;
    protected String clientSecret;
    protected String token;
    protected String username;
    protected String hostname;
    
    protected String userEndpoint;
    protected String redirectUrl;
    protected String scope;
    
    public AbstractTwoFactorAuthenticationProvider(){}
    
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

    public String getClientId() {
		return clientId;
	}

	public void setClientId(String clientId) {
		this.clientId = clientId;
	}

	public String getClientSecret() {
		return clientSecret;
	}

	public void setClientSecret(String clientSecret) {
		this.clientSecret = clientSecret;
	}
	
	public String getToken() {
		return token;
	}

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public String getHostname() {
		return hostname;
	}

	public void setHostname(String hostname) {
		this.hostname = hostname;
	}

	public String createToken(String username) {
		// Implemented by 2FA providers
		return new String();
	}
	
	public String verifyResponse(String response) {
		// Implemented by 2FA providers
		return new String();
	}
	
	@Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if ( ! (obj instanceof AbstractTwoFactorAuthenticationProvider)) {
            return false;
        }
        final AbstractTwoFactorAuthenticationProvider other = (AbstractTwoFactorAuthenticationProvider) obj;
        if (!Objects.equals(this.id, other.id)) {
            return false;
        }
        if (!Objects.equals(this.clientId, other.clientId)) {
            return false;
        }
        return Objects.equals(this.clientSecret, other.clientSecret);
    }    
    
    @Override
    public AuthenticationProviderDisplayInfo getInfo() {
        return new AuthenticationProviderDisplayInfo(getId(), "TwoFactor Provider", "Internal user repository");
    }
    
    @Override
    public AuthenticationResponse authenticate(AuthenticationRequest authReq) {
    	logger.log(Level.INFO, "TDL This is the authenticate() method of the AbstractTwoFactorAuthenticationProvider.");
	    return new AuthenticationResponse();
    }
    
    @Override
    public List<Credential> getRequiredCredentials() {
    	logger.log(Level.INFO, "TDL getRequiredCredentials() called in AbstractTwoFactorAuthenticationProvider.");
	    return CREDENTIALS_LIST;
    }
}
