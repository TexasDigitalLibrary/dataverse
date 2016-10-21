package edu.harvard.iq.dataverse.authorization.providers.twofactor.impl.duo;

import edu.harvard.iq.dataverse.authorization.AuthenticationRequest;
import edu.harvard.iq.dataverse.authorization.AuthenticationResponse;
import edu.harvard.iq.dataverse.authorization.providers.builtin.BuiltinUser;
import edu.harvard.iq.dataverse.authorization.providers.builtin.BuiltinUserServiceBean;
import edu.harvard.iq.dataverse.authorization.providers.builtin.PasswordEncryption;
import edu.harvard.iq.dataverse.authorization.providers.twofactor.AbstractTwoFactorAuthenticationProvider;
import edu.harvard.iq.dataverse.passwordreset.PasswordResetException;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.ejb.Stateful;
import javax.inject.Named;

import org.apache.commons.lang.RandomStringUtils;

import com.duosecurity.duoweb.DuoWeb;
import com.duosecurity.duoweb.DuoWebException;

/**
 *
 * @author Nicholas
 */

@Named(value = "DuoTwoFactorAP")
public class DuoTwoFactorAP extends AbstractTwoFactorAuthenticationProvider {

	private static final Logger logger = Logger.getLogger(DuoTwoFactorAP.class.getCanonicalName());
	
	private String title = "Duo Two-Factor Authentication";
	// private String id = "duo";	

	private String akey = new String();
	 
	private String token = new String(); // sig_request in Duo terminology
	
	private String response = new String(); // sig_response in Duo terminology
	
	final BuiltinUserServiceBean bean;
	
	public DuoTwoFactorAP(BuiltinUserServiceBean aBean, String clientId, String clientSecret, String hostname) {
		super(aBean);
		this.bean = aBean;
		this.clientId = clientId;
		this.clientSecret = clientSecret;
		this.hostname = hostname;
	
    	logger.log(Level.INFO, "Duo clientId: " + clientId);
        logger.log(Level.INFO, "Duo clientSecret: " + clientSecret);
    	logger.log(Level.INFO, "Duo hostname: " + hostname);    	   
	}
	
    @Override
    public AuthenticationResponse authenticate( AuthenticationRequest authReq ) {
    	logger.log(Level.INFO, "We made it to DuoWebTwoFactorAP authenticate() method!!!");
        BuiltinUser u = bean.findByUsernameOrEmail(authReq.getCredential(KEY_USERNAME_OR_EMAIL) );
        if ( u == null ) return AuthenticationResponse.makeFail("Bad username, email address, or password");
        
        boolean userAuthenticated = PasswordEncryption.getVersion(u.getPasswordEncryptionVersion())
                                            .check(authReq.getCredential(KEY_PASSWORD), u.getEncryptedPassword() );
        if ( ! userAuthenticated ) {
            return AuthenticationResponse.makeFail("Bad username or password");
        }
                
        if ( u.getPasswordEncryptionVersion() < PasswordEncryption.getLatestVersionNumber() ) {
            try {
                String passwordResetUrl = bean.requestPasswordUpgradeLink(u);
                
                return AuthenticationResponse.makeBreakout(u.getUserName(), passwordResetUrl);
            } catch (PasswordResetException ex) {
                return AuthenticationResponse.makeError("Error while attempting to upgrade password", ex);
            }
        } else {
        	// Set username in 2FA AP
        	logger.log(Level.INFO, "Setting DuoWebTwoFactorAP.username.");
        	logger.log(Level.INFO, "u.getUserName(): " + u.getUserName());
        	this.setUsername(u.getUserName());
        	
        	logger.log(Level.INFO, "Redirecting to Duo two-factor authentication page...");
            String duoAuthenticationPage = "two-factor/duo.xhtml?faces-redirect=true";    		           
            return AuthenticationResponse.makeBreakout(u.getUserName(), duoAuthenticationPage);
        }
    }
    
	@Override
    public String createToken(String username) {
    	logger.log(Level.INFO, "TDL In DuoWebTwoFactorIdp.createToken(username).");
    	
    	String token = new String();

    	// Generate random alphanumeric string for the akey
        akey = RandomStringUtils.randomAlphanumeric(40);
        logger.log(Level.INFO, "TDL Duo Created akey: " + akey);
        
        System.out.println("Calling DuoWeb.signRequest...");
        logger.log(Level.INFO, "TDL Going to DuoWeb.signRequest...");
		        
        token = DuoWeb.signRequest(clientId, clientSecret, akey, username);
        
		System.out.println("Back from DuoWeb.signRequest.");
		logger.log(Level.INFO, "TDL Back from DuoWeb.signRequest. sig_request: " + token);
    	
    	return token;
    }

    /**		
	 * @return String
	 */
	@Override
    public String verifyResponse(String response) {
    	logger.log(Level.INFO, "TDL In DuoWebTwoFactorIdp.verifyResponse().");
    	
    	if (response.length() == 0) {
    		logger.log(Level.WARNING, "TDL Response (sig_response) from Duoweb is empty.");
    	}	
    	
        String authenticatedUsername = new String();
        	
        logger.log(Level.INFO, "TDL this.clientId: " + this.getClientId());
        logger.log(Level.INFO, "TDL this.clientSecret: " + this.getClientSecret());
        logger.log(Level.INFO, "TDL this.akey: " + this.getAkey());
        
        try {
        	authenticatedUsername = DuoWeb.verifyResponse(clientId, clientSecret, akey, response);
        	authenticatedUsername = authenticatedUsername.trim();
        } catch (InvalidKeyException e) {
        	logger.log(Level.SEVERE, e.getMessage());
        	e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
        	logger.log(Level.SEVERE, e.getMessage());
        	e.printStackTrace();
        } catch (DuoWebException e) {
        	logger.log(Level.SEVERE, e.getMessage());
        	e.printStackTrace();
        } catch (IOException e) {
        	logger.log(Level.SEVERE, e.getMessage());
        	e.printStackTrace();
        }
    	
    	return authenticatedUsername;
    }
    

    public String getTitle() {
		return title;
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

	public String getAkey() {
		return akey;
	}

	public void setAkey(String akey) {
		this.akey = akey;
	}

	public String getHostname() {
		return hostname;
	}

	public void setHostname(String hostname) {
		this.hostname = hostname;
	}

	public String getToken() {
		return token;
	}

	public void setToken(String token) {
		this.token = token;
	}	

	public String getUsername() {		
		return username;
	}
	
	public void setUsername(String username) {
		logger.log(Level.INFO, "In DuoWebTwoFactorAP.setUsername().");
		logger.log(Level.INFO, "this.username: " + this.username);
		this.username = username;
	}
}
