package edu.harvard.iq.dataverse.authorization.providers.twofactor.providers;

import edu.harvard.iq.dataverse.authorization.AuthenticatedUserDisplayInfo;
import edu.harvard.iq.dataverse.authorization.AuthenticationRequest;
import edu.harvard.iq.dataverse.authorization.AuthenticationResponse;
import edu.harvard.iq.dataverse.authorization.providers.builtin.BuiltinUser;
import edu.harvard.iq.dataverse.authorization.providers.builtin.BuiltinUserServiceBean;
import edu.harvard.iq.dataverse.authorization.providers.builtin.PasswordEncryption;
import edu.harvard.iq.dataverse.authorization.providers.twofactor.AbstractTwoFactorAuthenticationProvider;
import edu.harvard.iq.dataverse.passwordreset.PasswordResetException;
import edu.harvard.iq.dataverse.twofactor.TwoFactorAuthenticationServiceBean;

import java.io.IOException;
import java.io.StringReader;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ResourceBundle;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonReader;

import org.apache.commons.lang.RandomStringUtils;

import com.duosecurity.duoweb.DuoWeb;
import com.duosecurity.duoweb.DuoWebException;

/**
 *
 * @author Nicholas
 */
public class DuoWebTwoFactorIdp extends AbstractTwoFactorAuthenticationProvider {

	private static final Logger logger = Logger.getLogger(TwoFactorAuthenticationServiceBean.class.getCanonicalName());
	
	private String title = "Duo Two-Factor Authentication";
	// private String id = "duo";
	
	private String ikey = new String();

	private String skey = new String();
	   
	private String hostname = new String();
	
	private String akey = new String();
	    
	private String username = new String();      
	 
	private String sig_response = new String();
	
	final BuiltinUserServiceBean bean;
	
	public DuoWebTwoFactorIdp(BuiltinUserServiceBean aBean) {
		super(aBean);
		this.bean = aBean;
	
		// Retrieve values for title, ikey and skey from properties file
    	title = ResourceBundle.getBundle("TwoFactor").getString("title");
    	logger.log(Level.INFO, "Duo title: " + title);
        
    	ikey = ResourceBundle.getBundle("TwoFactor").getString("ikey");
    	logger.log(Level.INFO, "Duo ikey: " + ikey);
        
    	skey = ResourceBundle.getBundle("TwoFactor").getString("skey");
        logger.log(Level.INFO, "Duo skey: " + skey);
        
        hostname = ResourceBundle.getBundle("TwoFactor").getString("hostname");
    	logger.log(Level.INFO, "Duo hostname: " + hostname);        
	}

    @Override
    public AuthenticationResponse authenticate( AuthenticationRequest authReq ) {
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
        	// Set username in 2FA bean
        	logger.log(Level.INFO, "Setting TwoFactorAuthenticationServiceBean.username.");
        	logger.log(Level.INFO, "u.getUserName(): " + u.getUserName());
        	bean.setUsername(u.getUserName());

        	logger.log(Level.INFO, "Redirecting to two factor authentication page...");
            String twoFactorAuthenticationPage = "twofactorauthentication.xhtml?faces-redirect=true";    		           
            return AuthenticationResponse.makeBreakout(u.getUserName(), twoFactorAuthenticationPage);
            
            // return AuthenticationResponse.makeSuccess(u.getUserName(), u.getDisplayInfo());
        }
   }
    
    public String getSigRequestForUsername(String new_username) {
    	logger.log(Level.INFO, "In DuoWebTwoFactorIdp.getSigRequest().");
    	
    	// Set current username
    	username = new_username;
    	
    	String sig_request = new String();

        // Generate random alphanumeric string for the akey
        akey = RandomStringUtils.randomAlphanumeric(40);
        logger.log(Level.INFO, "Duo Created akey: " + akey);
        
        System.out.println("Calling DuoWeb.signRequest...");
        logger.log(Level.INFO, "Going to DuoWeb.signRequest...");
		        
        sig_request = DuoWeb.signRequest(ikey, skey, akey, new_username);
        
		System.out.println("Back from DuoWeb.signRequest.");
		logger.log(Level.INFO, "Back from DuoWeb.signRequest. sig_request: " + sig_request);
    	
    	return sig_request;
    }

    /**	
	 * 
	 * @return String
	 */
    public String verifyResponse(String sig_response) {
    	logger.log(Level.INFO, "In DuoWebTwoFactorIdp.verifyResponse().");
    	
    	if (sig_response.length() == 0) {
    		logger.log(Level.WARNING, "sig_response from Duoweb is empty.");
    	}
    	
    	if (username.length() == 0) {
    		logger.log(Level.WARNING, "The DuoWebTwoFactorIdp's username is empty.");
    	}    	
    	
        String authenticatedUsername = new String();
        	
        logger.log(Level.INFO, "this.getIkey(): " + this.getIkey());
        logger.log(Level.INFO, "this.getSkey(): " + this.getSkey());
        logger.log(Level.INFO, "this.getAkey(): " + this.getAkey());
        
        try {
        	authenticatedUsername = DuoWeb.verifyResponse(this.getIkey(), this.getSkey(), this.getAkey(), sig_response);
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
    
    
	public String getIkey() {
		return ikey;
	}


	public void setIkey(String ikey) {
		this.ikey = ikey;
	}


	public String getSkey() {
		return skey;
	}


	public void setSkey(String skey) {
		this.skey = skey;
	}


	public String getAkey() {
		return akey;
	}


	public void setAkey(String akey) {
		this.akey = akey;
	}

	public String getSig_response() {
		return sig_response;
	}

	public void setSig_response(String sig_response) {
		this.sig_response = sig_response;
	}	

	public String getUsername() {		
		return username;
	}
	
	public void setUsername(String username) {
		logger.log(Level.INFO, "In TwoFactorAuthenticationServiceBean.setUsername().");
		logger.log(Level.INFO, "this.username: " + this.username);
		this.username = username;
	}
}
