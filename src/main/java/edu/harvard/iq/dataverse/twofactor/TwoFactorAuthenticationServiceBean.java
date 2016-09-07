package edu.harvard.iq.dataverse.twofactor;

import edu.harvard.iq.dataverse.MailServiceBean;
import edu.harvard.iq.dataverse.authorization.providers.builtin.PasswordEncryption;
import edu.harvard.iq.dataverse.authorization.providers.builtin.BuiltinUser;
import edu.harvard.iq.dataverse.authorization.providers.builtin.BuiltinUserServiceBean;
import edu.harvard.iq.dataverse.util.SystemConfig;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.util.List;
import java.util.ResourceBundle;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ManagedProperty;
import javax.inject.Named;
import javax.persistence.EntityManager;
import javax.persistence.NoResultException;
import javax.persistence.NonUniqueResultException;
import javax.persistence.PersistenceContext;
import javax.persistence.TypedQuery;

import org.apache.commons.lang.RandomStringUtils;
import com.duosecurity.duoweb.DuoWeb;
import com.duosecurity.duoweb.DuoWebException;

@Stateless
@Named
public class TwoFactorAuthenticationServiceBean {

    private static final Logger logger = Logger.getLogger(TwoFactorAuthenticationServiceBean.class.getCanonicalName());
    
    private String ikey = new String();

    private String skey = new String();
    
    private String akey = new String();
    
    private String username = new String();      
    
    private String sig_response = new String();
    
    private BuiltinUser user;
    
    
    public String getSigRequest() {
    	if (username.length() > 0) {
    		return this.getSigRequestForUsername(this.username);
    	} else {
    		return "";
    	}
    }
    
    public String getSigRequestForUsername(String new_username) {
    	logger.log(Level.INFO, "In TwoFactorAuthenticationServiceBean.getSigRequest().");
    	
    	// Set Bean's username to the user trying to log in
    	// username = new_username;
    	
    	String sig_request = new String();
    	
    	// Retrieve values for ikey and skey from properties file
    	ikey = ResourceBundle.getBundle("TwoFactor").getString("ikey");
    	logger.log(Level.INFO, "Duo ikey: " + ikey);
        
    	skey = ResourceBundle.getBundle("TwoFactor").getString("skey");
        logger.log(Level.INFO, "Duo skey: " + skey);
        
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
    	logger.log(Level.INFO, "In TwoFactorAuthenticationServiceBean.verifyResponse().");
    	
    	if (sig_response.length() == 0) {
    		logger.log(Level.WARNING, "sig_response from Duoweb is empty.");
    	}
    	
    	if (username.length() == 0) {
    		logger.log(Level.WARNING, "The TwoFactorAuthenticationServiceBean's username is empty.");
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

	public void setUser(BuiltinUser user) {
		this.user = user;
	}
	
	public BuiltinUser getUser() {
		return user;
	}
	
}
