package edu.harvard.iq.dataverse.authorization.providers.twofactor.impl.duo;

import edu.harvard.iq.dataverse.DataverseServiceBean;
import edu.harvard.iq.dataverse.DataverseSession;
import edu.harvard.iq.dataverse.actionlogging.ActionLogServiceBean;
import edu.harvard.iq.dataverse.authorization.AuthenticationServiceBean;
import edu.harvard.iq.dataverse.authorization.providers.builtin.BuiltinUser;
import edu.harvard.iq.dataverse.authorization.providers.builtin.BuiltinUserServiceBean;

import java.util.ResourceBundle;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.faces.view.ViewScoped;
import javax.inject.Inject;
import javax.inject.Named;


@Stateless
@Named("foo")
public class DuoTwoFactorAuthenticationPage implements java.io.Serializable {

    private static final Logger logger = Logger.getLogger(DuoTwoFactorAuthenticationPage.class.getCanonicalName());

    private String username = new String();      
    
    private String host = new String();
    
    private String sig_request = new String();
        
    @EJB
    DuoTwoFactorAP duoTwoFactorAP;
    
    @EJB
    BuiltinUserServiceBean dataverseUserService;
    
    @EJB
    DataverseServiceBean dataverseService;    
    
    @EJB
    AuthenticationServiceBean authSvc;
    
    @Inject
    DataverseSession session;
    
    @EJB
    ActionLogServiceBean actionLogSvc;
        
    BuiltinUser user;

	public void init() {
		logger.log(Level.INFO, "In DuoTwoFactorAuthenticationPage.init().");
		
		// Retrieve host from properties file
		host = ResourceBundle.getBundle("TwoFactor").getString("host");
		logger.log(Level.INFO, "Duo host: " + host);		
		
		// Retrieve username from TwoFactorAuthenticationServiceBean
		username = duoTwoFactorAP.getUsername();
		if (username.length() > 0) {
			logger.log(Level.INFO, "TwoFactorAuthenticationServiceBean's username is not empty: " + username);
		}
		
		// Calculate sig_request in bean
		sig_request = duoTwoFactorAP.getToken();
		logger.log(Level.INFO, "in TwoFactorAuthenticationPage, Duo sig_request: " + sig_request);
	}	 
	
	/**
	 * Note: This method is no longer needed, since the verify response process now occurs in the 
	 * TwoFactorAuthenticationServlet.
	 * 
	 * @return
	 */
	public String verifyResponse() {
		logger.log(Level.INFO, "In TwoFactorAuthenticationPage.verifyResponse().");
		
		String authenticatedUsername = new String();
		
		String sig_response = "";
		
		authenticatedUsername = duoTwoFactorAP.verifyResponse(sig_response);
		// logger.log(Level.INFO, "in TwoFactorAuthenticationPage, Duo authenticatedUsername: " + authenticatedUsername);
		
		logger.log(Level.INFO, "Leaving TwoFactorAuthenticationPage.verifyResponse().");
		return authenticatedUsername;
	}
	
    public BuiltinUser getUser() {
        return user;
    }
	    
    public String getHost() {
		return host;
	}

	public void setHost(String host) {
		this.host = host;
	}

	public String getSig_request() {
		return sig_request;
	}

	public void setSig_request(String sig_request) {
		this.sig_request = sig_request;
	}

}
