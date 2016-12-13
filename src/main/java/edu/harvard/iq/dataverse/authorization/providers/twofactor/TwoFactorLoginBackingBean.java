package edu.harvard.iq.dataverse.authorization.providers.twofactor;

import edu.harvard.iq.dataverse.DataverseRequestServiceBean;
import edu.harvard.iq.dataverse.DataverseServiceBean;
import edu.harvard.iq.dataverse.DataverseSession;
import edu.harvard.iq.dataverse.authorization.AuthenticatedUserDisplayInfo;
import edu.harvard.iq.dataverse.authorization.AuthenticationProvider;
import edu.harvard.iq.dataverse.authorization.AuthenticationProviderDisplayInfo;
import edu.harvard.iq.dataverse.authorization.AuthenticationRequest;
import edu.harvard.iq.dataverse.authorization.AuthenticationResponse;
import edu.harvard.iq.dataverse.authorization.AuthenticationServiceBean;
import edu.harvard.iq.dataverse.authorization.CredentialsAuthenticationProvider;
import edu.harvard.iq.dataverse.authorization.UserRecordIdentifier;
import edu.harvard.iq.dataverse.authorization.exceptions.AuthenticationFailedException;
import edu.harvard.iq.dataverse.authorization.providers.builtin.BuiltinAuthenticationProvider;
import edu.harvard.iq.dataverse.authorization.users.AuthenticatedUser;
import edu.harvard.iq.dataverse.settings.SettingsServiceBean;
import edu.harvard.iq.dataverse.util.BundleUtil;
import edu.harvard.iq.dataverse.util.JsfHelper;
import edu.harvard.iq.dataverse.util.StringUtil;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.Comparator;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import static edu.harvard.iq.dataverse.util.JsfHelper.JH;
import static java.util.stream.Collectors.toList;
import javax.ejb.EJB;
import javax.inject.Named;
import javax.servlet.http.HttpServletRequest;
import javax.faces.application.FacesMessage;
import javax.faces.context.FacesContext;
import javax.faces.event.AjaxBehaviorEvent;
import javax.faces.view.ViewScoped;
import javax.inject.Inject;

/**
 * Backing bean of the 2fa login process. Used from the login page and the callback page.
 * 
 * @author Nicholas
 */
@Named(value = "TwoFactorPage")
@ViewScoped
public class TwoFactorLoginBackingBean implements Serializable {
    
    private static final Logger logger = Logger.getLogger(TwoFactorLoginBackingBean.class.getName());
    
    public static class FilledCredential {
        CredentialsAuthenticationProvider.Credential credential;
        String value;

        public FilledCredential() {
        }

        public FilledCredential(CredentialsAuthenticationProvider.Credential credential, String value) {
            this.credential = credential;
            this.value = value;
        }
        
        public CredentialsAuthenticationProvider.Credential getCredential() {
            return credential;
        }

        public void setCredential(CredentialsAuthenticationProvider.Credential credential) {
            this.credential = credential;
        }

        public String getValue() {
            return value;
        }

        public void setValue(String value) {
            this.value = value;
        }        
    }
    
    private static final long STATE_TIMEOUT = 1000*60*15; // 15 minutes in msec
    private int responseCode;
    private String responseBody;
    private TwoFactorException error;
    private TwoFactorUserRecord twoFactorUser;
    
    @EJB
    AuthenticationServiceBean authenticationSvc;
    
    @EJB
    DataverseServiceBean dataverseService;
    
    @EJB
    SettingsServiceBean settingsSvc;
    
    @EJB
    AuthenticationServiceBean authSvc;
    
    @Inject
    DataverseRequestServiceBean dvRequestService;
    
    @Inject
    DataverseSession session;

    // private String credentialsAuthProviderId;
    
    private List<FilledCredential> filledCredentials;
    
    private String redirectPage = "dataverse.xhtml";
    
    public String getCallbackUrl() {
        return settingsSvc.get("TwoFactorCallbackUrl", "http://localhost:8080/two-factor/callback.xhtml");
    }
    
    public void init() {
    	logger.log(Level.INFO, "TDL Init() function of TwoFactorLoginBackingBean.");
        /*Iterator<String> credentialsIterator = authSvc.getTwoFactorAuthenticationProviderIdsOfType( CredentialsAuthenticationProvider.class ).iterator();
        if ( credentialsIterator.hasNext() ) {
        	logger.log(Level.INFO, "TDL TwoFactor credentialsIterator has a value.");
            setCredentialsAuthProviderId(credentialsIterator.next());
        }
        resetFilledCredentials(null);*/
    }
        
    /*public boolean isAuthenticationProvidersAvailable() {
        return ! authSvc.getAuthenticationProviderIds().isEmpty();
    }*/
    
    /*public List<AuthenticationProviderDisplayInfo> listCredentialsAuthenticationProviders() {
        List<AuthenticationProviderDisplayInfo> infos = new LinkedList<>();
        for ( String id : authSvc.getTwoFactorAuthenticationProviderIdsOfType( CredentialsAuthenticationProvider.class ) ) {
            AuthenticationProvider authenticationProvider = authSvc.getAuthenticationProvider(id);
            infos.add( authenticationProvider.getInfo());
        }
        return infos;
    }*/
    
    /*public List<AuthenticationProviderDisplayInfo> listAuthenticationProviders() {
        List<AuthenticationProviderDisplayInfo> infos = new LinkedList<>();
        for ( String id : authSvc.getTwoFactorAuthenticationProviderIds() ) {
            AuthenticationProvider authenticationProvider = authSvc.getAuthenticationProvider(id);
            infos.add( authenticationProvider.getInfo());
        }
        return infos;
    }*/
   
    /*public CredentialsAuthenticationProvider selectedCredentialsProvider() {
        // return (CredentialsAuthenticationProvider) authSvc.getAuthenticationProvider(getCredentialsAuthProviderId());
    	return (CredentialsAuthenticationProvider) authSvc.getTwoFactorAuthenticationProvider(getCredentialsAuthProviderId());
    }*/
    
    public boolean validatePassword(String username, String password) {
        return false;
    }

    private AbstractTwoFactorAuthenticationProvider getIdpFromState( String state ) {
        String[] topFields = state.split("~",2);
        if ( topFields.length != 2 ) {
            logger.log(Level.INFO, "Wrong number of fields in state string", state);
            return null;
        }
        AbstractTwoFactorAuthenticationProvider idp = authenticationSvc.getTwoFactorAuthenticationProvider( topFields[0] );
        if ( idp == null ) { 
            logger.log(Level.INFO, "Can''t find IDP ''{0}''", topFields[0]);
            return null;
        }
        String raw = StringUtil.decrypt(topFields[1], idp.clientSecret);
        String[] stateFields = raw.split("~", -1);
        if ( idp.getId().equals(stateFields[0]) ) {
            long timeOrigin = Long.parseLong(stateFields[1]);
            long timeDifference = System.currentTimeMillis() - timeOrigin;
            if ( timeDifference > 0 && timeDifference < STATE_TIMEOUT ) {
                return idp;
            } else {
                logger.info("State timeout");
                return null;
            }
        } else {
            logger.log(Level.INFO, "Invalid id field: ''{0}''", stateFields[0]);
            return null;
        }
    }
    
    /*private AbstractTwoFactorAuthenticationProvider getCurrentTwoFactorAuthenticationProvider() {
    	if (credentialsAuthProviderId.isEmpty()) {
    		return null;
    	}
    	
    	AbstractTwoFactorAuthenticationProvider idp = authenticationSvc.getTwoFactorAuthenticationProvider(credentialsAuthProviderId);
    	
    	return idp;
    }*/
    
    public String getTitle(String idpId) {
    	logger.log(Level.INFO, "TDL In getTitle(idpId) of TwoFactorLoginBackingBean: " + idpId);
    	String title = new String("Two Factor Authentication");
    	
    	AbstractTwoFactorAuthenticationProvider idp = authenticationSvc.getTwoFactorAuthenticationProvider(idpId);
    	if (idp != null) {
    		logger.log(Level.INFO, "TDL Found 2fa provider: " + idp.getTitle());
    		title = idp.getTitle();
    		logger.log(Level.INFO, "TDL 2fa provider's title: " + title);
    	} else {
    		 logger.log(Level.INFO, "TDL Unable to find 2fa provider.");
    	}
    	
    	return title;
    }    
    
    public String getHostname(String idpId) {
    	logger.log(Level.INFO, "TDL In getHostname(idpId) of TwoFactorLoginBackingBean: " + idpId);
    	String hostname = new String();
    	
    	AbstractTwoFactorAuthenticationProvider idp = authenticationSvc.getTwoFactorAuthenticationProvider(idpId);
    	if (idp != null) {
    		logger.log(Level.INFO, "TDL Found 2fa provider: " + idp.getTitle());
    		hostname = idp.getHostname();
    		logger.log(Level.INFO, "TDL 2fa provider's hostname: " + hostname);
    	} else {
    		 logger.log(Level.INFO, "TDL Unable to find 2fa provider.");
    	}
    	
    	return hostname;
    }

    public String getToken(String idpId, String username) {
    	logger.log(Level.INFO, "TDL In getToken(idpId) of TwoFactorLoginBackingBean: " + idpId);
    	String token = new String();
    	
    	AbstractTwoFactorAuthenticationProvider idp = authenticationSvc.getTwoFactorAuthenticationProvider(idpId);
    	if (idp != null) {
    		logger.log(Level.INFO, "TDL Found 2fa provider: " + idp.getTitle());
    		token = idp.createToken(username);
    		logger.log(Level.INFO, "TDL 2fa provider's token: " + token);
    	} else {
    		 logger.log(Level.INFO, "TDL Unable to find 2fa provider.");
    	}
    	
    	return token;
    }
    
    public String verifyResponse(String idpId, String response) {
    	logger.log(Level.INFO, "TDL In verifyResponse(idpId) of TwoFactorLoginBackingBean: " + response);
    	String authenticatedUser = new String();
    	
    	AbstractTwoFactorAuthenticationProvider idp = authenticationSvc.getTwoFactorAuthenticationProvider(idpId);
    	if (idp != null) {
    		logger.log(Level.INFO, "TDL Found 2fa provider: " + idp.getTitle());
    		authenticatedUser = idp.verifyResponse(response);
    		logger.log(Level.INFO, "TDL 2fa provider's authenticatedUser: " + authenticatedUser);
    	} else {
    		 logger.log(Level.INFO, "TDL Unable to find 2fa provider.");
    	}
    	
    	return authenticatedUser;
    	
    }
    
    public void exchangeCodeForToken() throws IOException {
        HttpServletRequest req = (HttpServletRequest) FacesContext.getCurrentInstance().getExternalContext().getRequest();
        
        logger.log(Level.INFO, "In TwoFactorLoginBackingBean.exchangeCodeForToken().");
        
        final String code = req.getParameter("code");
		logger.log(Level.INFO, "response code: " + code);
		
		final String idpId = req.getParameter("provider");
		logger.log(Level.INFO, "2fa provider: " + idpId);
			
		final String foo = req.getParameter("foo");
		logger.log(Level.INFO, "2fa foo: " + foo);
		
		logger.log(Level.INFO, "2fa req object: " + req.toString());
		
		Enumeration pnames = req.getParameterNames();
		while (pnames.hasMoreElements()) {
			String parameterName = pnames.nextElement().toString();
			logger.log(Level.INFO,  "parameter name: " + parameterName);
			logger.log(Level.INFO,  "parameter value: " + req.getParameter(parameterName));			
		}
		
        if ((code != null) && (!code.trim().isEmpty())) {
        	String authenticatedUsername = new String();
        	
        	AbstractTwoFactorAuthenticationProvider idp = authenticationSvc.getTwoFactorAuthenticationProvider(idpId);
        	if (idp != null) {
        		authenticatedUsername = idp.verifyResponse(code);
        	
        		logger.log(Level.INFO, "authenticated username: " + authenticatedUsername);
        	
        		String username = idp.getUsername().trim();
        		logger.log(Level.INFO, "TwoFactorLoginBackingBean.getUsername(): " + username);
        	
        		if ((authenticatedUsername.length() > 0) && (username.length() > 0)) {
        			if (username.equals(authenticatedUsername)) {
        				// The user is valid
        				logger.log(Level.INFO, "The user is valid.");
        			        			
        				// Retrieve AuthenticatedUser object and store in Session so the user is logged in
        				String builtinAuthProviderId = BuiltinAuthenticationProvider.PROVIDER_ID;
        				logger.log(Level.INFO, "builtinAuthProviderId: " + builtinAuthProviderId);
        				AuthenticatedUser au = authSvc.lookupUser(builtinAuthProviderId, authenticatedUsername);
        				logger.log(Level.INFO, "AuthenticatedUser userIdentifier: " + au.getUserIdentifier());        	        
        	        	session.setUser(au);
        	        
        	        	logger.log(Level.INFO, "Finished setting user in session.");
        	        
        	        	// Redirect to the root dataverse
        	        	String redirect = "/dataverse.xhtml?alias=" + dataverseService.findRootDataverse().getAlias() + "&faces-redirect=true";
        	        	logger.log(Level.INFO, "Redirecting user to: " + redirect);
        	                	             	           
        	        	FacesContext.getCurrentInstance().getExternalContext().redirect(redirect);
        			} else {        				
        				// The usernames don't match. Need to redirect to login page and display a message
        				logger.log(Level.SEVERE, "The usernames don't match.");
        			
        			}
        		} else {        			
        			logger.log(Level.SEVERE, "Either the username from the TwoFactorAuthenticationServiceBean or the authenticatedUsername from Duo is empty.");
        		}        	
        	}
        }
    }
    
    /*public String login() {
    	AuthenticationRequest authReq = new AuthenticationRequest();
        List<FilledCredential> filledCredentialsList = getFilledCredentials();
        
        if ( filledCredentialsList == null ) {
            logger.info("Credential list is null!");
            return null;
        }
        
        for ( FilledCredential fc : filledCredentialsList ) {
            if(fc.getValue()==null || fc.getValue().isEmpty()){
                JH.addMessage(FacesMessage.SEVERITY_ERROR, "Please enter a "+fc.getCredential().getTitle());
            }
            authReq.putCredential(fc.getCredential().getTitle(), fc.getValue());
        }
        authReq.setIpAddress( dvRequestService.getDataverseRequest().getSourceAddress() );
        
        try {
            AuthenticatedUser r = authSvc.authenticate(credentialsAuthProviderId, authReq);
            logger.log(Level.FINE, "User authenticated: {0}", r.getEmail());
            session.setUser(r);
            
            if ("dataverse.xhtml".equals(redirectPage)) {
                redirectPage = redirectPage + "&alias=" + dataverseService.findRootDataverse().getAlias();
            }
            
            try {            
                redirectPage = URLDecoder.decode(redirectPage, "UTF-8");
            } catch (UnsupportedEncodingException ex) {
                Logger.getLogger(TwoFactorLoginBackingBean.class.getName()).log(Level.SEVERE, null, ex);
                redirectPage = "dataverse.xhtml&alias=" + dataverseService.findRootDataverse().getAlias();
            }

            logger.log(Level.FINE, "Sending user to = {0}", redirectPage);

            return redirectPage + (!redirectPage.contains("?") ? "?" : "&") + "faces-redirect=true";

            
        } catch (AuthenticationFailedException ex) {
            AuthenticationResponse response = ex.getResponse();
            switch ( response.getStatus() ) {
                case FAIL:
                    JsfHelper.addErrorMessage(BundleUtil.getStringFromBundle("login.builtin.invalidUsernameEmailOrPassword"));
                    return null;
                case ERROR:

                    JsfHelper.addErrorMessage(BundleUtil.getStringFromBundle("login.error"));
                    logger.log( Level.WARNING, "Error logging in: " + response.getMessage(), response.getError() );
                    return null;
                case BREAKOUT:
                    return response.getMessage();
                default:
                    JsfHelper.addErrorMessage("INTERNAL ERROR");
                    return null;
            }
        }
    } */
    
    /*public String getCredentialsAuthProviderId() {
        return credentialsAuthProviderId;
    }*/
    
    /*public void resetFilledCredentials( AjaxBehaviorEvent event) {
        if ( selectedCredentialsProvider()==null ) return;
        
        filledCredentials = new LinkedList<>();
        for ( CredentialsAuthenticationProvider.Credential c : selectedCredentialsProvider().getRequiredCredentials() ) {
            filledCredentials.add( new FilledCredential(c, ""));
        }
    }*/
    
    /*public void setCredentialsAuthProviderId(String authProviderId) {
        this.credentialsAuthProviderId = authProviderId;
    }*/

    public List<FilledCredential> getFilledCredentials() {
        return filledCredentials;
    }

    public void setFilledCredentials(List<FilledCredential> filledCredentials) {
        this.filledCredentials = filledCredentials;
    }

    public boolean isMultipleProvidersAvailable() {
        return authSvc.getAuthenticationProviderIds().size()>1;
    }
    
    public String getRedirectPage() {
        return redirectPage;
    }

    public void setRedirectPage(String redirectPage) {
        this.redirectPage = redirectPage;
    }
    
    public String getResponseBody() {
        return responseBody;
    }

    public int getResponseCode() {
        return responseCode;
    }

    public TwoFactorUserRecord getUser() {
        return twoFactorUser;
    }

    public TwoFactorException getError() {
        return error;
    }
    
    public boolean isInError() {
        return error!=null;
    }
    
    private String createState( AbstractTwoFactorAuthenticationProvider idp ) {
        if ( idp == null ) {
            throw new IllegalArgumentException("idp cannot be null");
        }
        String base = idp.getId() + "~" + System.currentTimeMillis() + "~" + (int)java.lang.Math.round( java.lang.Math.random()*1000 );
        
        String encrypted = StringUtil.encrypt(base, idp.clientSecret);
        final String state = idp.getId() + "~" + encrypted;
        return state;
    }
    
    public List<AbstractTwoFactorAuthenticationProvider> getProviders() {
        return authenticationSvc.getTwoFactorAuthenticationProviders().stream()
                                .sorted(Comparator.comparing(AbstractTwoFactorAuthenticationProvider::getTitle))
                                .collect(toList());
    }
    
    public boolean isTwoFactorCallbackNotSet() {
        return settingsSvc.get("TwoFactorCallbackUrl") == null;
    }
    
    public boolean isTwoFactorProvidersDefined() {
    	logger.log(Level.INFO, "TDL Count twoFactorProviders: ", authenticationSvc.getTwoFactorAuthenticationProviders().size());
    	if (authenticationSvc.getTwoFactorAuthenticationProviders().isEmpty()) {
    		logger.log(Level.INFO, "twoFactorProviders is empty!");
    	}
        return ! authenticationSvc.getTwoFactorAuthenticationProviders().isEmpty();
    }
}
