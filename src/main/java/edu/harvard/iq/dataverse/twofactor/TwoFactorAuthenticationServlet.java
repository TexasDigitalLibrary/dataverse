package edu.harvard.iq.dataverse.twofactor;

import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.ejb.EJB;
import javax.faces.application.FacesMessage;
import javax.faces.component.UIViewRoot;
import javax.faces.context.FacesContext;
import javax.inject.Inject;
import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import edu.harvard.iq.dataverse.DataverseRequestServiceBean;
import edu.harvard.iq.dataverse.DataverseServiceBean;
import edu.harvard.iq.dataverse.DataverseSession;
import edu.harvard.iq.dataverse.authorization.AuthenticationResponse;
import edu.harvard.iq.dataverse.authorization.AuthenticationServiceBean;
import edu.harvard.iq.dataverse.authorization.providers.builtin.BuiltinAuthenticationProvider;
import edu.harvard.iq.dataverse.authorization.providers.builtin.BuiltinUser;
import edu.harvard.iq.dataverse.authorization.providers.builtin.BuiltinUserServiceBean;
import edu.harvard.iq.dataverse.authorization.users.AuthenticatedUser;

@WebServlet(name = "TwoFactorAuthenticationResponse", urlPatterns = {"/twofactorresponse"})
public class TwoFactorAuthenticationServlet extends HttpServlet {
	
	private static final Logger logger = Logger.getLogger(TwoFactorAuthenticationServlet.class.getCanonicalName());

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	@EJB
    TwoFactorAuthenticationServiceBean twoFactorAuthenticationService;
	
	@EJB
    BuiltinUserServiceBean dataverseUserService;
	
	@EJB
    AuthenticationServiceBean authSvc;
	
	@Inject
    DataverseRequestServiceBean dvRequestService;
	
	@EJB
	DataverseServiceBean dataverseService;
	 
	@Inject DataverseSession session;
	
	public TwoFactorAuthenticationServlet() {
		super();
	}

	public void init(ServletConfig config) throws ServletException {
	    super.init(config);
	}
	    
	protected void processRequest(HttpServletRequest request, HttpServletResponse response)
			throws ServletException, IOException {
		
		logger.log(Level.INFO, "In TwoFactorAuthenticationServlet.processRequest().");
		
		boolean error = false;
		
		String sig_response = request.getParameter("sig_response");
		logger.log(Level.INFO, "sig_response: " + sig_response);
        if (sig_response != null) {
        	String authenticatedUsername = new String();
        	
        	authenticatedUsername = twoFactorAuthenticationService.verifyResponse(sig_response);
        	
        	logger.log(Level.INFO, "authenticated username: " + authenticatedUsername);
        	
        	String username = twoFactorAuthenticationService.getUsername().trim();
        	logger.log(Level.INFO, "TwoFactorAuthenticationServiceBean.getUsername(): " + username);
        	
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
        	                	             	                	                	                	      
        	        response.sendRedirect(redirect);
        	        return;
        	    } else {
        			error = true;
        			// The usernames don't match. Need to redirect to login page and display a message
        			logger.log(Level.SEVERE, "The usernames don't match.");
        			
        		}
        	} else {
        		error = true;
        		logger.log(Level.SEVERE, "Either the username from the TwoFactorAuthenticationServiceBean or the authenticatedUsername from Duo is empty.");
        	}        	
        }
        
        if (error) {
        	FacesContext.getCurrentInstance().addMessage(null, new FacesMessage(FacesMessage.SEVERITY_FATAL, "Unable to verify user", "2FA failed"));			
        }
        
        logger.log(Level.INFO, "Leaving TwoFactorAuthenticationServlet.processRequest().");
        
        String redirect = "/loginpage.xhtml?alias=" + dataverseService.findRootDataverse().getAlias() + "&faces-redirect=true";
        logger.log(Level.INFO, "Redirecting user to: " + redirect);
        
        response.sendRedirect(redirect);
        return;
    }
	
	@Override
	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		processRequest(request, response);
	}

	@Override
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		logger.log(Level.INFO, "In TwoFactorAuthenticationServlet.doGet().");		
	}
}
