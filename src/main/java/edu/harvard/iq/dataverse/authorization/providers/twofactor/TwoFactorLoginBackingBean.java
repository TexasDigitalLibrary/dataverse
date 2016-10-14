package edu.harvard.iq.dataverse.authorization.providers.twofactor;

import edu.harvard.iq.dataverse.DataverseSession;
import edu.harvard.iq.dataverse.authorization.AuthenticationServiceBean;
import edu.harvard.iq.dataverse.settings.SettingsServiceBean;
import edu.harvard.iq.dataverse.util.StringUtil;
import java.io.Serializable;
import java.util.Comparator;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import static java.util.stream.Collectors.toList;
import javax.ejb.EJB;
import javax.inject.Named;
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
    private static final long STATE_TIMEOUT = 1000*60*15; // 15 minutes in msec
    private int responseCode;
    private String responseBody;
    private TwoFactorException error;
    private TwoFactorUserRecord twoFactorUser;
    
    @EJB
    AuthenticationServiceBean authenticationSvc;
    
    @EJB
    SettingsServiceBean settingsSvc;
    
    @Inject
    DataverseSession session;

    
    private AbstractTwoFactorAuthenticationProvider getIdpFromState( String state ) {
        String[] topFields = state.split("~",2);
        if ( topFields.length != 2 ) {
            logger.log(Level.INFO, "Wrong number of fields in state string", state);
            return null;
        }
        AbstractTwoFactorAuthenticationProvider idp = authenticationSvc.getTwoFactorProvider( topFields[0] );
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
    
    private String createState( AbstractTwoFactorAuthenticationProvider idp ) {
        if ( idp == null ) {
            throw new IllegalArgumentException("idp cannot be null");
        }
        String base = idp.getId() + "~" + System.currentTimeMillis() + "~" + (int)java.lang.Math.round( java.lang.Math.random()*1000 );
        
        String encrypted = StringUtil.encrypt(base, idp.clientSecret);
        final String state = idp.getId() + "~" + encrypted;
        return state;
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
    
    public List<AbstractTwoFactorAuthenticationProvider> getProviders() {
        return authenticationSvc.getTwoFactorProviders().stream()
                                .sorted(Comparator.comparing(AbstractTwoFactorAuthenticationProvider::getTitle))
                                .collect(toList());
    }
    
    public boolean isTwoFactorCallbackNotSet() {
        return settingsSvc.get("OAuth2CallbackUrl") == null;
    }
    
    public boolean isTwoFactorProvidersDefined() {
        return ! authenticationSvc.getTwoFactorProviders().isEmpty();
    }
}
