package edu.harvard.iq.dataverse.twofactor;

import edu.harvard.iq.dataverse.authorization.providers.builtin.BuiltinUser;
import java.io.Serializable;
import javax.persistence.EnumType;
import javax.persistence.Enumerated;

public class TwoFactorAuthenticationData implements Serializable {
    
    /**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	public enum Provider {
        DUO       
    }

    private BuiltinUser builtinUser;
    
    private String userInfo;
   
    private String ikey;
   
    private String skey;
    
    private String akey;
    
    @Enumerated(EnumType.STRING)
    private Provider provider;

    /**
     * This is only here because it has to be: "The class should have a no-arg,
     * public or protected constructor." Please use the constructor that takes
     * arguments.
     */
    @Deprecated
    public TwoFactorAuthenticationData() {
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

	public TwoFactorAuthenticationData(BuiltinUser aBuiltinUser) {
        builtinUser = aBuiltinUser;        
    }
   
    public BuiltinUser getBuiltinUser() {
        return builtinUser;
    }
}
