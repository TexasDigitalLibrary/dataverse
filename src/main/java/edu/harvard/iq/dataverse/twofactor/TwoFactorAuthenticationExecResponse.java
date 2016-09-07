package edu.harvard.iq.dataverse.twofactor;

public class TwoFactorAuthenticationExecResponse {

    private String userid;
    private TwoFactorAuthenticationData twoFactorAuthenticationData;

    public TwoFactorAuthenticationExecResponse(String userid, TwoFactorAuthenticationData twoFactorAuthenticationData) {
        this.userid = userid;
        this.twoFactorAuthenticationData = twoFactorAuthenticationData;
    }

    public String getUserid() {
        return userid;
    }

    public TwoFactorAuthenticationData getTwoFactorAuthenticationData() {
        return twoFactorAuthenticationData;
    }

    public void setTwoFactorAuthenticationData(TwoFactorAuthenticationData twoFactorAuthenticationData) {
        this.twoFactorAuthenticationData = twoFactorAuthenticationData;
    }

}
