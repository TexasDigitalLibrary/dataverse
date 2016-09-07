package edu.harvard.iq.dataverse.authorization;

/**
 * A result of an authentication attempt. May succeed, fail, or be in error.
 * Client code may use normal constructors, or use one of the static convenience 
 * methods ({@code createXXX}).
 * 
 * @author michael
 */
public class DuoWebAuthenticationResponse extends AuthenticationResponse {
    
    public static DuoWebAuthenticationResponse makeSuccess( String userId, AuthenticatedUserDisplayInfo disInf, String signRequest ) {
        return new DuoWebAuthenticationResponse()
               .setStatus( Status.SUCCESS )
               .setUserId(userId)
               .setUserDisplayInfo(disInf)
               .setSignRequest(signRequest);
    }
    
    public static DuoWebAuthenticationResponse makeBreakout( String userId, String redirectUrl ) {
        return new DuoWebAuthenticationResponse()
               .setStatus( Status.BREAKOUT )
               .setUserId(userId)
               .setMessage(redirectUrl);
    }
    
    public static DuoWebAuthenticationResponse makeFail( String message ) {
        return new DuoWebAuthenticationResponse()
               .setStatus( Status.FAIL )
               .setMessage(message);
    }
    
    public static DuoWebAuthenticationResponse makeError( String message, Throwable t ) {
        return new DuoWebAuthenticationResponse()
               .setStatus( Status.ERROR )
               .setMessage(message)
               .setError(t);
    }
    
    public enum Status { 
        /** Authentication succeeded - go on to the next phase */
        SUCCESS,
        
        /** UserProvider wants to take the user through some process. Go to link in the message field */
        BREAKOUT,
        
        /** Authentication failed (e.g wrong password) */
        FAIL,
        
        /** Can't authenticate (e.g database is down) */
        ERROR
    }
    
    private Status status;
    private String message;
    private String signRequest;
    private Throwable error;
    private String userId;
    private AuthenticatedUserDisplayInfo userDisplayInfo;

    /*public Status getStatus() {
        return status;
    }*/

    public DuoWebAuthenticationResponse setStatus(Status status) {
        this.status = status;
        return this;
    }

    public String getMessage() {
        return message;
    }

    public DuoWebAuthenticationResponse setMessage(String message) {
        this.message = message;
        return this;
    }

    public DuoWebAuthenticationResponse setSignRequest(String signRequest) {
        this.signRequest = signRequest;
        return this;
    }
    
    public Throwable getError() {
        return error;
    }

    public DuoWebAuthenticationResponse setError(Throwable error) {
        this.error = error;
        return this;
    }

    public String getUserId() {
        return userId;
    }

    public DuoWebAuthenticationResponse setUserId(String userId) {
        this.userId = userId;
        return this;
    }

    public AuthenticatedUserDisplayInfo getUserDisplayInfo() {
        return userDisplayInfo;
    }

    public DuoWebAuthenticationResponse setUserDisplayInfo(AuthenticatedUserDisplayInfo userDisplayInfo) {
        this.userDisplayInfo = userDisplayInfo;
        return this;
    }
    
    
    
}
