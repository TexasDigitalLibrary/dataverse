package edu.harvard.iq.dataverse.authorization.providers.twofactor;

/**
 * Captures errors thrown during the OAuth process.
 * @author Nicholas
 */
public class TwoFactorException extends Exception {
    
    private final int httpReturnCode;
    private final String messageBody;

    public TwoFactorException(int httpReturnCode, String messageBody, String message) {
        super(message);
        this.httpReturnCode = httpReturnCode;
        this.messageBody = messageBody;
    }

    public TwoFactorException(int httpReturnCode, String messageBody, String message, Throwable cause) {
        super(message, cause);
        this.httpReturnCode = httpReturnCode;
        this.messageBody = messageBody;
    }

    public int getHttpReturnCode() {
        return httpReturnCode;
    }

    public String getMessageBody() {
        return messageBody;
    }

}