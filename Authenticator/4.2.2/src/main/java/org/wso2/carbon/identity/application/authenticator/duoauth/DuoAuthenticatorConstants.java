package org.wso2.carbon.identity.application.authenticator.duoauth;

import java.util.Random;

/**
 * Constants used by the DuoAuthenticator
 *
 */
public abstract class DuoAuthenticatorConstants{
	
	public static final String AUTHENTICATOR_NAME = "DuoAuthenticator";
	public static final String AUTHENTICATOR_FRIENDLY_NAME = "duo";

    public static final String IKEY = "IntegrationKey";
    public static final String SKEY = "SecretKey";
    public static final String ADMIN_IKEY = "AdminIntegrationKey";
    public static final String ADMIN_SKEY = "AdminSecretKey";
    public static final String HOST = "DuoHost";
    public static final String SIG_RESPONSE = "sig_response";

    public static final String MOBILE_CLAIM = "http://wso2.org/claims/mobile";
    public static final String API_PHONE = "/admin/v1/phones";
    public static final String DUO_NUMBER = "number";
    public static final String API_USER = "/admin/v1/users";
    public static final String DUO_USERNAME = "username";
    public static final String DUO_PHONES = "phones";

    public static final String RAND = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    public static String stringGenerator(){
        StringBuilder sb = new StringBuilder(42);
        Random rnd = new Random();

        for( int i = 0; i < 42; i++ ){
            sb.append(RAND.charAt(rnd.nextInt(DuoAuthenticatorConstants.RAND.length())));
        }
        return sb.toString();
    }
}
