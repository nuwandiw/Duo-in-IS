package org.wso2.carbon.identity.application.authenticator.duoauth;

import com.duosecurity.client.Http;
import com.duosecurity.duoweb.DuoWeb;
import com.duosecurity.duoweb.DuoWebException;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.LocalApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.config.ConfigurationFacade;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * Mobile based 2nd factor Authenticator
 * 
 */
public class DuoAuthenticator extends AbstractApplicationAuthenticator
		implements LocalApplicationAuthenticator {

	private static final long serialVersionUID = 4438354156955223654L;

	private static Log log = LogFactory.getLog(DuoAuthenticator.class);

    private String AKEY;

	@Override
	public boolean canHandle(HttpServletRequest request) {

		if (request.getParameter(DuoAuthenticatorConstants.SIG_RESPONSE) != null) {
			return true;
		}
		return false;
	}


	@Override
	protected void initiateAuthenticationRequest(HttpServletRequest request,
			HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException {

        String username = null;
        String loginPage = ConfigurationFacade.getInstance().getAuthenticationEndpointURL();
        AKEY = DuoAuthenticatorConstants.stringGenerator();

        try {

            for (int i = 1; i < context.getSequenceConfig().getStepMap().size(); i++) {
                if (context.getSequenceConfig().getStepMap().get(i).getAuthenticatedUser() != null &&
                        context.getSequenceConfig().getStepMap().get(i).getAuthenticatedAutenticator()
                                .getApplicationAuthenticator() instanceof LocalApplicationAuthenticator) {

                    username = context.getSequenceConfig().getStepMap().get(i).getAuthenticatedUser();
                }
            }


            String mobile = null;

            if (username != null) {
                UserStoreManager userStoreManager = PrivilegedCarbonContext.getThreadLocalCarbonContext()
                        .getUserRealm().getUserStoreManager();

                mobile = userStoreManager.getUserClaimValue(username, DuoAuthenticatorConstants.MOBILE_CLAIM, null);


                Object result = null;
                if (mobile != null) {

                    //Initiate Duo API request to get the user
                    Http duoRequest = new Http("GET", getAuthenticatorConfig().getParameterMap()
                            .get(DuoAuthenticatorConstants.HOST), DuoAuthenticatorConstants.API_USER);

                    duoRequest.addParam(DuoAuthenticatorConstants.DUO_USERNAME, username);

                    duoRequest.signRequest(getAuthenticatorConfig().getParameterMap()
                            .get(DuoAuthenticatorConstants.ADMIN_IKEY), getAuthenticatorConfig()
                            .getParameterMap().get(DuoAuthenticatorConstants.ADMIN_SKEY));

                    //Execute Duo API request
                    result = duoRequest.executeRequest();

                    if (result != null) {
                        if (log.isDebugEnabled()) {
                            log.debug(result.toString());
                        }
                        JSONArray array = new JSONArray(result.toString());

                        if (array.length() == 0) {
                            if (log.isDebugEnabled()) {
                                log.debug(
                                        "User is not registered in Duo. Authentication failed");
                            }

                            throw new AuthenticationFailedException(
                                    "User is not registered in Duo. Authentication failed");

                        } else {
                            JSONObject object = array.getJSONObject(0);
                            array = (JSONArray) object.get(DuoAuthenticatorConstants.DUO_PHONES);

                            if (array.length() == 0) {
                                if(log.isDebugEnabled()){
                                    log.debug("User doesn't have a valid mobile number for Duo Authentication");
                                }

                                throw new AuthenticationFailedException(
                                        "User doesn't have a valid mobile number for Duo Authentication");

                            } else {
                                String number = ((JSONObject) array.get(0))
                                        .getString(DuoAuthenticatorConstants.DUO_NUMBER);

                                if (number.equals(mobile)) {

                                    String sig_request = DuoWeb.signRequest(getAuthenticatorConfig()
                                            .getParameterMap().get(DuoAuthenticatorConstants.IKEY),
                                            getAuthenticatorConfig().getParameterMap()
                                            .get(DuoAuthenticatorConstants.SKEY), AKEY, username);

                                    //Redirect to Duo Authentication page
                                    response.sendRedirect(loginPage + "?authenticators=" + getName() + ":" +
                                            "LOCAL&type=duo&signreq=" + sig_request + "&sessionDataKey=" +
                                            context.getContextIdentifier() + "&duoHost=" + getAuthenticatorConfig()
                                            .getParameterMap().get(DuoAuthenticatorConstants.HOST));


                                } else {
                                    if(log.isDebugEnabled()){
                                        log.debug("Mismatch in mobile numbers");
                                    }

                                    throw new AuthenticationFailedException(
                                            "Authentication failed due to mismatch in mobile numbers");
                                }
                            }

                        }
                    }

                } else {
                    if(log.isDebugEnabled()){
                        log.debug("User doesn't have a mobile number. Authentication failed");
                    }
                    throw new AuthenticationFailedException("User doesn't have a mobile number for Duo Authentication");
                }
            }else{
                if(log.isDebugEnabled()){
                    log.debug("No local user found");
                }
                throw new AuthenticationFailedException("Duo authenticator failed to initialize");
            }

		} catch (UserStoreException e) {
            throw new AuthenticationFailedException(e.getMessage(), e);
        } catch (JSONException e) {
            throw new AuthenticationFailedException(e.getMessage(), e);
        } catch (UnsupportedEncodingException e) {
            throw new AuthenticationFailedException(e.getMessage(), e);
        } catch (IOException e) {
            throw new AuthenticationFailedException(e.getMessage(), e);
        } catch (Exception e) {
            throw new AuthenticationFailedException(e.getMessage(), e);
        }
    }

	@Override
	protected void processAuthenticationResponse(HttpServletRequest request,
			HttpServletResponse response, AuthenticationContext context)
			throws AuthenticationFailedException {

        String username = null;

		try {
            username = DuoWeb.verifyResponse(getAuthenticatorConfig().getParameterMap()
                    .get(DuoAuthenticatorConstants.IKEY),getAuthenticatorConfig().getParameterMap()
                    .get(DuoAuthenticatorConstants.SKEY),AKEY, request
                    .getParameter(DuoAuthenticatorConstants.SIG_RESPONSE));

            if(log.isDebugEnabled()){
                log.debug("Authenticated user: "+username);
            }

		} catch (DuoWebException e) {
            throw new AuthenticationFailedException(e.getMessage(),e);
        } catch (NoSuchAlgorithmException e) {
            throw new AuthenticationFailedException(e.getMessage(),e);
        } catch (InvalidKeyException e) {
            throw new AuthenticationFailedException(e.getMessage(),e);
        } catch (IOException e) {
            throw new AuthenticationFailedException(e.getMessage(),e);
        }

		context.setSubject(username);
	}

	@Override
	public String getContextIdentifier(HttpServletRequest request) {
		return request.getParameter("sessionDataKey");
	}

	@Override
	public String getFriendlyName() {
		return DuoAuthenticatorConstants.AUTHENTICATOR_FRIENDLY_NAME;
	}

	@Override
	public String getName() {
		return DuoAuthenticatorConstants.AUTHENTICATOR_NAME;
	}
}
