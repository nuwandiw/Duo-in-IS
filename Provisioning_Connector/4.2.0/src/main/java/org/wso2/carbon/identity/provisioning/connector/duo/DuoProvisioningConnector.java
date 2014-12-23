/*
 *  Copyright (c) 2005-2014, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */
package org.wso2.carbon.identity.provisioning.connector.duo;

import com.duosecurity.client.Http;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.provisioning.*;

import java.io.UnsupportedEncodingException;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Properties;

public class DuoProvisioningConnector extends AbstractOutboundProvisioningConnector {

    private static final long serialVersionUID = 8465869197181038416L;

    private static final Log log = LogFactory.getLog(DuoProvisioningConnector.class);
    private DuoProvisioningConnectorConfig configHolder;

    @Override
    /**
     * 
     */
    public void init(Property[] provisioningProperties) throws IdentityProvisioningException {
        Properties configs = new Properties();

        if (provisioningProperties != null && provisioningProperties.length > 0)
            for (Property property : provisioningProperties) {
                if (property.getValue() == null || property.getValue() == "") {
                    log.error("Required attributes are not set for Duo Provisioning Connector");
                    throw new IdentityProvisioningException();
                }
                configs.put(property.getName(), property.getValue());
                if (IdentityProvisioningConstants.JIT_PROVISIONING_ENABLED.equals(property
                        .getName())) {
                    if ("1".equals(property.getValue())) {
                        jitProvisioningEnabled = true;
                    }
                }
            }

        configHolder = new DuoProvisioningConnectorConfig(configs);
    }

    @Override
    /**
     * 
     */
    public ProvisionedIdentifier provision(ProvisioningEntity provisioningEntity)
            throws IdentityProvisioningException {

        String provisionedId = null;

        boolean isDebugEnabled = log.isDebugEnabled();

        if (provisioningEntity.isJitProvisioning() && !isJitProvisioningEnabled()) {
            if(isDebugEnabled){
                log.info("JIT provisioning disabled for Duo connector");
            }
            return null;
        }

        if (provisioningEntity.getEntityType() == ProvisioningEntityType.USER) {
            if (provisioningEntity.getOperation() == ProvisioningOperation.DELETE) {
                deleteUser(provisioningEntity);

            } else if (provisioningEntity.getOperation() == ProvisioningOperation.POST) {
                provisionedId = createUser(provisioningEntity);

            } else if (provisioningEntity.getOperation() == ProvisioningOperation.PUT) {
                updateUser(provisioningEntity);

            } else {
                log.warn("Unsupported provisioning operation.");
            }
        } else {
            log.warn("Unsupported provisioning operation.");
        }

        //creates identifier for the provisioned user
        ProvisionedIdentifier identifier = new ProvisionedIdentifier();
        identifier.setIdentifier(provisionedId);

        return identifier;
    }

    /**
     * 
     * @param provisioningEntity
     * @return provisionedId
     * @throws IdentityProvisioningException
     */
    private String createUser(ProvisioningEntity provisioningEntity)
            throws IdentityProvisioningException{

        boolean isDebugEnabled = log.isDebugEnabled();
        Object result = null;
        JSONObject jo = null;
        String provisionedId = null;

        Map<String, String> requiredAttributes = getSingleValuedClaims(provisioningEntity
                .getAttributes());
        requiredAttributes.put(DuoConnectorConstants.USERNAME, provisioningEntity.getEntityName());

        try {

            result = httpCall("POST", DuoConnectorConstants.API_USER, requiredAttributes);

            if(result != null){
                if(isDebugEnabled){
                    log.debug(result.toString());
                }
                jo = new JSONObject(result.toString());
                provisionedId = jo.getString(DuoConnectorConstants.USER_ID);
            }

        } catch (UnsupportedEncodingException e) {
            log.error("Error in encoding provisioning request");
            throw new IdentityProvisioningException(e);
        } catch(JSONException e){
            log.error("Error while accessing JSON object");
            throw new IdentityProvisioningException(e);
        }catch (Exception e){
            log.error("Error while creating user in Duo");
            throw new IdentityProvisioningException(e);
        }

        if (isDebugEnabled) {
            log.debug("Returning created user's ID : " + provisionedId);
        }

        return provisionedId;
    }

    /**
     * 
     * @param provisioningEntity
     * @throws IdentityProvisioningException
     */
    private void deleteUser(ProvisioningEntity provisioningEntity)
            throws IdentityProvisioningException {

        String userID = null;
        boolean isDebugEnabled = log.isDebugEnabled();

        try {
            userID = getIdbyUsername(provisioningEntity.getEntityName());
            if(userID != null){
                httpCall("DELETE", DuoConnectorConstants.API_USER+"/"+userID, null);
            }
        } catch (Exception e) {
            log.error("Error while deleting user from Duo");
            throw new IdentityProvisioningException(e);
        }

        if(isDebugEnabled){
            log.debug("Deleted user in Duo with user id: "+userID);
        }
    }


    /**
     *
     * @param provisioningEntity
     * @throws IdentityProvisioningException
     */
    private void updateUser(ProvisioningEntity provisioningEntity) throws IdentityProvisioningException {

        String userID = null;
        String phoneNumber = null;
        boolean needUpdate = false;

        Map<String, String> requiredAttributes = getSingleValuedClaims(provisioningEntity.getAttributes());

        Iterator<Map.Entry<String, String>> iterator = requiredAttributes.entrySet().iterator();

        while (iterator.hasNext()) {
            Map.Entry<String, String> mapEntry = iterator.next();
            if(mapEntry.getValue() != null){
                needUpdate = true;
                break;
            }
        }

        if(!needUpdate){
            return;
        }

        userID = getIdbyUsername(provisioningEntity.getEntityName()); //provisioningEntity.getIdentifier().getIdentifier()
        phoneNumber = requiredAttributes.get(DuoConnectorConstants.PHONE_NUMBER);

        modifyDuoUser(userID, requiredAttributes);

        if(phoneNumber != null &&  phoneNumber.trim().length() > 0){
            addPhoneToUser(userID,phoneNumber);
        }

    }

    /**
     *
     * @param phone
     * @return
     * @throws IdentityProvisioningException
     */
    private String createPhone(Map<String,String> phone) throws IdentityProvisioningException {
        String phoneID = null;
        Object result = null;
        JSONObject jo = null;
        boolean isDebugEnabled = log.isDebugEnabled();


        try {
            result = httpCall("POST", DuoConnectorConstants.API_PHONE, phone);
            if(result != null){
                if(isDebugEnabled){
                    log.debug(result.toString());
                }
                jo = new JSONObject(result.toString());
                phoneID = jo.getString(DuoConnectorConstants.PHONE_ID);

            }

        } catch (UnsupportedEncodingException e) {
            log.error("Error in encoding provisioning request");
            throw new IdentityProvisioningException(e);
        } catch(JSONException e){
            log.error("Error while accessing JSON object");
            throw new IdentityProvisioningException(e);
        }catch (Exception e){
            log.error("Error while adding phone in Duo");
            throw new IdentityProvisioningException(e);
        }

        return  phoneID;

    }

    /**
     *
     * @param userId
     * @param attributes
     * @throws IdentityProvisioningException
     */
    private void modifyDuoUser(String userId, Map<String, String> attributes) throws IdentityProvisioningException {
        Object result;
        boolean isDebugEnabled = log.isDebugEnabled();

        if(attributes.get(DuoConnectorConstants.PHONE_NUMBER) != null){
            attributes.remove(DuoConnectorConstants.PHONE_NUMBER);
        }
        try {
            result = httpCall("POST", DuoConnectorConstants.API_USER+"/"+userId, attributes);
            if(result != null){
                if(isDebugEnabled){
                    log.debug(result.toString());
                }
            }
        } catch (UnsupportedEncodingException e) {
            log.error("Error in encoding provisioning request");
            throw new IdentityProvisioningException(e);
        }catch (Exception e){
            log.error("Error while updating user in Duo");
            throw new IdentityProvisioningException(e);
        }

        return;
    }

    /**
     *
     * @param userId
     * @param phone
     * @throws IdentityProvisioningException
     */
    private void addPhoneToUser(String userId, String phone) throws IdentityProvisioningException {
        String phoneID = null;

        Map<String,String> param = new HashMap<String, String>();
        param.put(DuoConnectorConstants.PHONE_NUMBER, phone);

        try {
            phoneID = getPhoneByNumber(param);
        } catch (IdentityProvisioningException e) {
            log.error(e.getMessage());
        }

        String currentPhone = getPhoneByUserId(userId);

        if(phoneID != null && phoneID.equals(currentPhone)){
            return;
        }else if(currentPhone != null){
            removePhoneFromUser(currentPhone, userId);
        }

        if(phoneID == null){
            phoneID = createPhone(param);
        }

        param.remove(DuoConnectorConstants.PHONE_NUMBER);
        param.put(DuoConnectorConstants.PHONE_ID, phoneID);

        try {

            httpCall("POST", DuoConnectorConstants.API_USER+"/"+userId+"/phones", param);

        } catch (UnsupportedEncodingException e) {
            log.error("Error in encoding provisioning request");
            throw new IdentityProvisioningException(e);
        }catch (Exception e){
            log.error("Error while assigning phone to user in Duo");
            throw new IdentityProvisioningException(e);
        }
    }

    /**
     *
     * @param phone
     * @return
     * @throws IdentityProvisioningException
     */
    private String getPhoneByNumber(Map<String, String> phone) throws IdentityProvisioningException {
        Object result = null;
        String phoneID = null;
        JSONArray jo = null;
        boolean isDebugEnabled = log.isDebugEnabled();

        try {
            result = httpCall("GET", DuoConnectorConstants.API_PHONE, phone);

            if(result != null){
                if(isDebugEnabled){
                    log.debug(result.toString());
                }
                jo = new JSONArray(result.toString());
                if(jo.length() > 0){
                    phoneID = jo.getJSONObject(0).getString(DuoConnectorConstants.PHONE_ID);
                }
            }

        } catch (UnsupportedEncodingException e) {
            log.error("Error in encoding provisioning request");
            throw new IdentityProvisioningException(e);
        } catch(JSONException e){
            log.error("Error while accessing JSON object");
            throw new IdentityProvisioningException(e);
        }catch (Exception e){
            log.error("Error while retrieving phone Id in Duo. Phone number might not be saved");
            throw new IdentityProvisioningException(e);
        }

        return phoneID;
    }

    /**
     *
     * @param userId
     * @return
     * @throws IdentityProvisioningException
     */
    private String getPhoneByUserId(String userId) throws IdentityProvisioningException {
        Object result = null;
        String phoneID = null;
        JSONArray jo = null;
        boolean isDebugEnabled = log.isDebugEnabled();

        try{
            result = httpCall("GET",DuoConnectorConstants.API_USER+"/"+userId+"/phones", null);
            if(result != null){
                if(isDebugEnabled){
                    log.debug(result.toString());
                }
                jo = new JSONArray(result.toString());
                if(jo.length() > 0){
                    phoneID = jo.getJSONObject(0).getString(DuoConnectorConstants.PHONE_ID);
                }
            }

        }catch (UnsupportedEncodingException e) {
            log.error("Error in encoding provisioning request");
            throw new IdentityProvisioningException(e);
        } catch(JSONException e){
            log.error("Error while accessing JSON object");
            throw new IdentityProvisioningException(e);
        }catch (Exception e){
            log.error("Error while retrieving phones in Duo");
            throw new IdentityProvisioningException(e);
        }

        return phoneID;
    }

    private void removePhoneFromUser(String phoneId, String userId) throws IdentityProvisioningException {

        try {
            httpCall("DELETE",DuoConnectorConstants.API_USER+"/"+userId+"/phones/"+phoneId,null);
        } catch (Exception e) {
            log.error("Error while deleting phone from Duo user");
            throw new IdentityProvisioningException(e);
        }
    }

    /**
     *
     * @param method
     * @param URI
     * @param param
     * @return
     * @throws Exception
     */
    private Object httpCall(String method,String URI, Map param) throws Exception {
        Object result = null;

        Http request = new Http(method,configHolder.getValue(DuoConnectorConstants.HOST),URI);

        if(param != null){
            Iterator<Map.Entry<String, String>> iterator = param.entrySet().iterator();

            while (iterator.hasNext()) {
                Map.Entry<String, String> mapEntry = iterator.next();
                if(mapEntry.getValue() != null){
                    request.addParam(mapEntry.getKey(),mapEntry.getValue());
                }
            }

        }


        request.signRequest(configHolder.getValue(DuoConnectorConstants.IKEY),configHolder.getValue(DuoConnectorConstants.SKEY));
        result = request.executeRequest();

        return result;
    }

    /**
     *
     * @param uname
     * @return
     */
    private String getIdbyUsername(String uname){
        Object result = null;
        String user_id = null;
        JSONArray jo;

        Map<String, String> param = new HashMap<String, String>();

        try{
            param.put(DuoConnectorConstants.USERNAME, uname);
            result = httpCall("GET", DuoConnectorConstants.API_USER, param);

        }catch (UnsupportedEncodingException e) {
            log.error("Error in retrieving user");
        } catch(JSONException e){
            log.error("JSON exception");
        }catch (Exception e){
            log.error("Exception while retrieving data");
        }


        try {
            jo = new JSONArray(result.toString());
            if(jo.length() > 0){
                user_id = jo.getJSONObject(0).getString(DuoConnectorConstants.USER_ID);
            }


        } catch (JSONException e) {
            log.error("JSON exception");
            e.printStackTrace();
        }
        return user_id;
    }


}
