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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.provisioning.AbstractOutboundProvisioningConnector;
import org.wso2.carbon.identity.provisioning.AbstractProvisioningConnectorFactory;
import org.wso2.carbon.identity.provisioning.IdentityProvisioningException;

import java.util.ArrayList;
import java.util.List;

/**
 * 
 *
 */
public class DuoProvisioningConnectorFactory extends AbstractProvisioningConnectorFactory {

    private static final Log log = LogFactory.getLog(DuoProvisioningConnectorFactory.class);
    private static final String DUO = "duo";

    @Override
    /**
     * 
     */
    protected AbstractOutboundProvisioningConnector buildConnector(
            Property[] provisioningProperties) throws IdentityProvisioningException {
        DuoProvisioningConnector duoSecProvisioning = new DuoProvisioningConnector();
        duoSecProvisioning.init(provisioningProperties);

        if (log.isDebugEnabled()) {
            log.debug("Duo Security provisioning connector created successfully.");
        }

        return duoSecProvisioning;
    }

    @Override
    /**
     * 
     */
    public String getConnectorType() {
        return DUO;
    }

	@Override
	public List<Property> getConfigurationProperties() {

		List<Property> configProperties = new ArrayList<Property>();

		Property duoHost = new Property();
        duoHost.setDisplayName("Host");
        duoHost.setName(DuoConnectorConstants.HOST);
        duoHost.setDescription("Enter host name of Duo Account");
        duoHost.setRequired(true);

        Property ikey = new Property();
        ikey.setDisplayName("Integration Key");
        ikey.setName(DuoConnectorConstants.IKEY);
        ikey.setDescription("Enter Integration Key");
        ikey.setRequired(true);

        Property skey = new Property();
        skey.setDisplayName("Secret Key");
        skey.setName(DuoConnectorConstants.SKEY);
        skey.setDescription("Enter Secret Key");
        skey.setRequired(true);
        skey.setConfidential(true);
		//configProperties.

		configProperties.add(duoHost);
        configProperties.add(ikey);
        configProperties.add(skey);
		return configProperties;

	}

}
