// Copyright 2015 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package com.google.enterprise.adaptor.opentext;

import com.google.enterprise.adaptor.AbstractAdaptor;
import com.google.enterprise.adaptor.AdaptorContext;
import com.google.enterprise.adaptor.Config;
import com.google.enterprise.adaptor.DocId;
import com.google.enterprise.adaptor.DocIdPusher;
import com.google.enterprise.adaptor.InvalidConfigurationException;
import com.google.enterprise.adaptor.Request;
import com.google.enterprise.adaptor.Response;

import com.opentext.livelink.service.core.Authentication;
import com.opentext.livelink.service.core.Authentication_Service;

import java.net.URL;
import java.net.UnknownHostException;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.xml.soap.SOAPFault;
import javax.xml.ws.BindingProvider;
import javax.xml.ws.WebServiceException;
import javax.xml.ws.soap.SOAPFaultException;

/** For getting OpenText repository content into a Google Search Appliance. */
public class OpentextAdaptor extends AbstractAdaptor {

  private static final Logger log
      = Logger.getLogger(OpentextAdaptor.class.getName());

  public static void main(String[] args) {
    AbstractAdaptor.main(new OpentextAdaptor(), args);
  }

  /** The Authentication service object. */
  private Authentication authentication;

  @Override
  public void initConfig(Config config) {
    config.addKey("opentext.webServicesUrl", null);
    config.addKey("opentext.username", null);
    config.addKey("opentext.password", null);
  }

  /**
   * Verifies the configured Content Web Services location and
   * credentials.
   *
   * @throws InvalidConfigurationException if the hostname or
   * credentials are invalid
   * @throws SOAPFaultException if the Content Server is unavailable
   * @throws WebServiceException if the adaptor can't connect to
   * the web services server
   */
  @Override
  public void init(AdaptorContext context) {
    Config config = context.getConfig();

    String webServicesUrl = config.getValue("opentext.webServicesUrl");
    String username = config.getValue("opentext.username");
    String password = context.getSensitiveValueDecoder().decodeValue(
        config.getValue("opentext.password"));
    log.log(Level.CONFIG, "opentext.webServicesUrl: {0}", webServicesUrl);
    log.log(Level.CONFIG, "opentext.username: {0}", username);

    Authentication_Service authService = new Authentication_Service(
        Authentication_Service.class.getResource("Authentication.wsdl"));
    Authentication authPort = authService.getBasicHttpBindingAuthentication();
    ((BindingProvider) authPort).getRequestContext().put(
        BindingProvider.ENDPOINT_ADDRESS_PROPERTY,
        webServicesUrl + "/Authentication");
    try {
      authPort.authenticateUser(username, password);
    } catch (SOAPFaultException soapFaultException) {
      SOAPFault fault = soapFaultException.getFault();
      String localPart = fault.getFaultCodeAsQName().getLocalPart();
      if ("Core.LoginFailed".equals(localPart)) {
        throw new InvalidConfigurationException(fault.getFaultString(),
            soapFaultException);
      }
      // The only other currently known exception code here is
      // Core.ServiceException, seen when the Content Server was
      // unavailable. We want to allow the adaptor to retry if
      // that's the error.
      throw soapFaultException;
    }
    this.authentication = authPort;
  }

  @Override
  public void getDocIds(DocIdPusher pusher) {
  }

  /** Gives the bytes of a document referenced with id. */
  @Override
  public void getDocContent(Request req, Response resp) {
  }
}
