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

import static com.google.enterprise.adaptor.opentext.OpentextAdaptor.SoapFactory;
import static com.google.enterprise.adaptor.opentext.OpentextAdaptor.SoapFactoryImpl;
import static org.junit.Assert.*;

import com.google.enterprise.adaptor.AdaptorContext;
import com.google.enterprise.adaptor.Config;
import com.google.enterprise.adaptor.InvalidConfigurationException;

import com.opentext.livelink.service.core.Authentication;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.lang.reflect.Proxy;

import javax.xml.namespace.QName;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPFactory;
import javax.xml.soap.SOAPFault;
import javax.xml.ws.BindingProvider;
import javax.xml.ws.soap.SOAPFaultException;

public class OpentextAdaptorTest {
  @Rule
  public ExpectedException thrown = ExpectedException.none();

  /**
   * Verify that the ENDPOINT_ADDRESS_PROPERTY is set.
   */
  @Test
  public void testSoapFactoryImpl() {
    SoapFactoryImpl factory = new SoapFactoryImpl();
    Authentication authentication = factory.newAuthentication(
        "webServicesUrl/");
    assertEquals("webServicesUrl/Authentication",
        ((BindingProvider) authentication).getRequestContext().get(
            BindingProvider.ENDPOINT_ADDRESS_PROPERTY));
  }

  /**
   * Check that trailing slashes or the lack thereof are handled
   * on the webServicesUrl property.
   */
  @Test
  public void testSoapFactoryImplGetWebServiceAddress() {
    SoapFactoryImpl factory = new SoapFactoryImpl();
    assertEquals("webServicesUrl/Authentication",
        factory.getWebServiceAddress("webServicesUrl", "Authentication"));
    assertEquals("webServicesUrl/Authentication",
        factory.getWebServiceAddress("webServicesUrl/", "Authentication"));
  }

  @Test
  public void testAuthenticateUser() {
    SoapFactoryMock soapFactory = new SoapFactoryMock();
    OpentextAdaptor adaptor = new OpentextAdaptor(soapFactory);
    assertFalse("authUser called before init",
        soapFactory.authenticationMock.authenticateUserCalled);
    AdaptorContext context = ProxyAdaptorContext.getInstance();
    Config config = context.getConfig();
    config.addKey("opentext.username", "validuser");
    config.addKey("opentext.password", "validpassword");
    config.addKey("opentext.webServicesUrl",
        "http://example.com/les-services/services");
    adaptor.init(context);
    assertTrue("authUser not called after init",
        soapFactory.authenticationMock.authenticateUserCalled);
    assertEquals("unexpected authentication token", "authentication_token",
        soapFactory.authenticationMock.authenticationToken);
  }

  @Test
  public void testAuthenticateUserInvalidUser() {
    thrown.expect(InvalidConfigurationException.class);
    thrown.expectMessage("javax.xml.ws.soap.SOAPFaultException");

    SoapFactoryMock soapFactory = new SoapFactoryMock();
    OpentextAdaptor adaptor = new OpentextAdaptor(soapFactory);
    assertFalse("authUser called before init",
        soapFactory.authenticationMock.authenticateUserCalled);
    AdaptorContext context = ProxyAdaptorContext.getInstance();
    Config config = context.getConfig();
    config.addKey("opentext.username", "invaliduser");
    config.addKey("opentext.password", "validpassword");
    config.addKey("opentext.webServicesUrl",
        "http://example.com/les-services/services");
    adaptor.init(context);
  }

  @Test
  public void testAuthenticateUserInvalidPassword() {
    thrown.expect(InvalidConfigurationException.class);
    thrown.expectMessage("Invalid username/password specified.");

    SoapFactoryMock soapFactory = new SoapFactoryMock();
    OpentextAdaptor adaptor = new OpentextAdaptor(soapFactory);
    assertFalse("authUser called before init",
        soapFactory.authenticationMock.authenticateUserCalled);
    AdaptorContext context = ProxyAdaptorContext.getInstance();
    Config config = context.getConfig();
    config.addKey("opentext.username", "validuser");
    config.addKey("opentext.password", "invalidpassword");
    config.addKey("opentext.webServicesUrl",
        "http://example.com/les-services/services");
    adaptor.init(context);
  }

  @Test
  public void testAuthenticateUserOtherSoapException() {
    thrown.expect(SOAPFaultException.class);
    thrown.expectMessage("Other SOAPFaultException");

    SoapFactoryMock soapFactory = new SoapFactoryMock();
    OpentextAdaptor adaptor = new OpentextAdaptor(soapFactory);
    assertFalse("authUser called before init",
        soapFactory.authenticationMock.authenticateUserCalled);
    AdaptorContext context = ProxyAdaptorContext.getInstance();
    Config config = context.getConfig();
    config.addKey("opentext.username", "validuser");
    config.addKey("opentext.password", "other");
    config.addKey("opentext.webServicesUrl",
        "http://example.com/les-services/services");
    adaptor.init(context);
  }

  private class SoapFactoryMock implements SoapFactory {
    private AuthenticationMock authenticationMock;

    private SoapFactoryMock() {
      this.authenticationMock = new AuthenticationMock();
    }

    @Override
    public Authentication newAuthentication(String webServicesUrl) {
      return Proxies.newProxyInstance(Authentication.class,
          this.authenticationMock);
    }
  }

  private class AuthenticationMock {
    private boolean authenticateUserCalled;
    private String authenticationToken;

    public String authenticateUser(String username, String password)
        throws SOAPFaultException {
      this.authenticateUserCalled = true;

      if ("validuser".equals(username) && "validpassword".equals(password)) {
        this.authenticationToken = "authentication_token";
        return this.authenticationToken;
      }
      if ("invaliduser".equals(username) && "validpassword".equals(password)) {
        throw getSoapFaultException("javax.xml.ws.soap.SOAPFaultException",
            "urn:Core.service.livelink.opentext.com",
            "Core.LoginFailed", "ns0");
      }
      if ("validuser".equals(username) && "invalidpassword".equals(password)) {
        throw getSoapFaultException("Invalid username/password specified.",
            "urn:Core.service.livelink.opentext.com",
            "Core.LoginFailed", "ns0");
      }
      if ("other".equals(password)) {
        throw getSoapFaultException("Other SOAPFaultException",
            "urn:opentextadaptortest", "Test.OtherException", "ns0");
      }
      throw new AssertionError(
          "Unexpected test config: " + username + "/" + password);
    }

    private SOAPFaultException getSoapFaultException(String message,
        String uri, String localPart, String prefix) {
      try {
        SOAPFactory soapFactory = SOAPFactory.newInstance();
        SOAPFault soapFault = soapFactory.createFault(
            message, new QName(uri, localPart, prefix));
        return new SOAPFaultException(soapFault);
      } catch (SOAPException soapException) {
        throw new RuntimeException("Failed to create SOAPFaultException",
            soapException);
      }
    }
  }
}
