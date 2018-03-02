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

import static com.google.enterprise.adaptor.opentext.Logging.captureLogMessages;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import com.google.common.collect.ImmutableSet;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import javax.xml.namespace.QName;
import javax.xml.soap.MessageFactory;
import javax.xml.soap.SOAPElement;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPHeader;
import javax.xml.soap.SOAPHeaderElement;
import javax.xml.soap.SOAPMessage;
import javax.xml.ws.handler.MessageContext;
import javax.xml.ws.handler.soap.SOAPMessageContext;

/**
 * Tests the AuthenticationHandler class.
 */
public class AuthenticationHandlerTest {
  @Rule
  public ExpectedException thrown = ExpectedException.none();

  @Test
  public void testSetHeader() throws SOAPException {
    SOAPMessageContextMock contextMock = new SOAPMessageContextMock(true);
    SOAPMessageContext context =
        Proxies.newProxyInstance(SOAPMessageContext.class, contextMock);
    AuthenticationHandler handler = new AuthenticationHandler("authtoken");
    assertTrue(handler.handleMessage(context));
    assertAuthenticationHeaderEquals("authtoken",
        contextMock.message.getSOAPHeader());
  }

  @Test
  public void testGetNewToken() throws SOAPException {
    SOAPMessageContextMock contextMock = new SOAPMessageContextMock(false);
    SOAPMessageContext context =
        Proxies.newProxyInstance(SOAPMessageContext.class, contextMock);
    AuthenticationHandler handler = new AuthenticationHandler("authtoken");
    assertEquals("authtoken", handler.getAuthenticationToken());
    assertTrue(handler.handleMessage(context));
    assertEquals("incoming token", handler.getAuthenticationToken());
  }

  @Test
  public void testEmptyMessage() throws SOAPException {
    SOAPMessageContextMock contextMock = new SOAPMessageContextMock(false);
    contextMock.message = null;
    SOAPMessageContext context =
        Proxies.newProxyInstance(SOAPMessageContext.class, contextMock);
    AuthenticationHandler handler = new AuthenticationHandler("authtoken");
    List<String> messages = new ArrayList<>();
    captureLogMessages(AuthenticationHandler.class,
        "SOAPMessageContext.message==null", messages);
    assertTrue(handler.handleMessage(context));
    assertEquals(messages.toString(), 1, messages.size());
  }

  @Test
  public void testEmptyHeaderInbound() throws SOAPException {
    SOAPMessageContextMock contextMock = new SOAPMessageContextMock(false);
    contextMock.message.getSOAPPart().getEnvelope().getHeader().detachNode();
    assertNull("header should be missing",
        contextMock.message.getSOAPHeader());
    SOAPMessageContext context =
        Proxies.newProxyInstance(SOAPMessageContext.class, contextMock);
    AuthenticationHandler handler = new AuthenticationHandler(null);
    assertTrue(handler.handleMessage(context));
    assertNull("token should be missing", handler.getAuthenticationToken());
  }

  @Test
  public void testEmptyHeaderOutbound() throws SOAPException {
    SOAPMessageContextMock contextMock = new SOAPMessageContextMock(true);
    contextMock.message.getSOAPPart().getEnvelope().getHeader().detachNode();
    assertEquals("header should be missing",
        null, contextMock.message.getSOAPHeader());
    SOAPMessageContext context =
        Proxies.newProxyInstance(SOAPMessageContext.class, contextMock);
    AuthenticationHandler handler = new AuthenticationHandler("authtoken");
    assertTrue(handler.handleMessage(context));
    assertAuthenticationHeaderEquals("authtoken",
        contextMock.message.getSOAPHeader());
  }

  // Test interface methods for coverage
  @Test
  public void testBasicMethods() throws SOAPException {
    SOAPMessageContextMock contextMock = new SOAPMessageContextMock(false);
    SOAPMessageContext context =
        Proxies.newProxyInstance(SOAPMessageContext.class, contextMock);
    AuthenticationHandler handler = new AuthenticationHandler("authtoken");
    assertEquals(ImmutableSet.of(
            new QName("urn:api.ecm.opentext.com", "OTAuthentication")),
        handler.getHeaders());
    assertTrue(handler.handleFault(context));
    handler.close(context);
  }

  private static class SOAPMessageContextMock {
    private SOAPMessage message;
    private boolean isOutbound;

    private SOAPMessageContextMock(boolean isOutbound) throws SOAPException {
      MessageFactory factory = MessageFactory.newInstance();
      this.message = factory.createMessage();
      this.isOutbound = isOutbound;
      if (!isOutbound) {
        SOAPHeader header = this.message.getSOAPHeader();
        SOAPHeaderElement authenticationHeaderElement =
            header.addHeaderElement(
                AuthenticationHandler.authenticationHeaderName);
        SOAPElement authenticationTokenElement =
            authenticationHeaderElement.addChildElement(
                AuthenticationHandler.authenticationTokenName);
        authenticationTokenElement.addTextNode("incoming token");
      }
    }

    public SOAPMessage getMessage() {
      return this.message;
    }

    public Object get(Object key) {
      if (MessageContext.MESSAGE_OUTBOUND_PROPERTY.equals(key)) {
        return this.isOutbound;
      }
      return null;
    }
  }

  private void assertAuthenticationHeaderEquals(String authenticationToken,
      SOAPHeader header) {
    Iterator<?> headerElements = header.getChildElements(
        AuthenticationHandler.authenticationHeaderName);
    assertTrue(headerElements.hasNext());
    SOAPHeaderElement headerElement =
        (SOAPHeaderElement) headerElements.next();
    Iterator<?> childElements = headerElement.getChildElements(
        AuthenticationHandler.authenticationTokenName);
    assertTrue(childElements.hasNext());
    SOAPElement child = (SOAPElement) childElements.next();
    assertEquals(authenticationToken,
        child.getFirstChild().getNodeValue());
  }
}
