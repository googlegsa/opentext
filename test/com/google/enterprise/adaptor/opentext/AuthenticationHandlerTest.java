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

import static org.junit.Assert.*;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.io.IOException;
import java.util.Iterator;

import javax.xml.soap.MessageFactory;
import javax.xml.soap.SOAPElement;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPHeader;
import javax.xml.soap.SOAPHeaderElement;
import javax.xml.soap.SOAPMessage;
import javax.xml.ws.handler.MessageContext;
import javax.xml.ws.handler.soap.SOAPMessageContext;

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

  private static class SOAPMessageContextMock {
    private SOAPMessage message;
    private boolean isOutbound;

    private SOAPMessageContextMock(boolean isOutbound) throws SOAPException {
      MessageFactory factory = MessageFactory.newInstance();
      this.message = factory.createMessage();
      this.isOutbound = isOutbound;
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
    Iterator headerElements = header.getChildElements(
        AuthenticationHandler.authenticationHeaderName);
    assertTrue(headerElements.hasNext());
    SOAPHeaderElement headerElement =
        (SOAPHeaderElement) headerElements.next();
    Iterator childElements = headerElement.getChildElements(
        AuthenticationHandler.authenticationTokenName);
    assertTrue(childElements.hasNext());
    SOAPElement child = (SOAPElement) childElements.next();
    assertEquals(authenticationToken,
        child.getFirstChild().getNodeValue());
  }
}
