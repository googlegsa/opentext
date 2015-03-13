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

import com.google.common.annotations.VisibleForTesting;

import org.w3c.dom.Node;

import java.util.Collections;
import java.util.Iterator;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.xml.namespace.QName;
import javax.xml.soap.SOAPElement;
import javax.xml.soap.SOAPEnvelope;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPHeader;
import javax.xml.soap.SOAPHeaderElement;
import javax.xml.soap.SOAPMessage;
import javax.xml.soap.SOAPPart;
import javax.xml.ws.handler.MessageContext;
import javax.xml.ws.handler.soap.SOAPHandler;
import javax.xml.ws.handler.soap.SOAPMessageContext;

class AuthenticationHandler implements SOAPHandler<SOAPMessageContext> {
  private static final Logger log
      = Logger.getLogger(AuthenticationHandler.class.getName());

  @VisibleForTesting
  static final QName authenticationHeaderName =
      new QName("urn:api.ecm.opentext.com", "OTAuthentication");
  @VisibleForTesting
  static final QName authenticationTokenName =
      new QName("urn:api.ecm.opentext.com", "AuthenticationToken");
  private static final Set<QName> headers =
      Collections.singleton(AuthenticationHandler.authenticationHeaderName);

  private String authenticationToken;

  AuthenticationHandler(String authenticationToken) {
    this.authenticationToken = authenticationToken;
  }

  @VisibleForTesting
  String getAuthenticationToken() {
    return this.authenticationToken;
  }

  @Override
  public Set<QName> getHeaders() {
    return headers;
  }

  @Override
  public void close(MessageContext context) {
  }

  @Override
  public boolean handleFault(SOAPMessageContext context) {
    return true;
  }

  @Override
  public boolean handleMessage(SOAPMessageContext context) {
    SOAPMessage message = context.getMessage();
    if (message == null) {
      log.log(Level.FINEST,
          "SOAPMessageContext.message==null; can't add authentication");
      return true;
    }

    if ((Boolean) context.get(MessageContext.MESSAGE_OUTBOUND_PROPERTY)) {
      try {
        SOAPHeader header = message.getSOAPHeader();
        if (header == null) {
          SOAPPart part = message.getSOAPPart();
          SOAPEnvelope envelope = part.getEnvelope();
          header = envelope.addHeader();
        }
        SOAPHeaderElement authenticationHeaderElement =
            header.addHeaderElement(
                AuthenticationHandler.authenticationHeaderName);
        authenticationHeaderElement.setPrefix("");
        SOAPElement authenticationTokenElement =
            authenticationHeaderElement.addChildElement(
                AuthenticationHandler.authenticationTokenName);
        authenticationTokenElement.setPrefix("");
        authenticationTokenElement.addTextNode(this.authenticationToken);
      } catch (SOAPException soapException) {
        log.log(Level.WARNING, "Error adding authentication header",
            soapException);
        return false;
      }
    } else {
      try {
        SOAPHeader header = message.getSOAPHeader();
        if (header != null) {
          Iterator headerElements = header.getChildElements(
              AuthenticationHandler.authenticationHeaderName);
          if (headerElements.hasNext()) {
            SOAPHeaderElement headerElement =
                (SOAPHeaderElement) headerElements.next();
            Iterator childElements = headerElement.getChildElements(
                AuthenticationHandler.authenticationTokenName);
            if (childElements.hasNext()) {
              SOAPElement child = (SOAPElement) childElements.next();
              Node tokenNode = child.getFirstChild();
              if (tokenNode != null) {
                this.authenticationToken = tokenNode.getNodeValue();;
              }
            }
          }
        }
      } catch (SOAPException soapException) {
        log.log(Level.WARNING, "Error reading authentication header",
            soapException);
      }
    }
    return true;
  }
}
