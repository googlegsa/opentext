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
import com.google.common.base.Splitter;
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
import com.opentext.livelink.service.docman.DocumentManagement;
import com.opentext.livelink.service.docman.DocumentManagement_Service;
import com.opentext.livelink.service.docman.Node;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.xml.namespace.QName;
import javax.xml.soap.SOAPElement;
import javax.xml.soap.SOAPEnvelope;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPHeaderElement;
import javax.xml.soap.SOAPFault;
import javax.xml.soap.SOAPHeader;
import javax.xml.soap.SOAPMessage;
import javax.xml.soap.SOAPPart;
import javax.xml.ws.BindingProvider;
import javax.xml.ws.handler.Handler;
import javax.xml.ws.handler.MessageContext;
import javax.xml.ws.handler.soap.SOAPMessageContext;
import javax.xml.ws.handler.soap.SOAPHandler;
import javax.xml.ws.soap.SOAPFaultException;

/** For getting OpenText repository content into a Google Search Appliance. */
public class OpentextAdaptor extends AbstractAdaptor {

  private static final Logger log
      = Logger.getLogger(OpentextAdaptor.class.getName());

  public static void main(String[] args) {
    AbstractAdaptor.main(new OpentextAdaptor(), args);
  }

  private final SoapFactory soapFactory;

  /** The Authentication service object. */
  private Authentication authentication;

  /** Configured start points, with unknown values removed. */
  private List<StartPoint> startPoints;

  public OpentextAdaptor() {
    this(new SoapFactoryImpl());
  }

  @VisibleForTesting
  OpentextAdaptor(SoapFactory soapFactory) {
    this.soapFactory = soapFactory;
  }

  @Override
  public void initConfig(Config config) {
    config.addKey("opentext.webServicesUrl", null);
    config.addKey("opentext.username", null);
    config.addKey("opentext.password", null);
    config.addKey("opentext.src", "EnterpriseWS");
    config.addKey("opentext.src.separator", ",");
  }

  /**
   * Verifies the configured Content Web Services location and
   * credentials. Sets up the start points.
   *
   * @throws InvalidConfigurationException if the hostname or
   * credentials are invalid, or if no usable start points are provided
   * @throws SOAPFaultException if the Content Server is unavailable
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

    this.authentication = soapFactory.newAuthentication(webServicesUrl);
    String authenticationToken = null;
    try {
      authenticationToken =
          this.authentication.authenticateUser(username, password);
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

    String src = config.getValue("opentext.src");
    String separator = config.getValue("opentext.src.separator");
    log.log(Level.CONFIG, "opentext.src: {0}", src);
    log.log(Level.CONFIG, "opentext.src.separator: {0}", separator);
    this.startPoints = OpentextAdaptor.getStartPoints(src, separator);
    if (this.startPoints.isEmpty()) {
      // All we've done is check for either integer doc id values
      // or the distinguished volume names, so if there aren't
      // any of either, we're not going to get far.
      throw new InvalidConfigurationException("No valid source values");
    }

    DocumentManagement docman =
        soapFactory.newDocumentManagement(webServicesUrl, authenticationToken);
    Node node = docman.getRootNode("EnterpriseWS");
  }

  @Override
  public void getDocIds(DocIdPusher pusher) throws InterruptedException {
    ArrayList<DocId> docIds = new ArrayList<DocId>();
    for (StartPoint startPoint : this.startPoints) {
        docIds.add(new DocId(startPoint.getName()));
    }
    log.log(Level.FINER, "Sending doc ids: {0}", docIds);
    pusher.pushDocIds(docIds);
  }

  /** Gives the bytes of a document referenced with id. */
  @Override
  public void getDocContent(Request req, Response resp) {
  }

  @VisibleForTesting
  interface SoapFactory {
    Authentication newAuthentication(String webServicesUrl);
    DocumentManagement newDocumentManagement(String webServicesUrl,
      String authenticationToken);
  }

  @VisibleForTesting
  static class SoapFactoryImpl implements SoapFactory {
    @VisibleForTesting
    String getWebServiceAddress(String webServicesUrl, String serviceName) {
      if (!webServicesUrl.endsWith("/")) {
        webServicesUrl += "/";
      }
      return webServicesUrl + serviceName;
    }

    private class AuthenticationHandler
        implements SOAPHandler<SOAPMessageContext> {

      private final QName authHeaderName =
          new QName("urn:api.ecm.opentext.com", "OTAuthentication");
      private final QName authTokenName =
          new QName("urn:api.ecm.opentext.com", "AuthenticationToken");
      private final Set<QName> headers =
          Collections.singleton(authHeaderName);

      private String authenticationToken;

      private AuthenticationHandler(String authenticationToken) {
        this.authenticationToken = authenticationToken;
      }

      public Set<QName> getHeaders() {
        System.out.println("Hey, we're listing headers");
        return headers;
      }

      public void close(MessageContext context) {
      }

      public boolean handleFault(SOAPMessageContext context) {
        System.out.println("Hey, we're handling a fault");
        return true;
      }

      public boolean handleMessage(SOAPMessageContext context) {
        System.out.println("Hey, we're handling a message");

        // TODO: split into request/response cases.

        if ((Boolean) context.get(MessageContext.MESSAGE_OUTBOUND_PROPERTY)) {
          try {
            SOAPMessage message = context.getMessage();
            SOAPPart part = message.getSOAPPart();
            SOAPEnvelope envelope = part.getEnvelope();
            SOAPHeader header = envelope.getHeader();
            if (header != null) {
              // TODO: can we reuse instead?

              header.detachNode();
              header = envelope.addHeader();
            } else {
              header = envelope.addHeader();
            }

            SOAPHeaderElement authHeaderElement = header.addHeaderElement(
                authHeaderName);
            authHeaderElement.setPrefix("");

            SOAPElement authTokenElement = authHeaderElement.addChildElement(
                authTokenName);
            authTokenElement.setPrefix("");
            authTokenElement.addTextNode(this.authenticationToken);

            message.writeTo(System.out);
          } catch (SOAPException soapException) {
            System.out.println("soap exception : " + soapException);
            return false;
          }  catch (Exception e) {
          }
        } else {
          // TODO: incoming message; read authToken and store
          try {
            context.getMessage().writeTo(System.out);
          } catch (Exception e) {
          }
        }
        return true;
      }
    }

    @Override
    public Authentication newAuthentication(String webServicesUrl) {
      Authentication_Service authService = new Authentication_Service(
          Authentication_Service.class.getResource("Authentication.wsdl"));
      Authentication authPort = authService.getBasicHttpBindingAuthentication();
      ((BindingProvider) authPort).getRequestContext().put(
          BindingProvider.ENDPOINT_ADDRESS_PROPERTY,
          getWebServiceAddress(webServicesUrl, "Authentication"));
      return authPort;
    }

    @Override
    public DocumentManagement newDocumentManagement(String webServicesUrl,
      String authenticationToken) {
      DocumentManagement_Service docmanService = new DocumentManagement_Service(
          DocumentManagement_Service.class.getResource(
              "DocumentManagement.wsdl"));
      DocumentManagement docmanPort =
          docmanService.getBasicHttpBindingDocumentManagement();
      ((BindingProvider) docmanPort).getRequestContext().put(
          BindingProvider.ENDPOINT_ADDRESS_PROPERTY,
          getWebServiceAddress(webServicesUrl, "DocumentManagement"));

      AuthenticationHandler handler =
          new AuthenticationHandler(authenticationToken);
      List<Handler> chain = Arrays.asList((Handler) handler);
      ((BindingProvider) docmanPort).getBinding().setHandlerChain(chain);

      return docmanPort;
    }
  }

  @VisibleForTesting
  List<StartPoint> getStartPoints() {
    return this.startPoints;
  }

  @VisibleForTesting
  static List<StartPoint> getStartPoints(String src, String separator) {
    List<StartPoint> startPoints = new ArrayList<StartPoint>();
    Iterable<String> srcValues = Splitter.on(separator)
        .trimResults().omitEmptyStrings().split(src);
    for (String srcValue : srcValues) {
      try {
        startPoints.add(new StartPoint(srcValue));
      } catch (AssertionError e) {
        log.log(Level.CONFIG, "Source value not supported: {0}", srcValue);
      }
    }
    return startPoints;
  }
}
