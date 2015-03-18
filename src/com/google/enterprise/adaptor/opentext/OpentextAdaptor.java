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
import com.opentext.livelink.service.docman.GetNodesInContainerOptions;
import com.opentext.livelink.service.docman.Node;

import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.io.Writer;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.xml.soap.SOAPFault;
import javax.xml.ws.BindingProvider;
import javax.xml.ws.handler.Handler;
import javax.xml.ws.soap.SOAPFaultException;

/** For getting OpenText repository content into a Google Search Appliance. */
public class OpentextAdaptor extends AbstractAdaptor {

  private static final Logger log
      = Logger.getLogger(OpentextAdaptor.class.getName());
  /** Charset used in generated HTML responses. */
  private static final Charset CHARSET = Charset.forName("UTF-8");

  public static void main(String[] args) {
    AbstractAdaptor.main(new OpentextAdaptor(), args);
  }

  private AdaptorContext context;
  private final SoapFactory soapFactory;
  private String username;
  private String password;
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
    this.context = context;
    Config config = context.getConfig();
    this.soapFactory.configure(config);

    String webServicesUrl = config.getValue("opentext.webServicesUrl");
    String username = config.getValue("opentext.username");
    String password = context.getSensitiveValueDecoder().decodeValue(
        config.getValue("opentext.password"));
    log.log(Level.CONFIG, "opentext.webServicesUrl: {0}", webServicesUrl);
    log.log(Level.CONFIG, "opentext.username: {0}", username);
    this.username = username;
    this.password = password;


    Authentication authentication = soapFactory.newAuthentication();
    String authenticationToken;
    try {
      authenticationToken =
          authentication.authenticateUser(username, password);
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
      throw new InvalidConfigurationException("No valid opentext.src values.");
    }

    // Compute a node id for all start points.
    DocumentManagement documentManagement =
        soapFactory.newDocumentManagement(authenticationToken);
    for (StartPoint startPoint : this.startPoints) {
      if (startPoint.getType() == StartPoint.Type.VOLUME) {
        Node node = documentManagement.getRootNode(startPoint.getName());
        if (node != null) {
          startPoint.setNodeId(node.getID());
        }
      }
    }
  }

  @Override
  public void getDocIds(DocIdPusher pusher) throws InterruptedException {
    Authentication authentication = this.soapFactory.newAuthentication();
    String authenticationToken =
        authentication.authenticateUser(this.username, this.password);
    DocumentManagement documentManagement =
        soapFactory.newDocumentManagement(authenticationToken);
    ArrayList<DocId> docIds = new ArrayList<DocId>();
    for (StartPoint startPoint : this.startPoints) {
      if (isValidStartPoint(startPoint, documentManagement)) {
        docIds.add(new DocId(startPoint.getName()));
      }
    }
    log.log(Level.FINER, "Sending doc ids: {0}", docIds);
    pusher.pushDocIds(docIds);
  }

  /** Gives the bytes of a document referenced with id. */
  @Override
  public void getDocContent(Request req, Response resp)
      throws IOException {

    Authentication authentication = this.soapFactory.newAuthentication();
    String authenticationToken =
        authentication.authenticateUser(this.username, this.password);
    DocumentManagement documentManagement =
        this.soapFactory.newDocumentManagement(authenticationToken);
    DocId docId = req.getDocId();
    Node node = getNode(documentManagement, docId);
    if (node == null) {
      log.log(Level.INFO, "Not found: {0}", docId);
      resp.respondNotFound();
      return;
    }

    if (node.isIsContainer()) {
      // TODO: restrict the types of containers we handle.
      doContainer(documentManagement, docId, node, resp);
    } else {
      // TODO: return document content.
      resp.respondNotFound();
    }
  }

  @VisibleForTesting
  void doContainer(DocumentManagement documentManagement, DocId docId,
      Node containerNode, Response response) throws IOException {

    List<Node> containerContents;
    try {
      // The second argument causes listNodes to return partial
      // content, but that content includes the name.
      containerContents = documentManagement.listNodes(containerNode.getID(),
          true);
    } catch (SOAPFaultException soapFaultException) {
      log.log(Level.WARNING, "Error retrieving container contents: " + docId,
          soapFaultException);
      return;
    }

    response.setContentType("text/html; charset=" + CHARSET.name());
    Writer writer = new OutputStreamWriter(response.getOutputStream(),
        CHARSET);
    HtmlResponseWriter responseWriter = new HtmlResponseWriter(
        writer, this.context.getDocIdEncoder(), Locale.ENGLISH);
    responseWriter.start(docId, docId.getUniqueId());
    for (Node node : containerContents) {
      String name = node.getName();
      String encodedName;
      try {
        encodedName = URLEncoder.encode(name, CHARSET.name());
      } catch (UnsupportedEncodingException unsupportedEncoding) {
        log.log(Level.WARNING, "Error encoding value: " + name,
            unsupportedEncoding);
        encodedName = name;
      }
      responseWriter.addLink(
          new DocId(docId.getUniqueId() + "/" + encodedName), name);
    }
    responseWriter.finish();
  }

  @VisibleForTesting
  Node getNode(DocumentManagement documentManagement, DocId docId) {
    List<String> path = OpentextAdaptor.getPath(docId);
    StartPoint startPoint = getStartPointByName(path.get(0));
    if (startPoint == null) {
      log.log(Level.WARNING,
          "Invalid start point in doc id: {0}", path.get(0));
      return null;
    }
    try {
      Node node;
      if (path.size() == 1) {
        node = documentManagement.getNode(startPoint.getNodeId());
      } else {
        node = documentManagement.getNodeByPath(startPoint.getNodeId(),
            path.subList(1, path.size()));
      }
      return node;
    } catch (SOAPFaultException soapFaultException) {
      log.log(Level.WARNING, "Error retrieving item: " + docId,
          soapFaultException);
      return null;
    }
  }

  private StartPoint getStartPointByName(String name) {
    for (StartPoint startPoint : this.startPoints) {
      if (name.equals(startPoint.getName())) {
        return startPoint;
      }
    }
    return null;
  }

  @VisibleForTesting
  interface SoapFactory {
    Authentication newAuthentication();
    DocumentManagement newDocumentManagement(String authenticationToken);
    void configure(Config config);
  }

  @VisibleForTesting
  static class SoapFactoryImpl implements SoapFactory {
    private final Authentication_Service authenticationService;
    private final DocumentManagement_Service documentManagementService;
    private String webServicesUrl;

    SoapFactoryImpl() {
      this.authenticationService = new Authentication_Service(
          Authentication_Service.class.getResource("Authentication.wsdl"));
      this.documentManagementService = new DocumentManagement_Service(
          DocumentManagement_Service.class.getResource(
              "DocumentManagement.wsdl"));
    }

    @VisibleForTesting
    String getWebServiceAddress(String serviceName) {
      if (!this.webServicesUrl.endsWith("/")) {
        this.webServicesUrl += "/";
      }
      return this.webServicesUrl + serviceName;
    }

    @Override
    public Authentication newAuthentication() {
      Authentication authenticationPort =
          authenticationService.getBasicHttpBindingAuthentication();
      ((BindingProvider) authenticationPort).getRequestContext().put(
          BindingProvider.ENDPOINT_ADDRESS_PROPERTY,
          getWebServiceAddress("Authentication"));
      return authenticationPort;
    }

    @Override
    public DocumentManagement newDocumentManagement(
        String authenticationToken) {
      DocumentManagement documentManagementPort =
          documentManagementService.getBasicHttpBindingDocumentManagement();
      ((BindingProvider) documentManagementPort).getRequestContext().put(
          BindingProvider.ENDPOINT_ADDRESS_PROPERTY,
          getWebServiceAddress("DocumentManagement"));
      AuthenticationHandler handler =
          new AuthenticationHandler(authenticationToken);
      List<Handler> chain = Arrays.asList((Handler) handler);
      ((BindingProvider) documentManagementPort)
          .getBinding().setHandlerChain(chain);
      return documentManagementPort;
    }

    @Override
    public void configure(Config config) {
      this.webServicesUrl = config.getValue("opentext.webServicesUrl");
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
      } catch (IllegalArgumentException illegalArgumentException) {
        log.log(Level.CONFIG, "opentext.src value not supported: " + srcValue,
          illegalArgumentException);
      }
    }
    return startPoints;
  }

  @VisibleForTesting
  boolean isValidStartPoint(StartPoint startPoint,
      DocumentManagement documentManagement) {

    try {
      if (startPoint.getType() == StartPoint.Type.NODE) {
        Node node = documentManagement.getNode(startPoint.getNodeId());
        if (node != null) {
          return true;
        }
      } else if (startPoint.getType() == StartPoint.Type.VOLUME) {
        // init() will have checked for a node id
        if (startPoint.getNodeId() != -1) {
          return true;
        }
      }
      log.log(Level.WARNING, "No such start point: " + startPoint);
      return false;
    } catch (SOAPFaultException soapFaultException) {
      log.log(Level.WARNING, "Unable to access start point: " + startPoint,
          soapFaultException);
      return false;
    }
  }

  @VisibleForTesting
  static List<String> getPath(DocId docId) {
    String[] path = docId.getUniqueId().split("/");
    for (int i = 0; i < path.length; i++) {
      try {
        path[i] = URLDecoder.decode(path[i], CHARSET.name());
      } catch (UnsupportedEncodingException unsupportedEncoding) {
        log.log(Level.WARNING, "Error decoding value: " + path[i],
            unsupportedEncoding);
      }
    }
    return Arrays.asList(path);
  }
}
