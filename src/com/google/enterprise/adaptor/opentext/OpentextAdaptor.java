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
import com.google.enterprise.adaptor.IOHelper;
import com.google.enterprise.adaptor.InvalidConfigurationException;
import com.google.enterprise.adaptor.Request;
import com.google.enterprise.adaptor.Response;

import com.opentext.livelink.service.core.Authentication;
import com.opentext.livelink.service.core.Authentication_Service;
import com.opentext.livelink.service.core.ContentService;
import com.opentext.livelink.service.core.ContentService_Service;
import com.opentext.livelink.service.docman.DocumentManagement;
import com.opentext.livelink.service.docman.DocumentManagement_Service;
import com.opentext.livelink.service.docman.GetNodesInContainerOptions;
import com.opentext.livelink.service.docman.Node;
import com.opentext.livelink.service.docman.NodeVersionInfo;
import com.opentext.livelink.service.docman.Version;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.io.Writer;
import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.activation.DataHandler;
import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.soap.SOAPFault;
import javax.xml.ws.BindingProvider;
import javax.xml.ws.handler.Handler;
import javax.xml.ws.soap.MTOMFeature;
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
  private String contentServerUrl;
  private Map<String, String> queryStrings;
  private Map<String, String> objectActions;
  private List<String> excludedNodeTypes;

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
    config.addKey("opentext.displayUrl.contentServerUrl", null);
    config.addKey("opentext.displayUrl.queryString.default",
        "?func=ll&objAction={0}&objId={1}");
    config.addKey("opentext.displayUrl.objAction.Document", "overview");
    config.addKey("opentext.displayUrl.objAction.default", "properties");
    config.addKey("opentext.excludedNodeTypes", "Alias, URL");
    config.addKey("opentext.excludedNodeTypes.separator", ",");
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

    this.contentServerUrl =
        config.getValue("opentext.displayUrl.contentServerUrl");
    this.queryStrings =
        config.getValuesWithPrefix("opentext.displayUrl.queryString.");
    this.objectActions =
        config.getValuesWithPrefix("opentext.displayUrl.objAction.");
    log.log(Level.CONFIG, "opentext.displayUrl.contentServerUrl: {0}",
        this.contentServerUrl);
    log.log(Level.CONFIG, "opentext.displayUrl.queryString: {0}",
        this.queryStrings);
    log.log(Level.CONFIG, "opentext.displayUrl.objAction: {0}",
        this.objectActions);

    String excludedNodeTypes = config.getValue("opentext.excludedNodeTypes");
    separator = config.getValue("opentext.excludedNodeTypes.separator");
    log.log(Level.CONFIG,
        "opentext.excludedNodeTypes: {0}", excludedNodeTypes);
    log.log(Level.CONFIG,
        "opentext.excludedNodeTypes.separator: {0}", separator);
    this.excludedNodeTypes =
        OpentextAdaptor.getExcludedNodeTypes(excludedNodeTypes, separator);
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
        docIds.add(
            new DocId(startPoint.getName() + ":" + startPoint.getNodeId()));
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
    OpentextDocId opentextDocId = new OpentextDocId(req.getDocId());
    Node node = getNode(documentManagement, opentextDocId);
    if (node == null) {
      log.log(Level.INFO, "Not found: {0}", opentextDocId);
      resp.respondNotFound();
      return;
    }

    if (this.excludedNodeTypes.contains(node.getType())) {
      log.log(Level.FINER, "Item {0} is excluded by type: {1}",
          new String[] { String.valueOf(node.getID()), node.getType() });
      resp.respondNotFound();
      return;
    }

    if (node.isIsContainer()) {
      // TODO: restrict the types of containers we handle.
      doContainer(documentManagement, opentextDocId, node, resp);
    } else {
      if ("Document".equals(node.getType())) {
        doDocument(documentManagement, opentextDocId, node, resp);
      } else {
        // TODO: other types.
        resp.respondNotFound();
      }
    }
  }

  @VisibleForTesting
  void doContainer(DocumentManagement documentManagement,
      OpentextDocId opentextDocId, Node containerNode, Response response)
      throws IOException {

    List<Node> containerContents;
    try {
      // The second argument causes listNodes to return partial
      // content, but that content includes the name.
      containerContents = documentManagement.listNodes(containerNode.getID(),
          true);
    } catch (SOAPFaultException soapFaultException) {
      log.log(Level.WARNING,
          "Error retrieving container contents: " + opentextDocId,
          soapFaultException);
      return;
    }

    response.setContentType("text/html; charset=" + CHARSET.name());
    // TODO: add displayUrl for container in Content Server
    Writer writer = new OutputStreamWriter(response.getOutputStream(),
        CHARSET);
    HtmlResponseWriter responseWriter = new HtmlResponseWriter(
        writer, this.context.getDocIdEncoder(), Locale.ENGLISH);
    responseWriter.start(opentextDocId.getDocId(),
        opentextDocId.getDocId().getUniqueId());
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
      // The ':' character is not allowed in Content Server names.
      String uniqueId = opentextDocId.getEncodedPath() + "/"
          + encodedName + ":" + node.getID();
      responseWriter.addLink(new DocId(uniqueId), name);
    }
    responseWriter.finish();
  }

  @VisibleForTesting
  Node getNode(DocumentManagement documentManagement,
      OpentextDocId opentextDocId) {
    log.log(Level.FINER, "Looking up docId: " + opentextDocId);

    // Use the object id to look up the node.
    Node node;
    try {
      node = documentManagement.getNode(opentextDocId.getNodeId());
      if (node == null) {
        return null;
      }
    } catch (SOAPFaultException soapFaultException) {
      log.log(Level.WARNING, "Error retrieving item: " + opentextDocId,
          soapFaultException);
      return null;
    }

    // Verify that the node we found still corresponds to the doc id.

    // Check the start point in the doc id against the configured ones.
    if (!isStartPointValid(opentextDocId)) {
      return null;
    }

    List<String> path = opentextDocId.getPath();

    // If the doc id is a start point, return the node.
    if (path.size() == 1) {
      return node;
    }

    try {
      // If we can find it by path, the doc id is still valid.
      StartPoint startPoint = getStartPointByName(path.get(0));
      if (documentManagement.getNodeByPath(startPoint.getNodeId(),
              path.subList(1, path.size())) != null) {
        return node;
      }

      // Some nodes can't be retrieved directly by path (for
      // example, nodes within a project). Build the current
      // node's path by walking up the tree to the start point. A
      // node that's a direct child of a volume will have a
      // negative parent id; to find the corresponding parent
      // node, we have to look up (-1 * id). Root nodes have a
      // parent id of -1.
      List<String> nodePath = new ArrayList<String>(path.size());
      nodePath.add(node.getName());
      long parentId = Math.abs(node.getParentID());
      while (parentId != -1 && parentId != startPoint.getNodeId()) {
        Node parentNode = documentManagement.getNode(parentId);
        if (parentNode == null) {
          log.log(Level.WARNING,
              "Parent of '" + nodePath.get(nodePath.size() - 1)
              + "' with id '" + parentId + "' not found: " + opentextDocId);
          return null;
        }
        nodePath.add(parentNode.getName());
        parentId = Math.abs(parentNode.getParentID());
      }
      nodePath.add(startPoint.getName());
      Collections.reverse(nodePath);
      if (!path.equals(nodePath)) {
        log.log(Level.FINER,
            "Doc id " + path + " does not match node path " + nodePath);
        return null;
      }
      return node;
    } catch (SOAPFaultException soapFaultException) {
      log.log(Level.WARNING, "Error verifying item: " + opentextDocId,
          soapFaultException);
      return null;
    }
  }

  private boolean isStartPointValid(OpentextDocId opentextDocId) {
    StartPoint startPoint =
        getStartPointByName(opentextDocId.getPath().get(0));
    if (startPoint == null) {
      log.log(Level.WARNING,
          "Invalid start point in doc id: {0}", opentextDocId);
      return false;
    }
    return true;
  }

  private StartPoint getStartPointByName(String name) {
    for (StartPoint startPoint : this.startPoints) {
      if (name.equals(startPoint.getName())) {
        return startPoint;
      }
    }
    return null;
  }

  /**
   * Return document content.
   *
   * @throws SOAPFaultException if the document content can't be read
   */
  @VisibleForTesting
  void doDocument(DocumentManagement documentManagement,
      OpentextDocId opentextDocId, Node documentNode, Response response)
      throws IOException {
    if (!documentNode.isIsVersionable()) {
      throw new UnsupportedOperationException(
          "Document does not support versions: " + opentextDocId);
    }

    // 0 indicates the most recent version.
    Version version = documentManagement.getVersion(documentNode.getID(), 0);
    long versionNumber = version.getNumber();
    String contextId = documentManagement.getVersionContentsContext(
        documentNode.getID(), versionNumber);
    ContentService contentService =
        this.soapFactory.newContentService(documentManagement);
    DataHandler dataHandler = contentService.downloadContent(contextId);

    String contentType = version.getMimeType();
    if (contentType != null) {
      response.setContentType(contentType);
    }
    XMLGregorianCalendar xmlCalendar = version.getModifyDate();
    if (xmlCalendar != null) {
      Date lastModifiedDate = xmlCalendar.toGregorianCalendar().getTime();
      response.setLastModified(lastModifiedDate);
    }
    response.setDisplayUrl(
        getDisplayUrl(documentNode.getType(), documentNode.getID()));
    InputStream inputStream = dataHandler.getInputStream();
    try {
      if (inputStream != null) {
        IOHelper.copyStream(inputStream, response.getOutputStream());
      }
    } finally {
      if (inputStream != null) {
        try {
          inputStream.close();
        } catch (IOException ioException) {
          log.log(Level.FINE, "Error closing document stream", ioException);
        }
      }
    }
  }

  @VisibleForTesting
  URI getDisplayUrl(String objectType, long objectId) {
    String queryString = this.queryStrings.get(objectType);
    if (queryString == null) {
      queryString = this.queryStrings.get("default");
    }
    String objectAction = this.objectActions.get(objectType);
    if (objectAction == null) {
      objectAction = this.objectActions.get("default");
    }
    StringBuilder builder = new StringBuilder(this.contentServerUrl);
    builder.append(MessageFormat.format(queryString, objectAction,
            Long.toString(objectId)));
    return URI.create(builder.toString());
  }

  @VisibleForTesting
  interface SoapFactory {
    Authentication newAuthentication();
    DocumentManagement newDocumentManagement(String authenticationToken);
    ContentService newContentService(DocumentManagement documentManagement);
    void configure(Config config);
  }

  @VisibleForTesting
  static class SoapFactoryImpl implements SoapFactory {
    private final Authentication_Service authenticationService;
    private final DocumentManagement_Service documentManagementService;
    private final ContentService_Service contentServiceService;
    private String webServicesUrl;

    SoapFactoryImpl() {
      this.authenticationService = new Authentication_Service(
          Authentication_Service.class.getResource("Authentication.wsdl"));
      this.documentManagementService = new DocumentManagement_Service(
          DocumentManagement_Service.class.getResource(
              "DocumentManagement.wsdl"));
      this.contentServiceService = new ContentService_Service(
          ContentService_Service.class.getResource(
              "ContentService.wsdl"));
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

      setEndpointAddress(
          (BindingProvider) authenticationPort, "Authentication");

      return authenticationPort;
    }

    @Override
    public DocumentManagement newDocumentManagement(
        String authenticationToken) {
      DocumentManagement documentManagementPort =
          documentManagementService.getBasicHttpBindingDocumentManagement();

      setEndpointAddress(
          (BindingProvider) documentManagementPort, "DocumentManagement");
      setAuthenticationHandler(
          (BindingProvider) documentManagementPort, authenticationToken);

      return documentManagementPort;
    }

    @Override
    public ContentService newContentService(
        DocumentManagement documentManagement) {
      ContentService contentServicePort =
          contentServiceService.getBasicHttpBindingContentService(
              new MTOMFeature());

      setEndpointAddress(
          (BindingProvider) contentServicePort, "ContentService");
      setAuthenticationHandler(
          (BindingProvider) contentServicePort,
          getAuthenticationToken((BindingProvider) documentManagement));

      return contentServicePort;
    }

    private void setEndpointAddress(BindingProvider bindingProvider,
        String serviceName) {
      bindingProvider.getRequestContext().put(
          BindingProvider.ENDPOINT_ADDRESS_PROPERTY,
          getWebServiceAddress(serviceName));
    }

    private String getAuthenticationToken(BindingProvider bindingProvider) {
      List<Handler> chain = bindingProvider.getBinding().getHandlerChain();
      for (Handler handler : chain) {
        if (handler instanceof AuthenticationHandler) {
          return ((AuthenticationHandler) handler).getAuthenticationToken();
        }
      }
      throw new RuntimeException("Missing authentication handler");
    }

    private void setAuthenticationHandler(BindingProvider bindingProvider,
        String authenticationToken) {
      Handler handler = new AuthenticationHandler(authenticationToken);
      List<Handler> chain = Arrays.asList(handler);
      bindingProvider.getBinding().setHandlerChain(chain);
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
  List<String> getExcludedNodeTypes() {
    return this.excludedNodeTypes;
  }

  @VisibleForTesting
  static List<String> getExcludedNodeTypes(String types, String separator) {
    List<String> excludedNodeTypes = new ArrayList<String>();
    Iterable<String> nodeTypes = Splitter.on(separator)
        .trimResults().omitEmptyStrings().split(types);
    for (String nodeType : nodeTypes) {
      try {
        Long.parseLong(nodeType);
        excludedNodeTypes.add("GenericNode:" + nodeType);
      } catch (NumberFormatException numberFormatException) {
        excludedNodeTypes.add(nodeType);
      }
    }
    return excludedNodeTypes;
  }
}
