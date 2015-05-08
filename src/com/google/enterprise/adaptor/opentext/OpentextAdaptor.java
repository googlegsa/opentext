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
import com.google.common.base.Strings;
import com.google.common.collect.Lists;
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
import com.opentext.livelink.service.core.BooleanValue;
import com.opentext.livelink.service.core.ContentService;
import com.opentext.livelink.service.core.ContentService_Service;
import com.opentext.livelink.service.core.DataValue;
import com.opentext.livelink.service.core.DateValue;
import com.opentext.livelink.service.core.IntegerValue;
import com.opentext.livelink.service.core.PrimitiveValue;
import com.opentext.livelink.service.core.RealValue;
import com.opentext.livelink.service.core.RowValue;
import com.opentext.livelink.service.core.StringValue;
import com.opentext.livelink.service.core.TableValue;
import com.opentext.livelink.service.docman.Attribute;
import com.opentext.livelink.service.docman.AttributeGroup;
import com.opentext.livelink.service.docman.AttributeGroupDefinition;
import com.opentext.livelink.service.docman.DocumentManagement;
import com.opentext.livelink.service.docman.DocumentManagement_Service;
import com.opentext.livelink.service.docman.GetNodesInContainerOptions;
import com.opentext.livelink.service.docman.Metadata;
import com.opentext.livelink.service.docman.Node;
import com.opentext.livelink.service.docman.NodeFeature;
import com.opentext.livelink.service.docman.NodeVersionInfo;
import com.opentext.livelink.service.docman.PrimitiveAttribute;
import com.opentext.livelink.service.docman.SetAttribute;
import com.opentext.livelink.service.docman.UserAttribute;
import com.opentext.livelink.service.docman.Version;
import com.opentext.livelink.service.memberservice.Member;
import com.opentext.livelink.service.memberservice.MemberService;
import com.opentext.livelink.service.memberservice.MemberService_Service;

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
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.SortedMap;
import java.util.SortedSet;
import java.util.TreeMap;
import java.util.TreeSet;
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
  private boolean indexCategories;
  private boolean indexCategoryNames;
  private boolean indexSearchableAttributesOnly;
  private List<String> includedCategories;
  private List<String> excludedCategories;

  // Look up attributes by key
  private SortedMap<String, Attribute> attributeDefinitions =
      Collections.synchronizedSortedMap(new TreeMap<String, Attribute>());
  // Look up category definitions by key
  private SortedMap<String, AttributeGroupDefinition> categoryDefinitions =
      Collections.synchronizedSortedMap(
          new TreeMap<String, AttributeGroupDefinition>());
  // Category keys
  private SortedSet<String> categoriesWithUserAttributes =
      Collections.synchronizedSortedSet(new TreeSet<String>());
  private Map<String, List<String>> includedNodeFeatures;
  private ThreadLocal<SimpleDateFormat> metadataDateFormatter;

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
    config.addKey("opentext.indexCategories", "true");
    config.addKey("opentext.indexCategoryNames", "true");
    config.addKey("opentext.indexSearchableAttributesOnly", "true");
    config.addKey("opentext.includedCategories", "");
    config.addKey("opentext.includedCategories.separator", ",");
    config.addKey("opentext.excludedCategories", "");
    config.addKey("opentext.excludedCategories.separator", ",");
    config.addKey("opentext.includedNodeFeatures.separator", ",");
    config.addKey("opentext.metadataDateFormat", "yyyy-MM-dd");
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

    String indexCategories = config.getValue("opentext.indexCategories");
    log.log(Level.CONFIG, "opentext.indexCategories: {0}", indexCategories);
    this.indexCategories = Boolean.parseBoolean(indexCategories);

    if (this.indexCategories) {
      String indexCategoryNames =
          config.getValue("opentext.indexCategoryNames");
      log.log(Level.CONFIG,
          "opentext.indexCategoryNames: {0}", indexCategoryNames);
      this.indexCategoryNames = Boolean.parseBoolean(indexCategoryNames);

      String indexSearchableAttributesOnly =
          config.getValue("opentext.indexSearchableAttributesOnly");
      log.log(Level.CONFIG,
          "opentext.indexSearchableAttributesOnly: {0}",
          indexSearchableAttributesOnly);
      this.indexSearchableAttributesOnly =
          Boolean.parseBoolean(indexSearchableAttributesOnly);

      String includedCategories =
          config.getValue("opentext.includedCategories");
      separator = config.getValue("opentext.includedCategories.separator");
      log.log(Level.CONFIG,
          "opentext.includedCategories: {0}", includedCategories);
      log.log(Level.CONFIG,
          "opentext.includedCategories.separator: {0}", separator);
      this.includedCategories = Lists.newArrayList(
          Splitter.on(separator).trimResults().omitEmptyStrings()
          .split(includedCategories));
      if (this.includedCategories.isEmpty()) {
        this.includedCategories = null;
      }

      String excludedCategories =
          config.getValue("opentext.excludedCategories");
      separator = config.getValue("opentext.excludedCategories.separator");
      log.log(Level.CONFIG,
          "opentext.excludedCategories: {0}", excludedCategories);
      log.log(Level.CONFIG,
          "opentext.excludedCategories.separator: {0}", separator);
      this.excludedCategories = Lists.newArrayList(
          Splitter.on(separator).trimResults().omitEmptyStrings()
          .split(excludedCategories));
      if (this.excludedCategories.isEmpty()) {
        this.excludedCategories = null;
      }
    }

    Map<String, String> includedNodeFeatures =
        config.getValuesWithPrefix("opentext.includedNodeFeatures.");
    separator = config.getValue("opentext.includedNodeFeatures.separator");
    log.log(Level.CONFIG,
        "opentext.includedNodeFeatures: {0}", includedNodeFeatures);
    log.log(Level.CONFIG,
        "opentext.includedNodeFeatures.separator: {0}", separator);
    this.includedNodeFeatures = OpentextAdaptor.getIncludedNodeFeatures(
        includedNodeFeatures, separator);

    final String metadataDateFormat =
        config.getValue("opentext.metadataDateFormat");
    log.log(Level.CONFIG,
        "opentext.metadataDateFormat: {0}", metadataDateFormat);
    this.metadataDateFormatter =
      new ThreadLocal<SimpleDateFormat>() {
          @Override
          protected SimpleDateFormat initialValue() {
              return new SimpleDateFormat(metadataDateFormat);
          }
      };
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
      doCategories(documentManagement, node, resp);
      doNodeFeatures(node, resp);
      doNodeProperties(documentManagement, node, resp);

      doContainer(documentManagement, opentextDocId, node, resp);
    } else {
      if ("Document".equals(node.getType())) {
        doCategories(documentManagement, node, resp);
        doNodeFeatures(node, resp);
        doNodeProperties(documentManagement, node, resp);

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
  void doCategories(DocumentManagement documentManagement, Node node,
      Response response) {
    if (!this.indexCategories) {
      return;
    }
    Metadata metadata = node.getMetadata();
    if (metadata == null) {
      return;
    }
    List<AttributeGroup> attributeGroups = metadata.getAttributeGroups();
    if (attributeGroups == null) {
      return;
    }

    for (AttributeGroup attributeGroup : attributeGroups) {
      if (!shouldIndex(attributeGroup)) {
        continue;
      }
      cacheCategoryDefinition(attributeGroup, documentManagement);
      // Check to see if we'll need to do user lookups.
      MemberService memberService = null;
      if (this.categoriesWithUserAttributes
          .contains(attributeGroup.getKey())) {
        memberService = this.soapFactory.newMemberService(documentManagement);
      }
      if (this.indexCategoryNames && attributeGroup.getDisplayName() != null) {
        response.addMetadata("Category", attributeGroup.getDisplayName());
      }
      List<DataValue> dataValues = attributeGroup.getValues();
      for (DataValue dataValue : dataValues) {
        if (dataValue instanceof PrimitiveValue) {
          doPrimitiveValue(
              (PrimitiveValue) dataValue, response,
              this.attributeDefinitions, memberService);
        } else if (dataValue instanceof RowValue) {
          doRowValue((RowValue) dataValue, response,
              this.attributeDefinitions, memberService);
        } else if (dataValue instanceof TableValue) {
          doTableValue((TableValue) dataValue, response,
              this.attributeDefinitions, memberService);
        }
      }
    }
  }

  @VisibleForTesting
  boolean shouldIndex(AttributeGroup attributeGroup) {
    if (!"Category".equals(attributeGroup.getType())) {
      log.log(Level.FINEST, "Skipping non-Category metadata type {0}",
          attributeGroup.getType());
      return false;
    }
    int index = attributeGroup.getKey().indexOf(".");
    if (index == -1) {
      log.log(Level.FINE,
          "Unable to get category id for " + attributeGroup.getDisplayName()
          + " from key " + attributeGroup.getKey());
      return false;
    }
    String categoryId = attributeGroup.getKey().substring(0, index);
    if (((this.includedCategories != null) &&
            !this.includedCategories.contains(categoryId)) ||
        ((this.excludedCategories != null) &&
            this.excludedCategories.contains(categoryId))) {
      return false;
    }
    return true;
  }

  @VisibleForTesting
  void cacheCategoryDefinition(
      AttributeGroup attributeGroup, DocumentManagement documentManagement) {
    AttributeGroupDefinition categoryDefinition =
        this.categoryDefinitions.get(attributeGroup.getKey());
    if (categoryDefinition == null) {
      // Look up definition and cache attribute data if we
      // haven't seen this category before.
      categoryDefinition = documentManagement.getAttributeGroupDefinition(
          attributeGroup.getType(), attributeGroup.getKey());
      this.categoryDefinitions.put(
          attributeGroup.getKey(), categoryDefinition);
      List<Attribute> attributes = categoryDefinition.getAttributes();
      for (Attribute attribute : attributes) {
        if (attribute instanceof PrimitiveAttribute) {
          this.attributeDefinitions.put(attribute.getKey(), attribute);
          if (attribute instanceof UserAttribute) {
            this.categoriesWithUserAttributes
                .add(categoryDefinition.getKey());
          }
        } else if (attribute instanceof SetAttribute) {
          List<Attribute> setAttributes =
              ((SetAttribute) attribute).getAttributes();
          for (Attribute setAttribute : setAttributes) {
            if (setAttribute instanceof PrimitiveAttribute)
              this.attributeDefinitions.put(
                  setAttribute.getKey(), setAttribute);
            if (attribute instanceof UserAttribute) {
              this.categoriesWithUserAttributes
                  .add(categoryDefinition.getKey());
            }
          }
        }
      }
    }
  }

  @VisibleForTesting
  void doTableValue(TableValue tableValue, Response response,
      Map<String, Attribute> attributeDefinitions,
      MemberService memberService) {
    List<RowValue> rowValues = tableValue.getValues();
    for (RowValue value : rowValues) {
      doRowValue(value, response, attributeDefinitions, memberService);
    }
  }

  private void doRowValue(RowValue rowValue, Response response,
      Map<String, Attribute> attributeDefinitions,
      MemberService memberService) {
    List<DataValue> values = rowValue.getValues();
    for (DataValue value : values) {
      if (value instanceof PrimitiveValue) {
        doPrimitiveValue((PrimitiveValue) value, response,
             attributeDefinitions, memberService);
      }
      // Nested attribute sets (tables, rows) are not supported.
    }
  }

  /* PrimitiveValue's subclasses are BooleanValue, DateValue,
   * IntegerValue, RealValue, StringValue; each can have multiple
   * values. PrimitiveValue does not have a getValues method;
   * only the subclasses do.
   */
  @VisibleForTesting
  void doPrimitiveValue(PrimitiveValue primitiveValue, Response response,
      Map<String, Attribute> attributeDefinitions,
      MemberService memberService) {

    String name = primitiveValue.getDescription();
    if (name == null) {
      log.log(Level.FINEST,
          "No name for attribute {0}; skipping", primitiveValue.getKey());
      return;
    }

    boolean isUserAttribute = false;
    boolean isSearchable = false;
    Attribute attribute = attributeDefinitions.get(primitiveValue.getKey());
    if (attribute != null) {
      isUserAttribute = (attribute instanceof UserAttribute);
      isSearchable = attribute.isSearchable();
    }
    if (this.indexSearchableAttributesOnly && !isSearchable) {
      return;
    }

    List<? extends Object> values = null;
    if (primitiveValue instanceof StringValue) {
      values = ((StringValue) primitiveValue).getValues();
    } else if (primitiveValue instanceof BooleanValue) {
      values = ((BooleanValue) primitiveValue).getValues();
    } else if (primitiveValue instanceof RealValue) {
      values = ((RealValue) primitiveValue).getValues();
    } else if (primitiveValue instanceof DateValue) {
      List<XMLGregorianCalendar> dateValues =
          ((DateValue) primitiveValue).getValues();
      List<String> dateStrings = new ArrayList<String>(dateValues.size());
      for (XMLGregorianCalendar xmlCalendar : dateValues) {
        if (xmlCalendar != null) {
          dateStrings.add(getDateAsString(xmlCalendar));
        }
      }
      values = dateStrings;
    } else if (primitiveValue instanceof IntegerValue) {
      // IntegerValue's enclosed type is Long.
      if (isUserAttribute && memberService != null) {
        try {
          List<Member> members = memberService.getMembersByID(
              ((IntegerValue) primitiveValue).getValues());
          List<String> usernames = new ArrayList<String>(members.size());
          for (Member member : members) {
            if (member != null && member.getName() != null) {
              usernames.add(member.getName());
            }
          }
          values = usernames;
        } catch (SOAPFaultException soapFaultException) {
          log.log(Level.FINER,
              "Failed to look up member names for attribute " + name,
              soapFaultException);
        }
      } else {
        values = ((IntegerValue) primitiveValue).getValues();
      }
    }

    if (values != null) {
      for (Object value : values) {
        if (value != null) {
          response.addMetadata(name, value.toString());
        }
      }
    }
  }

  void doNodeFeatures(Node node, Response response) {
    List<NodeFeature> features = node.getFeatures();
    if (features == null || features.size() == 0) {
      return;
    }
    List<String> includedFeatures =
        this.includedNodeFeatures.get(node.getType());
    if (includedFeatures == null) {
      // NodeFeatures to index must be explicitly configured.
      // TODO: we're not logging this case for every node
      // encountered; in future, try to log a message once for
      // each type with NodeFeatures that aren't being indexed.
      return;
    }

    for (NodeFeature feature : features) {
      String name = feature.getName();
      if (name == null) {
        continue;
      }
      if (!includedFeatures.contains(name)) {
        continue;
      }
      String value = null;
      switch (feature.getType()) {
        case "String":
          value = feature.getStringValue();
          break;
        case "Integer":
          if (feature.getIntegerValue() != null) {
            value = feature.getIntegerValue().toString();
          }
          break;
        case "Long":
          if (feature.getLongValue() != null) {
            value = feature.getLongValue().toString();
          }
          break;
        case "Date":
          if (feature.getDateValue() != null) {
            value = getDateAsString(feature.getDateValue());
          }
          break;
        case "Boolean":
          // The getter for boolean features really is "isBooleanValue".
          if (feature.isBooleanValue() != null) {
            value = feature.isBooleanValue().toString();
          }
          break;
        default:
          log.log(Level.FINEST,
              "Unknown feature type " + feature.getType()
              + " in NodeFeature " + name
              + " for object " + node.getID());
      }
      if (value != null) {
        response.addMetadata(name, value);
      }
    }
  }

  /* Names for metadata are taken from the Livelink Connector. */
  @VisibleForTesting
  void doNodeProperties(DocumentManagement documentManagement,
      Node node, Response response) {

    response.addMetadata("ID", String.valueOf(node.getID()));

    String name = node.getName();
    if (!Strings.isNullOrEmpty(name)) {
      response.addMetadata("Name", name);
    }

    String comment = node.getComment();
    if (!Strings.isNullOrEmpty(comment)) {
      response.addMetadata("Comment", comment);
    }

    XMLGregorianCalendar xmlCalendar = node.getCreateDate();
    if (xmlCalendar != null) {
      response.addMetadata("CreateDate", getDateAsString(xmlCalendar));
    }
    xmlCalendar = node.getModifyDate();
    if (xmlCalendar != null) {
      response.addMetadata("ModifyDate", getDateAsString(xmlCalendar));
    }

    if (node.getCreatedBy() != null) {
      MemberService memberService =
          this.soapFactory.newMemberService(documentManagement);
      try {
        Member member = memberService.getMemberById(node.getCreatedBy());
        if (member.getName() != null) {
          response.addMetadata("CreatedBy", member.getName());
        }
      } catch (SOAPFaultException soapFaultException) {
        log.log(Level.FINE,
            "Failed to look up node creator for " + node.getID(),
            soapFaultException);
      }
    }

    response.addMetadata("SubType", node.getType());
    String displayType = node.getDisplayType();
    if (!Strings.isNullOrEmpty(displayType)) {
      response.addMetadata("DisplayType", displayType);
    }

    response.addMetadata("VolumeID", String.valueOf(node.getVolumeID()));

    if (node.isIsVersionable()) {
      NodeVersionInfo versionInfo = node.getVersionInfo();
      if (versionInfo != null) {
        String mimeType = versionInfo.getMimeType();
        if (!Strings.isNullOrEmpty(mimeType)) {
          response.addMetadata("MimeType", mimeType);
        }
      }
    }
  }

  private String getDateAsString(XMLGregorianCalendar xmlCalendar) {
    return this.metadataDateFormatter.get().format(
        xmlCalendar.toGregorianCalendar().getTime());
  }

  @VisibleForTesting
  interface SoapFactory {
    Authentication newAuthentication();
    DocumentManagement newDocumentManagement(String authenticationToken);
    ContentService newContentService(DocumentManagement documentManagement);
    MemberService newMemberService(DocumentManagement documentManagement);
    void configure(Config config);
  }

  @VisibleForTesting
  static class SoapFactoryImpl implements SoapFactory {
    private final Authentication_Service authenticationService;
    private final DocumentManagement_Service documentManagementService;
    private final ContentService_Service contentServiceService;
    private final MemberService_Service memberServiceService;
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
      this.memberServiceService = new MemberService_Service(
          MemberService_Service.class.getResource(
              "MemberService.wsdl"));
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

    @Override
    public MemberService newMemberService(
        DocumentManagement documentManagement) {
      MemberService memberServicePort =
          memberServiceService.getBasicHttpBindingMemberService();

      setEndpointAddress(
          (BindingProvider) memberServicePort, "MemberService");
      setAuthenticationHandler(
          (BindingProvider) memberServicePort,
          getAuthenticationToken((BindingProvider) documentManagement));

      return memberServicePort;
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
      excludedNodeTypes.add(OpentextAdaptor.getCanonicalType(nodeType));
    }
    return excludedNodeTypes;
  }

  @VisibleForTesting
  static Map<String, List<String>> getIncludedNodeFeatures(
      Map<String, String> includedFeatures, String separator) {

    Map<String, List<String>> result = new HashMap<String, List<String>>();
    for (Map.Entry<String, String> entry : includedFeatures.entrySet()) {
      String key = OpentextAdaptor.getCanonicalType(entry.getKey());
      List<String> values = Lists.newArrayList(Splitter.on(separator)
          .trimResults().omitEmptyStrings().split(entry.getValue()));
      result.put(key, values);
    }
    return result;
  }

  @VisibleForTesting
  static String getCanonicalType(String nodeType) {
    if (nodeType == null) {
      return null;
    }
    try {
      Long.parseLong(nodeType);
      return "GenericNode:" + nodeType;
    } catch (NumberFormatException numberFormatException) {
      return nodeType;
    }
  }
}
