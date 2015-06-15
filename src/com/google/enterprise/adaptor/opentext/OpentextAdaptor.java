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
import com.google.enterprise.adaptor.Acl;
import com.google.enterprise.adaptor.Acl.Builder;
import com.google.enterprise.adaptor.AdaptorContext;
import com.google.enterprise.adaptor.Config;
import com.google.enterprise.adaptor.DocId;
import com.google.enterprise.adaptor.DocIdPusher;
import com.google.enterprise.adaptor.GroupPrincipal;
import com.google.enterprise.adaptor.IOHelper;
import com.google.enterprise.adaptor.InvalidConfigurationException;
import com.google.enterprise.adaptor.Request;
import com.google.enterprise.adaptor.Response;
import com.google.enterprise.adaptor.UserPrincipal;

import com.opentext.livelink.service.collaboration.Collaboration;
import com.opentext.livelink.service.collaboration.Collaboration_Service;
import com.opentext.livelink.service.collaboration.DiscussionItem;
import com.opentext.livelink.service.collaboration.MilestoneInfo;
import com.opentext.livelink.service.collaboration.NewsInfo;
import com.opentext.livelink.service.collaboration.ProjectInfo;
import com.opentext.livelink.service.collaboration.TaskInfo;
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
import com.opentext.livelink.service.docman.NodePermissions;
import com.opentext.livelink.service.docman.NodeRight;
import com.opentext.livelink.service.docman.NodeRights;
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
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
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
  private String adminUsername;
  private String adminPassword;
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
    config.addKey("opentext.adminUsername", "");
    config.addKey("opentext.adminPassword", "");
    config.addKey("opentext.src", "EnterpriseWS");
    config.addKey("opentext.src.separator", ",");
    config.addKey("opentext.displayUrl.contentServerUrl", null);
    config.addKey("opentext.displayUrl.queryString.default",
        "?func=ll&objAction={0}&objId={1}");
    config.addKey("opentext.displayUrl.objAction.Document", "overview");
    config.addKey("opentext.displayUrl.objAction.default", "properties");
    config.addKey("opentext.excludedNodeTypes", "");
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
    String adminUsername = config.getValue("opentext.adminUsername");
    if (Strings.isNullOrEmpty(adminUsername)) {
      log.log(Level.CONFIG, "No user with administration rights configured."
          + " User " + this.username
          + " will be used to read item permissions.");
      this.adminUsername = null;
      this.adminPassword = null;
    } else {
      String adminPassword = context.getSensitiveValueDecoder().decodeValue(
          config.getValue("opentext.adminPassword"));
      log.log(Level.CONFIG, "opentext.adminUsername: {0}", adminUsername);
      this.adminUsername = adminUsername;
      this.adminPassword = adminPassword;
      Authentication authentication = soapFactory.newAuthentication();
      try {
        authentication.authenticateUser(
            this.adminUsername, this.adminPassword);
      } catch (SOAPFaultException soapFaultException) {
        SOAPFault fault = soapFaultException.getFault();
        String localPart = fault.getFaultCodeAsQName().getLocalPart();
        if ("Core.LoginFailed".equals(localPart)) {
          throw new InvalidConfigurationException(
              localPart
              + " (opentext.adminUsername: " + this.adminUsername + "): "
              + fault.getFaultString(),
              soapFaultException);
        }
        throw soapFaultException;
      }
    }
    Authentication authentication = soapFactory.newAuthentication();
    String authenticationToken;
    try {
      authenticationToken =
          authentication.authenticateUser(username, password);
    } catch (SOAPFaultException soapFaultException) {
      SOAPFault fault = soapFaultException.getFault();
      String localPart = fault.getFaultCodeAsQName().getLocalPart();
      if ("Core.LoginFailed".equals(localPart)) {
        throw new InvalidConfigurationException(
            localPart + " (opentext.username: " + username + "): "
            + fault.getFaultString(),
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
    this.queryStrings = OpentextAdaptor.fixTypeKeys(
        config.getValuesWithPrefix("opentext.displayUrl.queryString."));
    this.objectActions = OpentextAdaptor.fixTypeKeys(
        config.getValuesWithPrefix("opentext.displayUrl.objAction."));
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
          new String[] { opentextDocId.toString(), node.getType() });
      resp.respondNotFound();
      return;
    }

    log.log(Level.FINER, "getDocContent for {0} with type {1}",
        new String[] { opentextDocId.toString(), node.getType() });
    doAcl(documentManagement, opentextDocId, node, resp);
    doCategories(documentManagement, node, resp);
    doNodeFeatures(node, resp);
    doNodeProperties(documentManagement, node, resp);
    switch (node.getType()) {
      case "Collection":
        doCollection(documentManagement, opentextDocId, node, resp);
        break;
      case "GenericNode:146": // Custom View
        // fall through
      case "GenericNode:335": // XML DTD
        // fall through
      case "Document":
        doDocument(documentManagement, opentextDocId, node, resp);
        break;
      case "Milestone":
        doMilestone(documentManagement, opentextDocId, node, resp);
        break;
      case "News":
        doNews(documentManagement, opentextDocId, node, resp);
        break;
      case "Project":
        doProject(documentManagement, opentextDocId, node, resp);
        break;
      case "Reply":
        // fall through
      case "Topic":
        doTopicReply(documentManagement, opentextDocId, node, resp);
        break;
      case "Task":
        doTask(documentManagement, opentextDocId, node, resp);
        break;
      default:
        if (node.isIsContainer()) {
          doContainer(documentManagement, opentextDocId, node, resp);
        } else {
          doNode(documentManagement, opentextDocId, node, resp);
        }
    }
  }

  @VisibleForTesting
  void doAcl(DocumentManagement documentManagement,
      OpentextDocId opentextDocId, Node node, Response response) {
    if (this.adminUsername != null) {
      Authentication authentication = this.soapFactory.newAuthentication();
      String authenticationToken;
      try {
        authenticationToken = authentication.authenticateUser(
            this.adminUsername, this.adminPassword);
        documentManagement =
            this.soapFactory.newDocumentManagement(authenticationToken);
      } catch (SOAPFaultException soapFaultException) {
        log.log(Level.WARNING,
            "Failed to authenticate as " + this.adminUsername,
            soapFaultException);
        throw soapFaultException;
      }
    }
    NodeRights nodeRights;
    try {
      nodeRights = documentManagement.getNodeRights(node.getID());
    } catch (SOAPFaultException soapFaultException) {
      log.log(Level.WARNING,
          "Failed to get node rights for " + opentextDocId,
          soapFaultException);
      throw soapFaultException;
    }
    Set<UserPrincipal> permitUsers = new HashSet<UserPrincipal>();
    Set<GroupPrincipal> permitGroups = new HashSet<GroupPrincipal>();
    NodeRight publicRight = nodeRights.getPublicRight();
    if (publicRight != null) {
      NodePermissions publicPermissions = publicRight.getPermissions();
      if (publicPermissions.isSeeContentsPermission()) {
        permitGroups.add(new GroupPrincipal("Public Access"));
      }
    }
    // Rights can be removed and can then be null in the API.
    List<NodeRight> nodeRightList = new ArrayList<NodeRight>();
    if (nodeRights.getOwnerRight() != null) {
      nodeRightList.add(nodeRights.getOwnerRight());
    }
    if (nodeRights.getOwnerGroupRight() != null) {
      nodeRightList.add(nodeRights.getOwnerGroupRight());
    }
    if (nodeRights.getACLRights() != null) {
      nodeRightList.addAll(nodeRights.getACLRights());
    }
    MemberService memberService =
        this.soapFactory.newMemberService(documentManagement);
    for (NodeRight nodeRight : nodeRightList) {
      NodePermissions permissions = nodeRight.getPermissions();
      if (!permissions.isSeeContentsPermission()) {
        continue;
      }
      try {
        Member member =
            memberService.getMemberById(nodeRight.getRightID());
        if (member == null) {
          log.log(Level.FINER, "Member not found: " + nodeRight.getRightID());
          continue;
        }
        if ("User".equals(member.getType())) {
          permitUsers.add(new UserPrincipal(member.getName()));
        } else if ("Group".equals(member.getType())) {
          permitGroups.add(new GroupPrincipal(member.getName()));
        }
      } catch (SOAPFaultException soapFaultException) {
        SOAPFault fault = soapFaultException.getFault();
        String localPart = fault.getFaultCodeAsQName().getLocalPart();
        if ("MemberService.MemberTypeNotValid".equals(localPart)) {
          // There are groups that are specific to projects
          // (Guests, Members, Coordinators). These have ids that
          // show up in NodeRight.getRightID, but you can't
          // retrieve information about them using
          // MemberService.getMemberById. You can list their
          // members using MemberService.listMembers.
          try {
            Set<UserPrincipal> users = new HashSet<UserPrincipal>();
            Set<GroupPrincipal> groups = new HashSet<GroupPrincipal>();
            listMembers(
                memberService, nodeRight.getRightID(), users, groups);
            permitUsers.addAll(users);
            permitGroups.addAll(groups);
          } catch (SOAPFaultException listMembersException) {
            log.log(Level.WARNING,
                "Failed to get member information for " + opentextDocId
                + " using rightId " + nodeRight.getRightID(),
                listMembersException);
            throw listMembersException;
          }
        } else {
          log.log(Level.WARNING,
              "Failed to get member information for " + opentextDocId
              + " using rightId " + nodeRight.getRightID(),
              soapFaultException);
          throw soapFaultException;
        }
      }
    }
    if (permitUsers.size() == 0 && permitGroups.size() == 0) {
      log.log(Level.FINE,
          "No users or groups with SeeContents permission for "
          + opentextDocId);
      throw new RuntimeException(
          "No ACL information for " + opentextDocId);
    }

    // Even when permissions are inherited, Content Server keeps
    // a copy of all the permissions on each node, so each ACL
    // that we construct here should be complete for the node.
    Acl acl = new Acl.Builder().setEverythingCaseSensitive()
        .setInheritanceType(Acl.InheritanceType.LEAF_NODE)
        .setPermitUsers(permitUsers).setPermitGroups(permitGroups).build();
    response.setAcl(acl);
  }

  private void listMembers(MemberService memberService, long id,
      Set<UserPrincipal> users, Set<GroupPrincipal> groups)
      throws SOAPFaultException {
    List<Member> members = memberService.listMembers(id);
    for (Member member : members) {
      if ("User".equals(member.getType())) {
        users.add(new UserPrincipal(member.getName()));
      } else if ("Group".equals(member.getType())) {
        groups.add(new GroupPrincipal(member.getName()));
      } else if ("ProjectGroup".equals(member.getType())) {
        // ProjectGroups can be references to parent
        // ProjectGroups when, for example, a Project is nested
        // within another Project.
        listMembers(memberService, member.getID(), users, groups);
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
    response.setDisplayUrl(
        getDisplayUrl(containerNode.getType(), containerNode.getID()));
    Writer writer = new OutputStreamWriter(response.getOutputStream(),
        CHARSET);
    HtmlResponseWriter responseWriter = new HtmlResponseWriter(
        writer, this.context.getDocIdEncoder(), Locale.ENGLISH);
    responseWriter.start(opentextDocId.getDocId(),
        opentextDocId.getDocId().getUniqueId());
    for (Node node : containerContents) {
      responseWriter.addLink(
          getChildDocId(opentextDocId, node.getName(), node.getID()),
          node.getName());
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
  DocId getChildDocId(OpentextDocId parent, String name, long id) {
    String encodedName;
    try {
      encodedName = URLEncoder.encode(name, CHARSET.name());
    } catch (UnsupportedEncodingException unsupportedEncoding) {
      log.log(Level.WARNING, "Error encoding value: " + name,
          unsupportedEncoding);
      encodedName = name;
    }
    // The ':' character is not allowed in Content Server names.
    String uniqueId = parent.getEncodedPath() + "/"
          + encodedName + ":" + id;
    return new DocId(uniqueId);
  }

  @VisibleForTesting
  void doNode(DocumentManagement documentManagement,
      OpentextDocId opentextDocId, Node node, Response response)
      throws IOException {
    response.setDisplayUrl(getDisplayUrl(node.getType(), node.getID()));
    response.setContentType("text/html; charset=" + CHARSET.name());
    Writer writer = new OutputStreamWriter(response.getOutputStream(),
        CHARSET);
    writer.write("<!DOCTYPE html>\n<html><head><title>");
    writer.write(escapeContent(node.getName()));
    writer.write("</title></head><body><h1>");
    writer.write(escapeContent(node.getName()));
    writer.write("</h1>");
    writer.write("</body></html>");
    writer.flush();
  }

  /* A Collection is a set of references to other Content Server
   * objects. Since the actual objects exist elsewhere, we only
   * index the names here.
   */
  @VisibleForTesting
  void doCollection(DocumentManagement documentManagement,
      OpentextDocId opentextDocId, Node node, Response response)
      throws IOException {
    List<Node> collectionContents;
    try {
      collectionContents = documentManagement.listNodes(node.getID(), true);
    } catch (SOAPFaultException soapFaultException) {
      log.log(Level.WARNING,
          "Error retrieving collection contents: " + opentextDocId,
          soapFaultException);
      // If we can't fetch the collection contents, at least send
      // the collection node itself.
      doNode(documentManagement, opentextDocId, node, response);
      return;
    }
    String[] bodyText = new String[collectionContents.size()];
    for (int i = 0; i < collectionContents.size(); i++) {
      bodyText[i] = collectionContents.get(i).getName();
    }
    writeHtmlResponse(response, node, node.getName(), bodyText);
  }

  @VisibleForTesting
  void doNews(DocumentManagement documentManagement,
      OpentextDocId opentextDocId, Node node, Response response)
      throws IOException {
    Collaboration collaboration =
        this.soapFactory.newCollaboration(documentManagement);
    NewsInfo newsInfo = null;
    try {
      newsInfo = collaboration.getNews(node.getID());
    } catch (SOAPFaultException soapFaultException) {
      log.log(Level.WARNING, "Error retrieving news item: " + opentextDocId,
          soapFaultException);

      // Some types of children that can be added using the UI
      // seem to cause an error in getNews when loading the
      // attachments. If that happens, we can't get the
      // News-specific data like Headline and Story, but we can
      // still treat the node as a generic container.
      doContainer(documentManagement, opentextDocId, node, response);
      return;
    }
    addChildAnchors(documentManagement, opentextDocId, response);
    addDateMetadata("EffectiveDate", newsInfo.getEffectiveDate(), response);
    addDateMetadata("ExpirationDate", newsInfo.getExpirationDate(), response);
    writeHtmlResponse(response, node,
        newsInfo.getHeadline(), newsInfo.getStory());
  }

  @VisibleForTesting
  void doTopicReply(DocumentManagement documentManagement,
      OpentextDocId opentextDocId, Node node, Response response)
      throws IOException {
    Collaboration collaboration =
        this.soapFactory.newCollaboration(documentManagement);
    DiscussionItem discussionItem = null;
    try {
      discussionItem = collaboration.getTopicReply(node.getID());
    } catch (SOAPFaultException soapFaultException) {
      log.log(Level.WARNING,
          "Error retrieving discussion item: " + opentextDocId,
          soapFaultException);

      // Some types of children that can be added using the UI
      // seem to cause an error in getTopicReply when loading the
      // attachments. If that happens, we can't get the
      // DiscussionItem-specific data like Subject and Content,
      // but we can still treat the node as a generic container.
      doContainer(documentManagement, opentextDocId, node, response);
      return;
    }
    addChildAnchors(documentManagement, opentextDocId, response);
    addDateMetadata("PostedDate", discussionItem.getPostedDate(), response);
    addMemberMetadata("PostedBy", discussionItem.getPostedBy(),
        response, this.soapFactory.newMemberService(documentManagement));
    writeHtmlResponse(response, node,
        discussionItem.getSubject(), discussionItem.getContent());
  }

  @VisibleForTesting
  void doTask(DocumentManagement documentManagement,
      OpentextDocId opentextDocId, Node node, Response response)
      throws IOException {
    Collaboration collaboration =
        this.soapFactory.newCollaboration(documentManagement);
    TaskInfo taskInfo = null;
    try {
      taskInfo = collaboration.getTask(node.getID());
    } catch (SOAPFaultException soapFaultException) {
      log.log(Level.WARNING,
          "Error retrieving task: " + opentextDocId, soapFaultException);
      // If we can't fetch the TaskInfo, at least treat the node
      // as a generic container.
      doContainer(documentManagement, opentextDocId, node, response);
      return;
    }
    addChildAnchors(documentManagement, opentextDocId, response);
    addMemberMetadata("AssignedTo", taskInfo.getAssignedTo(),
        response, this.soapFactory.newMemberService(documentManagement));
    addDateMetadata("CompletionDate", taskInfo.getCompletionDate(), response);
    addDateMetadata("DateAssigned", taskInfo.getDateAssigned(), response);
    addDateMetadata("DueDate", taskInfo.getDueDate(), response);
    addDateMetadata("StartDate", taskInfo.getStartDate(), response);
    addStringMetadata("Priority", taskInfo.getPriority().value(), response);
    addStringMetadata("Status", taskInfo.getStatus().value(), response);
    writeHtmlResponse(response, node,
        node.getName(), taskInfo.getComments(), taskInfo.getInstructions());
  }

  @VisibleForTesting
  void doMilestone(DocumentManagement documentManagement,
      OpentextDocId opentextDocId, Node node, Response response)
      throws IOException {
    Collaboration collaboration =
        this.soapFactory.newCollaboration(documentManagement);
    MilestoneInfo milestoneInfo = null;
    try {
      milestoneInfo = collaboration.getMilestone(node.getID());
    } catch (SOAPFaultException soapFaultException) {
      log.log(Level.WARNING,
          "Error retrieving milestone: " + opentextDocId, soapFaultException);
      // If we can't fetch the MilestoneInfo, at least treat the
      // node as a generic container.
      doContainer(documentManagement, opentextDocId, node, response);
      return;
    }
    addChildAnchors(documentManagement, opentextDocId, response);
    addDateMetadata("ActualDate", milestoneInfo.getActualDate(), response);
    addDateMetadata("OriginalTargetDate",
        milestoneInfo.getOriginalTargetDate(), response);
    addDateMetadata("TargetDate", milestoneInfo.getTargetDate(), response);
    response.addMetadata("Duration",
        String.valueOf(milestoneInfo.getDuration()));
    response.addMetadata("NumActive",
        String.valueOf(milestoneInfo.getNumActive()));
    response.addMetadata("NumCancelled",
        String.valueOf(milestoneInfo.getNumCancelled()));
    response.addMetadata("NumCompleted",
        String.valueOf(milestoneInfo.getNumCompleted()));
    response.addMetadata("NumInProcess",
        String.valueOf(milestoneInfo.getNumInprocess()));
    response.addMetadata("NumIssue",
        String.valueOf(milestoneInfo.getNumIssue()));
    response.addMetadata("NumLate",
        String.valueOf(milestoneInfo.getNumLate()));
    response.addMetadata("NumOnHold",
        String.valueOf(milestoneInfo.getNumOnHold()));
    response.addMetadata("NumPending",
        String.valueOf(milestoneInfo.getNumPending()));
    response.addMetadata("NumTasks",
        String.valueOf(milestoneInfo.getNumTasks()));
    response.addMetadata("PercentCancelled",
        String.valueOf(milestoneInfo.getPercentCancelled()));
    response.addMetadata("PercentComplete",
        String.valueOf(milestoneInfo.getPercentComplete()));
    response.addMetadata("PercentInProcess",
        String.valueOf(milestoneInfo.getPercentInprocess()));
    response.addMetadata("PercentIssue",
        String.valueOf(milestoneInfo.getPercentIssue()));
    response.addMetadata("PercentLate",
        String.valueOf(milestoneInfo.getPercentLate()));
    response.addMetadata("PercentOnHold",
        String.valueOf(milestoneInfo.getPercentOnHold()));
    response.addMetadata("PercentPending",
        String.valueOf(milestoneInfo.getPercentPending()));
    response.addMetadata("Resources",
        String.valueOf(milestoneInfo.getResources()));
    writeHtmlResponse(response, node, node.getName());
  }

  @VisibleForTesting
  void doProject(DocumentManagement documentManagement,
      OpentextDocId opentextDocId, Node node, Response response)
      throws IOException {
    Collaboration collaboration =
        this.soapFactory.newCollaboration(documentManagement);
    ProjectInfo projectInfo = null;
    try {
      projectInfo = collaboration.getProject(node.getID());
    } catch (SOAPFaultException soapFaultException) {
      log.log(Level.WARNING,
          "Error retrieving project: " + opentextDocId, soapFaultException);
      // If we can't fetch the ProjectInfo, at least treat the node
      // as a generic container.
      doContainer(documentManagement, opentextDocId, node, response);
      return;
    }
    addChildAnchors(documentManagement, opentextDocId, response);
    addDateMetadata("StartDate", projectInfo.getStartDate(), response);
    addDateMetadata("TargetDate", projectInfo.getTargetDate(), response);
    addStringMetadata("Goals", projectInfo.getGoals(), response);
    addStringMetadata("Initiatives", projectInfo.getInitiatives(), response);
    addStringMetadata("Mission", projectInfo.getMission(), response);
    addStringMetadata("Objectives", projectInfo.getObjectives(), response);
    addStringMetadata("Status", projectInfo.getStatus().value(), response);
    writeHtmlResponse(response, node, node.getName());
  }

  private void addChildAnchors(DocumentManagement documentManagement,
      OpentextDocId opentextDocId, Response response) {
    try {
      List<Node> children =
          documentManagement.listNodes(opentextDocId.getNodeId(), true);
      for (Node child : children) {
        DocId docId =
            getChildDocId(opentextDocId, child.getName(), child.getID());
        response.addAnchor(this.context.getDocIdEncoder().encodeDocId(docId),
            child.getName());
      }
    } catch (SOAPFaultException soapFaultException) {
      log.log(Level.WARNING,
          "Error retrieving children of node: " + opentextDocId,
          soapFaultException);
    }
  }

  private void writeHtmlResponse(Response response, Node node,
      String header, String... body) throws IOException {
    response.setDisplayUrl(getDisplayUrl(node.getType(), node.getID()));
    response.setContentType("text/html; charset=" + CHARSET.name());
    Writer writer = new OutputStreamWriter(response.getOutputStream(),
        CHARSET);
    writer.write("<!DOCTYPE html>\n<html><head><title>");
    writer.write(escapeContent(node.getName()));
    writer.write("</title></head><body><h1>");
    if (header != null) {
      writer.write(escapeContent(header));
    } else {
      writer.write(escapeContent(node.getName()));
    }
    writer.write("</h1>");
    for (String contentString : body) {
      writer.write("<p>");
      writer.write(escapeContent(contentString));
      writer.write("</p>");
    }
    writer.write("</body></html>");
    writer.flush();
  }

  /* Copied from HtmlResponseWriter. Modified to cope with null
   * arguments.
   */
  private String escapeContent(String raw) {
    if (raw == null) {
      return "";
    }
    return raw.replace("&", "&amp;").replace("<", "&lt;");
  }

  /* Copied from HtmlResponseWriter. */
  private String escapeAttributeValue(String raw) {
    return escapeContent(raw).replace("\"", "&quot;").replace("'", "&apos;");
  }

  private void addStringMetadata(
      String name, String value, Response response) {
    if (!Strings.isNullOrEmpty(value)) {
      response.addMetadata(name, value);
    }
  }

  private void addDateMetadata(
      String name, XMLGregorianCalendar xmlCalendar, Response response) {
    if (xmlCalendar != null) {
      response.addMetadata(name, getDateAsString(xmlCalendar));
    }
  }

  private void addMemberMetadata(String name, Long memberId,
      Response response, MemberService memberService) {
    if (memberId == null || memberId == 0) {
      return;
    }
    try {
      Member member = memberService.getMemberById(memberId);
      addStringMetadata(name, member.getName(), response);
    } catch (SOAPFaultException soapFaultException) {
      log.log(Level.FINE,
          "Failed to look up member for " + name + " = " + memberId,
          soapFaultException);
    }
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
      Date lastModifiedDate = xmlCalendar.toGregorianCalendar().getTime();
      response.setLastModified(lastModifiedDate);
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
    Collaboration newCollaboration(DocumentManagement documentManagement);
    void configure(Config config);
  }

  @VisibleForTesting
  static class SoapFactoryImpl implements SoapFactory {
    private final Authentication_Service authenticationService;
    private final DocumentManagement_Service documentManagementService;
    private final ContentService_Service contentServiceService;
    private final MemberService_Service memberServiceService;
    private final Collaboration_Service collaborationService;
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
      this.collaborationService = new Collaboration_Service(
          Collaboration_Service.class.getResource("Collaboration.wsdl"));
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

    @Override
    public Collaboration newCollaboration(
        DocumentManagement documentManagement) {
      Collaboration collaborationPort =
          collaborationService.getBasicHttpBindingCollaboration();

      setEndpointAddress(
          (BindingProvider) collaborationPort, "Collaboration");
      setAuthenticationHandler(
          (BindingProvider) collaborationPort,
          getAuthenticationToken((BindingProvider) documentManagement));

      return collaborationPort;
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
  static Map<String, String> fixTypeKeys(
      Map<String, String> mapWithTypesAsKeys) {
    Map<String, String> result = new HashMap<String, String>();
    for (Map.Entry<String, String> entry : mapWithTypesAsKeys.entrySet()) {
      String key = OpentextAdaptor.getCanonicalType(entry.getKey());
      result.put(key, entry.getValue());
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
