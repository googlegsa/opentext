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

import static com.google.common.net.HttpHeaders.COOKIE;
import static org.w3c.dom.Node.CDATA_SECTION_NODE;
import static org.w3c.dom.Node.TEXT_NODE;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Splitter;
import com.google.common.base.Strings;
import com.google.common.collect.Lists;
import com.google.common.collect.Sets;
import com.google.common.escape.Escaper;
import com.google.common.net.UrlEscapers;
import com.google.common.primitives.Ints;
import com.google.common.primitives.Longs;
import com.google.enterprise.adaptor.AbstractAdaptor;
import com.google.enterprise.adaptor.Acl;
import com.google.enterprise.adaptor.AdaptorContext;
import com.google.enterprise.adaptor.Config;
import com.google.enterprise.adaptor.DocId;
import com.google.enterprise.adaptor.DocIdPusher;
import com.google.enterprise.adaptor.GroupPrincipal;
import com.google.enterprise.adaptor.IOHelper;
import com.google.enterprise.adaptor.InvalidConfigurationException;
import com.google.enterprise.adaptor.PollingIncrementalLister;
import com.google.enterprise.adaptor.Principal;
import com.google.enterprise.adaptor.Request;
import com.google.enterprise.adaptor.Response;
import com.google.enterprise.adaptor.UserPrincipal;

import com.opentext.ecm.services.authws.AuthenticationException;
import com.opentext.ecm.services.authws.AuthenticationException_Exception;
import com.opentext.ecm.services.authws.AuthenticationService;
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
import com.opentext.livelink.service.core.PageHandle;
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
import com.opentext.livelink.service.memberservice.MemberPrivileges;
import com.opentext.livelink.service.memberservice.MemberSearchOptions;
import com.opentext.livelink.service.memberservice.MemberSearchResults;
import com.opentext.livelink.service.memberservice.MemberService;
import com.opentext.livelink.service.memberservice.MemberService_Service;
import com.opentext.livelink.service.memberservice.SearchColumn;
import com.opentext.livelink.service.memberservice.SearchFilter;
import com.opentext.livelink.service.memberservice.SearchMatching;
import com.opentext.livelink.service.memberservice.SearchScope;
import com.opentext.livelink.service.memberservice.User;

import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.io.Writer;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLConnection;
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
import java.util.ListIterator;
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
import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.FactoryConfigurationError;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPFactory;
import javax.xml.soap.SOAPFault;
import javax.xml.ws.BindingProvider;
import javax.xml.ws.handler.Handler;
import javax.xml.ws.soap.MTOMFeature;
import javax.xml.ws.soap.SOAPFaultException;

/** For getting OpenText repository content into a Google Search Appliance. */
public class OpentextAdaptor extends AbstractAdaptor
    implements PollingIncrementalLister {

  private static final Logger log
      = Logger.getLogger(OpentextAdaptor.class.getName());
  /** Charset used in generated HTML responses. */
  private static final Charset CHARSET = Charset.forName("UTF-8");
  private static final long ONE_DAY_MILLIS = 24 * 60 * 60 * 1000L;

  public static void main(String[] args) {
    AbstractAdaptor.main(new OpentextAdaptor(), args);
  }

  private AdaptorContext context;
  private final SoapFactory soapFactory;
  private String username;
  private String password;
  private String adminUsername;
  private String adminPassword;
  private boolean markAllDocsAsPublic;
  private boolean publicAccessGroupEnabled;
  private String windowsDomain;
  private String globalNamespace;
  private String localNamespace;
  /** Configured start points, with unknown values removed. */
  private List<StartPoint> startPoints;
  private String contentServerUrl;
  private Map<String, String> queryStrings;
  private Map<String, String> objectActions;
  private List<String> excludedNodeTypes;
  private int currentVersionType;
  private boolean indexCategories;
  private boolean indexCategoryNames;
  private boolean indexFolders;
  private boolean indexSearchableAttributesOnly;
  private List<String> includedCategories;
  private List<String> excludedCategories;

  // Cache the definition for OTEmailProperties
  private SortedMap<String, Attribute> emailAttributeDefinitions =
      Collections.synchronizedSortedMap(new TreeMap<String, Attribute>());
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

  // Used by getModifiedDocIds
  private DocumentBuilderFactory documentBuilderFactory;
  private Long lastModDocId;
  private String lastModDate;
  private String lastModTime;
  private Escaper paramEscaper = UrlEscapers.urlFormParameterEscaper();

  /** Possible CWS installation server types. */
  public enum CwsServer {
    IIS, TOMCAT
  }

  public OpentextAdaptor() {
    this(new SoapFactoryImpl());
  }

  @VisibleForTesting
  OpentextAdaptor(SoapFactory soapFactory) {
    this.soapFactory = soapFactory;
  }

  @Override
  public void initConfig(Config config) {
    config.addKey("opentext.directoryServicesUrl", "");
    config.addKey("opentext.webServicesUrl", null);
    config.addKey("opentext.webServicesServer", "");
    config.addKey("opentext.username", null);
    config.addKey("opentext.password", null);
    config.addKey("opentext.adminUsername", "");
    config.addKey("opentext.adminPassword", "");
    config.addKey("opentext.publicAccessGroupEnabled", "false");
    config.addKey("opentext.windowsDomain", "");
    config.addKey("adaptor.namespace", Principal.DEFAULT_NAMESPACE);
    config.addKey("opentext.src", "EnterpriseWS");
    config.addKey("opentext.src.separator", ",");
    config.addKey("opentext.displayUrl.contentServerUrl", null);
    config.addKey("opentext.displayUrl.queryString.default",
        "?func=ll&objAction={0}&objId={1}");
    config.addKey("opentext.displayUrl.objAction.Document", "overview");
    config.addKey("opentext.displayUrl.objAction.default", "properties");
    config.addKey("opentext.excludedNodeTypes", "");
    config.addKey("opentext.excludedNodeTypes.separator", ",");
    config.addKey("opentext.indexFolders", "true");
    config.addKey("opentext.currentVersionType", "-2");
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

    this.markAllDocsAsPublic =
        Boolean.parseBoolean(config.getValue("adaptor.markAllDocsAsPublic"));
    log.log(Level.CONFIG, "adaptor.markAllDocsAsPublic: {0}",
        markAllDocsAsPublic);

    String webServicesUrl = config.getValue("opentext.webServicesUrl");
    String username = config.getValue("opentext.username");
    String password = context.getSensitiveValueDecoder().decodeValue(
        config.getValue("opentext.password"));
    log.log(Level.CONFIG, "opentext.webServicesUrl: {0}", webServicesUrl);
    log.log(Level.CONFIG, "opentext.webServicesServer: {0}",
        config.getValue("opentext.webServicesServer"));
    log.log(Level.CONFIG, "opentext.directoryServicesUrl: {0}",
        config.getValue("opentext.directoryServicesUrl"));
    log.log(Level.CONFIG, "opentext.username: {0}", username);
    this.username = username;
    this.password = password;

    Authentication authentication = soapFactory.newAuthentication();
    String authenticationToken;
    try {
      authenticationToken = getAuthenticationToken(username, password);
    } catch (SOAPFaultException soapFaultException) {
      SOAPFault fault = soapFaultException.getFault();
      String localPart = fault.getFaultCodeAsQName().getLocalPart();
      if (isAuthenticationFailure(localPart)) {
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
    } catch (Exception e) {
      // If a specific Content Web Services server type was
      // configured, don't try the other version, just fail.
      if (!config.getValue("opentext.webServicesServer").isEmpty()) {
        throw e;
      }
      // When no server type is configured, the IIS web services
      // URL is tried first. If an exception is thrown, try the
      // Tomcat web services URL format.
      log.log(Level.CONFIG,
          "Trying Tomcat web services URL after initial error", e);
      soapFactory.setServer(CwsServer.TOMCAT);
      authentication = soapFactory.newAuthentication();
      try {
        authenticationToken = getAuthenticationToken(username, password);
      } catch (SOAPFaultException soapFaultException) {
        SOAPFault fault = soapFaultException.getFault();
        String localPart = fault.getFaultCodeAsQName().getLocalPart();
        if (isAuthenticationFailure(localPart)) {
          throw new InvalidConfigurationException(
              localPart + " (opentext.username: " + username + "): "
              + fault.getFaultString(),
              soapFaultException);
        }
        throw soapFaultException;
      }
    }

    if (!this.markAllDocsAsPublic) {
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
        try {
          getAuthenticationToken(this.adminUsername, this.adminPassword);
        } catch (SOAPFaultException soapFaultException) {
          SOAPFault fault = soapFaultException.getFault();
          String localPart = fault.getFaultCodeAsQName().getLocalPart();
          if (isAuthenticationFailure(localPart)) {
            throw new InvalidConfigurationException(
                localPart
                + " (opentext.adminUsername: " + this.adminUsername + "): "
                + fault.getFaultString(),
                soapFaultException);
          }
          throw soapFaultException;
        }
      }
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
    // Validate the display URLs.
    try {
      // First try the default queryString and objectAction.
      URI uri = getDisplayUrl("default", 0L);
      new ValidatedUri(uri.toString()).logUnreachableHost();
    } catch (URISyntaxException e) {
      throw new InvalidConfigurationException("Invalid display URL", e);
    }
    // Now try the display URLs for specific object types.
    for (String objectType :
         Sets.union(queryStrings.keySet(), objectActions.keySet())) {
      try {
        getDisplayUrl(objectType, 0L);
      } catch (URISyntaxException e) {
        throw new InvalidConfigurationException(
            "Invalid display URL for object type " + objectType, e);
      }
    }

    if (!this.markAllDocsAsPublic) {
      String publicAccessGroupEnabled =
          config.getValue("opentext.publicAccessGroupEnabled");
      log.log(Level.CONFIG,
          "opentext.publicAccessGroupEnabled: {0}", publicAccessGroupEnabled);
      this.publicAccessGroupEnabled =
          Boolean.parseBoolean(publicAccessGroupEnabled);
      this.windowsDomain = config.getValue("opentext.windowsDomain");
      log.log(Level.CONFIG, "opentext.windowsDomain: {0}", this.windowsDomain);
      this.globalNamespace = config.getValue("adaptor.namespace");
      log.log(Level.CONFIG, "adaptor.namespace: {0}", this.globalNamespace);
      this.localNamespace =
          getLocalNamespace(this.globalNamespace, this.contentServerUrl);
      log.log(Level.CONFIG, "local namespace: {0}", this.localNamespace);
    }

    // excludedNodeTypes may override the value for indexFolders,
    // so read this config property first.
    String indexFolders = config.getValue("opentext.indexFolders");
    log.log(Level.CONFIG, "opentext.indexFolders: {0}", indexFolders);
    this.indexFolders = Boolean.parseBoolean(indexFolders);

    String excludedNodeTypes = config.getValue("opentext.excludedNodeTypes");
    separator = config.getValue("opentext.excludedNodeTypes.separator");
    log.log(Level.CONFIG,
        "opentext.excludedNodeTypes: {0}", excludedNodeTypes);
    log.log(Level.CONFIG,
        "opentext.excludedNodeTypes.separator: {0}", separator);
    this.excludedNodeTypes =
        OpentextAdaptor.getExcludedNodeTypes(excludedNodeTypes, separator);
    if (this.excludedNodeTypes.contains("Folder")) {
      this.excludedNodeTypes.remove("Folder");
      this.indexFolders = false;
      log.log(Level.WARNING, "Removed Folder type from excludedNodeTypes;"
          + " folders will be crawled but not indexed.");
    }

    String currentVersionType =
        config.getValue("opentext.currentVersionType");
    log.log(Level.CONFIG,
        "opentext.currentVersionType: {0}", currentVersionType);
    try {
      this.currentVersionType = Integer.parseInt(currentVersionType);
    } catch (NumberFormatException numberFormatException) {
      throw new InvalidConfigurationException(
          "opentext.currentVersionType: " + currentVersionType,
          numberFormatException);
    }

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

    try {
      this.documentBuilderFactory = DocumentBuilderFactory.newInstance();
      context.setPollingIncrementalLister(this);
    } catch (FactoryConfigurationError e) {
      log.log(Level.WARNING,
          "Unable to create XML parser; modified doc id lookup not enabled.",
          e);
    }
  }

  private boolean isAuthenticationFailure(String code) {
    return "Core.LoginFailed".equals(code)
        || "Core.FailedToAuthenticateWithOTDS".equals(code)
        || "AuthenticationService.Application.AuthenticationFailed"
        .equals(code);
  }

  private boolean isPermissionsFailure(
      SOAPFaultException soapFaultException) {
    String code =
        soapFaultException.getFault().getFaultCodeAsQName().getLocalPart();
    return "DocMan.PermissionsError".equals(code)
        || "DocMan.VersionRetrievalError".equals(code);
  }

  @Override
  public void getDocIds(DocIdPusher pusher) throws InterruptedException {
    Authentication authentication = this.soapFactory.newAuthentication();
    String authenticationToken =
        getAuthenticationToken(this.username, this.password);
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

    if (!this.markAllDocsAsPublic) {
      MemberService memberService =
          this.soapFactory.newMemberService(documentManagement);
      Map<GroupPrincipal, List<Principal>> groupDefinitions =
          getGroups(memberService);
      if (this.publicAccessGroupEnabled) {
        List<Principal> publicAccessGroup = getPublicAccessGroup(memberService);
        if (publicAccessGroup.size() > 0) {
          groupDefinitions.put(
              new GroupPrincipal("[Public Access]", this.localNamespace),
              publicAccessGroup);
        }
      }
      if (groupDefinitions.size() > 0) {
        pusher.pushGroupDefinitions(groupDefinitions, true);
      }
    }
  }

  @VisibleForTesting
  Map<GroupPrincipal, List<Principal>> getGroups(MemberService memberService) {
    Map<GroupPrincipal, List<Principal>> groupDefinitions =
        new HashMap<GroupPrincipal, List<Principal>>();
    MemberSearchOptions options = new MemberSearchOptions();
    options.setFilter(SearchFilter.GROUP);
    options.setColumn(SearchColumn.NAME);
    options.setMatching(SearchMatching.STARTSWITH);
    options.setSearch(""); // Empty string matches everything.
    options.setScope(SearchScope.SYSTEM);
    options.setPageSize(50);
    PageHandle handle = memberService.searchForMembers(options);
    if (handle == null) {
      log.log(Level.WARNING, "No groups found");
      return groupDefinitions;
    }
    while (!handle.isFinalPage()) {
      MemberSearchResults results = memberService.getSearchResults(handle);
      if (results == null) {
        log.log(Level.WARNING,
            "getGroups: Search results from page handle were null");
        break;
      }
      List<Member> groups = results.getMembers();
      if (groups == null) {
        log.log(Level.WARNING, "No members found in search results");
        break;
      }
      log.log(Level.FINE, "Processing " + groups.size() + " groups");
      for (Member group : groups) {
        log.log(Level.FINER, "Processing group: " + group.getName());
        if (!isActive(group)) {
          log.log(Level.FINEST, "Is not active: " + group.getName());
          continue;
        }
        List<Member> members = memberService.listMembers(group.getID());
        List<Principal> memberPrincipals = new ArrayList<Principal>();
        for (Member member : members) {
          if (!isActive(member)) {
            log.log(Level.FINEST, "Is not active: " + member.getName());
            continue;
          }
          if ("User".equals(member.getType())) {
            memberPrincipals.add(getUserPrincipal(member));
          } else if ("Group".equals(member.getType())) {
            memberPrincipals.add(getGroupPrincipal(member));
          }
        }
        log.log(Level.FINER,
            "Size of " + group.getName() + ": " + memberPrincipals.size());
        if (memberPrincipals.size() > 0) {
          log.log(Level.FINEST, "Adding group {0}: {1}",
              new Object[] { group.getName(), memberPrincipals });
          groupDefinitions.put(getGroupPrincipal(group), memberPrincipals);
        }
      }
      handle = results.getPageHandle();
    }
    return groupDefinitions;
  }

  @VisibleForTesting
  List<Principal> getPublicAccessGroup(MemberService memberService) {
    List<Principal> publicAccessGroup = new ArrayList<Principal>();
    MemberSearchOptions options = new MemberSearchOptions();
    options.setFilter(SearchFilter.USER);
    options.setColumn(SearchColumn.NAME);
    options.setMatching(SearchMatching.STARTSWITH);
    options.setSearch(""); // Empty string matches everything.
    options.setScope(SearchScope.SYSTEM);
    options.setPageSize(50);
    PageHandle handle = memberService.searchForMembers(options);
    if (handle == null) {
      log.log(Level.WARNING, "No users found");
      return publicAccessGroup;
    }
    while (!handle.isFinalPage()) {
      MemberSearchResults results = memberService.getSearchResults(handle);
      if (results == null) {
        log.log(Level.WARNING,
            "getPublicAccessGroup: Search results from page handle were null");
        break;
      }
      List<Member> users = results.getMembers();
      if (users == null) {
        log.log(Level.WARNING, "No members found in search results");
        break;
      }
      for (Member user : users) {
        if (!(user instanceof User)) { // Just check before casting.
          continue;
        }
        if (!isActive(user)) {
          log.log(Level.FINEST, "Is not active: " + user.getName());
          continue;
        }
        MemberPrivileges memberPrivileges = ((User) user).getPrivileges();
        if (memberPrivileges.isPublicAccessEnabled()) {
          publicAccessGroup.add(getUserPrincipal(user));
        }
      }
      handle = results.getPageHandle();
    }
    log.log(Level.FINER,
        "Size of [Public Access] group: " + publicAccessGroup.size());
    return publicAccessGroup;
  }

  @VisibleForTesting
  UserPrincipal getUserPrincipal(Member user) {
    String name = user.getName();
    int slash = name.indexOf("\\");
    if (slash != -1) {
      return new UserPrincipal(name, this.globalNamespace);
    }
    if (Strings.isNullOrEmpty(this.windowsDomain)) {
      return new UserPrincipal(name, this.localNamespace);
    } else {
      return new UserPrincipal(
          windowsDomain + "\\" + name, this.globalNamespace);
    }
  }

  @VisibleForTesting
  GroupPrincipal getGroupPrincipal(Member group) {
    String name = group.getName();
    int slash = name.indexOf("\\");
    if (slash != -1) {
      return new GroupPrincipal(name, this.globalNamespace);
    } else {
      return new GroupPrincipal(name, this.localNamespace);
    }
  }

  @Override
  public void getModifiedDocIds(DocIdPusher pusher)
      throws IOException, InterruptedException {
    // Log in using CWS and use that token for the search.
    Authentication authentication = this.soapFactory.newAuthentication();
    String authenticationToken =
        getAuthenticationToken(this.username, this.password);

    ArrayList<DocId> docIds = new ArrayList<>();
    int resultCount = 0;
    do {
      String query = getLastModifiedQuery();
      log.log(Level.FINER, "getModifiedDocIds query: {0}", query);
      Element documentElement =
          getXmlSearchResults(authenticationToken, query);
      resultCount = getXmlSearchCount(documentElement);
      log.log(Level.FINER, "getModifiedDocIds result count: " + resultCount);
      if (resultCount > 0) {
        NodeList searchResults =
            documentElement.getElementsByTagName("SearchResult");
        for (int i = 0; i < searchResults.getLength(); i++) {
          String docId = getXmlSearchDocId((Element) searchResults.item(i));
          if (docId != null) {
            docIds.add(new DocId(docId));
          }
        }
        // Cache the last object's id/date/time
        if (docIds.size() > 0) {
          Long nodeId = Longs.tryParse(
              docIds.get(docIds.size() - 1).getUniqueId().split(":")[1]);
          DocumentManagement documentManagement =
              this.soapFactory.newDocumentManagement(authenticationToken);
          Node node = getNodeById(documentManagement, nodeId);
          if (node != null) {
            XMLGregorianCalendar xmlCalendar = node.getModifyDate();
            if (xmlCalendar != null) {
              Date date = xmlCalendar.toGregorianCalendar().getTime();
              this.lastModDocId = nodeId;
              this.lastModDate = new SimpleDateFormat("yyyyMMdd").format(date);
              this.lastModTime = new SimpleDateFormat("HHmmss").format(date);
            }
          }
        }
      }
    } while (resultCount > 0);
    log.log(Level.FINER, "Sending modified doc ids: {0}", docIds);
    pusher.pushDocIds(docIds);
  }

  /* Reads a SearchResult element from Content Server's XML
   * search results and builds a DocId by pulling various parts
   * from the SearchResult, including the names and ids of parent
   * elements and the result item itself. The DocId has the
   * form "<start point id>/<name>/<name>/<name>:<object id>".
   *
   * An example SearchResult element showing only the elements
   * used to construct the DocId:
   *
   * <SearchResult>
   *   <OTLocation><![CDATA[2000 1234 5678 -5678 9012]]></OTLocation>
   *   <OTLocationPath>
   *     <LocationPathString>
   *     Enterprise:Folder 1:Project 1
   *     </LocationPathString>
   *   </OTLocationPath>
   *   <OTName>
   *     Document in Project
   *     <Value lang="en">Document in Project</Value>
   *   </OTName>
   * </SearchResult>
   */
  @VisibleForTesting
  String getXmlSearchDocId(Element resultElement) {
    // Get the list of ids defining the path to the search result
    // item from the OTLocation element.
    List<String> originalIds = new ArrayList<>(
        Splitter.on(" ").omitEmptyStrings().trimResults()
        .splitToList(getTextContent(resultElement, "OTLocation")));
    List<String> ids = getXmlSearchIds(resultElement);
    if (ids.size() == 0) {
      log.log(Level.FINE,
          "Skipping search result with no id path found in OTLocation: {0}",
          originalIds);
      return null;
    }

    // OTLocation includes the search result item's id as the
    // final element. The corresponding list of names doesn't
    // include the search result item, so remove the item id to
    // make the lists parallel.
    String objectId = ids.remove(ids.size() - 1);

    // Look through the StartPoint list. If the result item is a
    // start point, return its id. Otherwise, find the index of a
    // start point in the id path.
    StartPoint startPoint = null;
    int startPointIndex = -1;
    for (StartPoint sp : this.startPoints) {
      String startPointId = String.valueOf(sp.getNodeId());
      if (startPointId.equals(objectId)) {
        return escapeParam(sp.getName()) + ":" + startPointId;
      } else {
        startPointIndex = ids.indexOf(startPointId);
        if (startPointIndex > -1) {
          startPoint = sp;
          break;
        }
      }
    }
    // If the result item is not contained under a configured
    // start point, skip it.
    if (startPointIndex == -1) {
      log.log(Level.FINE,
          "No start point in path; skipping: {0}", originalIds);
      return null;
    }

    // Get the list of names defining the path to the search result
    // item from the LocationPathString element.
    List<String> names = getXmlSearchNames(resultElement);
    if (names.size() != ids.size()) {
      log.log(Level.FINE,
          "Mismatch in names/ids in search results; skipping: {0} {1}",
          new Object[] { names, originalIds });
      return null;
    }

    // The first element in the doc id is the start point; use
    // the value from the config file.
    StringBuilder docId = new StringBuilder();
    docId.append(escapeParam(startPoint.getName()));
    for (int i = startPointIndex + 1; i < names.size(); i++) {
      docId.append("/").append(escapeParam(names.get(i)));
    }
    docId.append("/")
        .append(paramEscaper.escape(getTextContent(resultElement, "OTName")))
        .append(":")
        .append(objectId);

    return docId.toString();
  }

  /* LocationPathString contains a ':' separated list of object
   * names, not including the name of the search result object.
   * Example:
   * <LocationPathString>Enterprise:Folder 1:Project 1</LocationPathString>
   */
  @VisibleForTesting
  List<String> getXmlSearchNames(Element resultElement) {
    return Splitter.on(":").trimResults().omitEmptyStrings()
        .splitToList(getTextContent(resultElement, "LocationPathString"));
  }

  /* OTLocation contains a list of object ids, starting from the
   * root, defining the path to (and including) the search result object.
   * Example:
   * <OTLocation><![CDATA[2000 1234 5678 -5678 9012]]></OTLocation>
   *
   * This method returns a modifiable list.
   */
  @VisibleForTesting
  List<String> getXmlSearchIds(Element resultElement) {
    List<String> ids = new ArrayList<>(
        Splitter.on(" ").omitEmptyStrings().trimResults()
        .splitToList(getTextContent(resultElement, "OTLocation")));
    if (ids.size() == 0) {
      return ids;
    }
    ListIterator<String> iterator = ids.listIterator();
    while (iterator.hasNext()) {
      String id = iterator.next();
      Long idn = Longs.tryParse(id);
      if (idn == null) {
        log.log(Level.FINER, "Invalid id '{0}' in id list {1}; skipping",
            new Object[] {id, ids});
        return Collections.emptyList();
      } else if (idn < 0) {
        iterator.remove(); // Remove volume ids, e.g. Projects.
      }
    }
    return ids;
  }

  /* Results are returned in SearchResult elements, but
   * when there are no results, we get a single SearchResult
   * element containing a text message ("Sorry, no results
   * were found", for example). Check the count instead to
   * see if there are actual results in this response.
   */
  @VisibleForTesting
  int getXmlSearchCount(Element documentElement) {
    String countText =
        getTextContent(documentElement, "NumberResultsThisPage");
    Integer count = Ints.tryParse(countText);
    if (count != null) {
      return count;
    }
    return 0;
  }

  @VisibleForTesting
  Element getXmlSearchResults(String authenticationToken, String query)
      throws IOException {
    URL url = new URL(this.contentServerUrl + "?" + query);
    URLConnection conn = url.openConnection();
    conn.addRequestProperty(COOKIE, "LLCookie=" + authenticationToken);
    try {
      DocumentBuilder builder =
          this.documentBuilderFactory.newDocumentBuilder();
      try (InputStream in = conn.getInputStream()) {
        return builder.parse(in).getDocumentElement();
      }
    } catch (ParserConfigurationException | SAXException e) {
      throw new IOException("Failed to get search results", e);
    }
  }

  /* Helper to read the text content of a node, excluding element
   * children. Some search result elements contain the value
   * we're interested in as text/pcdata plus one or more Value
   * child elements containing multilingual variants of the data.
   */
  private String getTextContent(
      Element container, String contentElementName) {
    NodeList list = container.getElementsByTagName(contentElementName);
    if (list.getLength() != 1) {
      log.log(Level.FINE,
          "Missing/unexpected values for {0}", contentElementName);
      return "";
    }
    StringBuilder stringBuilder = new StringBuilder();
    NodeList children = list.item(0).getChildNodes();
    for (int i = 0; i < children.getLength(); i++) {
      org.w3c.dom.Node child = children.item(i);
      if (child.getNodeType() == CDATA_SECTION_NODE
          || child.getNodeType() == TEXT_NODE) {
        String content = child.getTextContent().trim();
        if (content.length() > 0) {
          stringBuilder.append(content).append(" ");
        }
      }
    }
    if (stringBuilder.length() > 0) {
      stringBuilder.deleteCharAt(stringBuilder.length() - 1);
    }
    return stringBuilder.toString();
  }

  @VisibleForTesting
  String getLastModifiedQuery() {
    StringBuilder query = new StringBuilder();
    query.append("func=search&outputFormat=xml&findSimilar=false")
        .append("&functionMenu=false&hhTerms=false&hitHightlight=false")
        .append("&sortByRegion=OTModifyDate&sortDirection=asc")
        .append("&startAt=1&goFor=100");
    for (int i = 0; i < this.startPoints.size(); i++) {
      query.append("&Location_ID").append(i + 1).append("=")
          .append(this.startPoints.get(i).getNodeId());
    }
    if (this.lastModDate == null) {
      // Search within last day.
      SimpleDateFormat dateFormat = new SimpleDateFormat("yyyyMMdd");
      this.lastModDate = dateFormat.format(
          new Date(System.currentTimeMillis() - ONE_DAY_MILLIS));
      this.lastModTime = "000000";
    }
    query.append("&where1=")
        .append(
            escapeParam("[QLREGION \"OTModifyDate\"] = \"{0}\"",
                this.lastModDate))
        .append("&boolean2=AND")
        .append("&where2=")
        .append(
            escapeParam("[QLREGION \"OTModifyTime\"] > \"{0}\"",
                this.lastModTime))
        .append("&boolean3=OR")
        .append("&where3=")
        .append(
            escapeParam("[QLREGION \"OTModifyDate\"] > \"{0}\"",
                this.lastModDate));
    return query.toString();
  }

  private String escapeParam(String param, String... values) {
    if (values.length == 0) {
      return paramEscaper.escape(param);
    }
    return paramEscaper.escape(
        MessageFormat.format(param, (Object[]) values));
  }

  /** Gives the bytes of a document referenced with id. */
  @Override
  public void getDocContent(Request req, Response resp)
      throws IOException {

    Authentication authentication = this.soapFactory.newAuthentication();
    String authenticationToken =
        getAuthenticationToken(this.username, this.password);
    DocumentManagement documentManagement =
        this.soapFactory.newDocumentManagement(authenticationToken);
    OpentextDocId opentextDocId;
    try {
      opentextDocId = new OpentextDocId(req.getDocId());
    } catch (IllegalArgumentException e) {
      // Non-Content Server doc ids can be generated within the
      // GSA from, for example, links within crawled documents.
      log.log(Level.FINE, "Invalid doc id {0}", req.getDocId());
      resp.respondNotFound();
      return;
    }
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

    if (node.getType().equals("Folder") && !this.indexFolders) {
      resp.setNoIndex(true);
    }
    if (!markAllDocsAsPublic) {
      doAcl(documentManagement, opentextDocId, node, resp);
    }
    doCategories(documentManagement, node, resp);
    doNodeFeatures(node, resp);
    doNodeProperties(documentManagement, node, resp);
    try {
      resp.setDisplayUrl(getDisplayUrl(node.getType(), node.getID()));
    } catch (URISyntaxException e) {
      // This should have been caught in init(), what went wrong here?
      throw new IOException("Invalid display URL for object ID "
          + node.getID() + " of type " + node.getType(), e);
    }
    switch (node.getType()) {
      case "Collection":
        doCollection(documentManagement, opentextDocId, node, resp);
        break;
      case "GenericNode:146": // Custom View
        // fall through
      case "GenericNode:335": // XML DTD
        // fall through
      case "Document":
        doDocument(documentManagement, opentextDocId, node, req, resp);
        break;
      case "Email":
        doEmail(documentManagement, opentextDocId, node, req, resp);
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
        authenticationToken =
            getAuthenticationToken(this.adminUsername, this.adminPassword);
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
    if (this.publicAccessGroupEnabled) {
      NodeRight publicRight = nodeRights.getPublicRight();
      if (publicRight != null) {
        NodePermissions publicPermissions = publicRight.getPermissions();
        if (publicPermissions.isSeeContentsPermission()) {
          permitGroups.add(
              new GroupPrincipal("[Public Access]", this.localNamespace));
        }
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
        if (!isActive(member)) {
          log.log(Level.FINEST, "Is not active: " + member.getName());
          continue;
        }
        if ("User".equals(member.getType())) {
          permitUsers.add(getUserPrincipal(member));
        } else if ("Group".equals(member.getType())) {
          permitGroups.add(getGroupPrincipal(member));
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
      if (!isActive(member)) {
        log.log(Level.FINEST, "Is not active: " + member.getName());
        continue;
      }
      if ("User".equals(member.getType())) {
        users.add(getUserPrincipal(member));
      } else if ("Group".equals(member.getType())) {
        groups.add(getGroupPrincipal(member));
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
      if (isPermissionsFailure(soapFaultException)) {
        log.log(Level.FINE, "{0}: {1}",
            new Object[] {
              soapFaultException.getFault().getFaultString(), opentextDocId });
        response.respondNotFound();
      } else {
        log.log(Level.WARNING,
            "Error retrieving container contents: " + opentextDocId,
            soapFaultException);
      }
      return;
    }

    response.setContentType("text/html; charset=" + CHARSET.name());
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

  private Node getNodeById(DocumentManagement documentManagement, long id) {
    // Use the object id to look up the node.
    Node node;
    try {
      node = documentManagement.getNode(id);
      if (node == null) {
        log.log(Level.FINER, "No item for id: " + id);
        return null;
      }
    } catch (SOAPFaultException soapFaultException) {
      log.log(Level.WARNING, "Error retrieving item: " + id,
          soapFaultException);
      return null;
    }
    return node;
  }

  @VisibleForTesting
  Node getNode(DocumentManagement documentManagement,
      OpentextDocId opentextDocId) {
    log.log(Level.FINER, "Looking up docId: " + opentextDocId);

    // Use the object id to look up the node.
    Node node = getNodeById(documentManagement, opentextDocId.getNodeId());
    if (node == null) {
      log.log(Level.FINER, "No item for id: " + opentextDocId);
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
      OpentextDocId opentextDocId, Node documentNode,
      Request request, Response response) throws IOException {
    if (!documentNode.isIsVersionable()) {
      throw new UnsupportedOperationException(
          "Document does not support versions: " + opentextDocId);
    }

    Version version;
    try {
      version = documentManagement.getVersion(documentNode.getID(),
        this.currentVersionType);
    } catch (SOAPFaultException soapFaultException) {
      if (isPermissionsFailure(soapFaultException)) {
        log.log(Level.FINE, "{0}: {1}",
            new Object[] {
              soapFaultException.getFault().getFaultString(), opentextDocId });
        response.respondNotFound();
      } else {
        log.log(Level.WARNING,
            "Error retrieving version: " + opentextDocId,
            soapFaultException);
      }
      return;
    }
    XMLGregorianCalendar fileModifyDate = version.getFileModifyDate();
    if (fileModifyDate != null
        && request.canRespondWithNoContent(
            new Date(fileModifyDate.toGregorianCalendar().getTimeInMillis()
                + ONE_DAY_MILLIS))) {
      // To avoid issues with time zones, we only count an object as
      // unmodified if its last modified time is more than a day before
      // the last crawl time.
      log.log(Level.FINER, "Content not modified: " + opentextDocId);
      response.respondNoContent();
      return;
    }
    long fileDataSize = version.getFileDataSize();
    // The GSA does not support files larger than 2 GB.
    if (fileDataSize == 0 || fileDataSize > (2L << 30)) {
        // We must call getOutputStream to avoid a library error.
        response.getOutputStream();
        log.log(Level.FINE, "Skipping content for {0} based on size: {1}",
            new Object[] { opentextDocId, fileDataSize });
        return;
    }
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
  URI getDisplayUrl(String objectType, long objectId)
      throws URISyntaxException {
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
    return new ValidatedUri(builder.toString()).getUri();
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

  /*
   * Return email content. Extract the email data available as
   * metadata, then send the email message file in the same way
   * as a document. Email objects can also have Category metadata;
   * only send email-specific attributes here.
   */
  @VisibleForTesting
  void doEmail(DocumentManagement documentManagement,
      OpentextDocId opentextDocId, Node node,
      Request request, Response response) throws IOException {
    Metadata metadata = node.getMetadata();
    if (metadata != null) {
      List<AttributeGroup> attributeGroups = metadata.getAttributeGroups();
      if (attributeGroups != null) {
        for (AttributeGroup attributeGroup : attributeGroups) {
          if (!"OTEmailProperties".equals(attributeGroup.getType())) {
            continue;
          }
          cacheEmailMetadataDefinition(documentManagement, attributeGroup);
          doAttributeGroup(
              response, null, attributeGroup, this.emailAttributeDefinitions);
        }
      }
    }
    doDocument(documentManagement, opentextDocId, node, request, response);
  }

  /* Email metadata uses the same data structures as Category
   * metadata. However, there are observed differences in the
   * attribute group definition that lead us to prefer a separate
   * definition cache.
   *
   * Email attribute definitions can return null for
   * isSearchable. Assume they're searchable.
   */
  private void cacheEmailMetadataDefinition(
      DocumentManagement documentManagement,
      AttributeGroup emailAttributeGroup) throws IOException {
    synchronized (this.emailAttributeDefinitions) {
      if (this.emailAttributeDefinitions.size() == 0) {
        AttributeGroupDefinition def =
            documentManagement.getAttributeGroupDefinition(
                emailAttributeGroup.getType(), emailAttributeGroup.getKey());
        List<Attribute> attributes = def.getAttributes();
        for (Attribute attribute : attributes) {
          if (attribute instanceof PrimitiveAttribute) {
            if (attribute.isSearchable() == null) {
              attribute.setSearchable(Boolean.TRUE);
            }
            this.emailAttributeDefinitions.put(attribute.getKey(), attribute);
          } else if (attribute instanceof SetAttribute) {
            List<Attribute> setAttributes =
                ((SetAttribute) attribute).getAttributes();
            for (Attribute setAttribute : setAttributes) {
              if (setAttribute instanceof PrimitiveAttribute) {
                if (setAttribute.isSearchable() == null) {
                  setAttribute.setSearchable(Boolean.TRUE);
                }
                this.emailAttributeDefinitions.put(
                    setAttribute.getKey(), setAttribute);
              }
            }
          }
        }
      }
    }
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
      doAttributeGroup(
          response, memberService, attributeGroup, this.attributeDefinitions);
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
    if (((this.includedCategories != null)
            && !this.includedCategories.contains(categoryId))
        || ((this.excludedCategories != null)
            && this.excludedCategories.contains(categoryId))) {
      return false;
    }
    return true;
  }

  @VisibleForTesting
  void cacheCategoryDefinition(
      AttributeGroup attributeGroup, DocumentManagement documentManagement) {
    synchronized (this.categoryDefinitions) {
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
              if (setAttribute instanceof PrimitiveAttribute) {
                this.attributeDefinitions.put(
                    setAttribute.getKey(), setAttribute);
              }
              if (attribute instanceof UserAttribute) {
                this.categoriesWithUserAttributes
                    .add(categoryDefinition.getKey());
              }
            }
          }
        }
      }
    }
  }

  private void doAttributeGroup(Response response, MemberService memberService,
      AttributeGroup attributeGroup,
      Map<String, Attribute> attributeDefinitions) {
    List<DataValue> dataValues = attributeGroup.getValues();

    for (DataValue dataValue : dataValues) {
      if (dataValue instanceof PrimitiveValue) {
        doPrimitiveValue(
            (PrimitiveValue) dataValue, response,
                attributeDefinitions, memberService);
      } else if (dataValue instanceof RowValue) {
        doRowValue((RowValue) dataValue, response,
            attributeDefinitions, memberService);
      } else if (dataValue instanceof TableValue) {
        doTableValue((TableValue) dataValue, response,
            attributeDefinitions, memberService);
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
      if (attribute.isSearchable() != null) {
        isSearchable = attribute.isSearchable();
      }
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

  private String getAuthenticationToken(String username, String password) {
    com.opentext.ecm.services.authws.Authentication dsAuthentication =
        this.soapFactory.newDsAuthentication();
    if (dsAuthentication == null) {
      return this.soapFactory.newAuthentication().authenticateUser(
          username, password);
    } else {
      String dsAuthToken;
      try {
        dsAuthToken = dsAuthentication.authenticate(username, password);
      } catch (AuthenticationException_Exception e) {
        // Construct a SOAPFaultException and throw that to make
        // this more like the direct Content Server
        // Authentication service
        String localPart = "Local.AuthenticationException";
        StringBuilder message = new StringBuilder(e.getMessage());
        AuthenticationException authException = e.getFaultInfo();
        if (authException != null) {
          localPart = authException.getFaultCode();
          if (authException.getParameters() != null) {
            for (AuthenticationException.Parameters.Entry param
                     : authException.getParameters().getEntry()) {
              message.append(" [").append(param.getKey()).append(" = ")
                  .append(param.getValue()).append("]");
            }
          }
        }
        try {
          throw new SOAPFaultException(
              SOAPFactory.newInstance().createFault(
                  message.toString(),
                  new QName("urn:api.ecm.opentext.com", localPart, "")));
        } catch (SOAPException se) {
          // Unable to construct a SOAPFaultException; throw the original
          throw new RuntimeException(message.toString(), e);
        }
      }
      return this.soapFactory.newAuthentication().validateUser(dsAuthToken);
    }
  }

  @VisibleForTesting
  interface SoapFactory {
    com.opentext.ecm.services.authws.Authentication newDsAuthentication();
    Authentication newAuthentication();
    DocumentManagement newDocumentManagement(String authenticationToken);
    ContentService newContentService(DocumentManagement documentManagement);
    MemberService newMemberService(DocumentManagement documentManagement);
    Collaboration newCollaboration(DocumentManagement documentManagement);
    void configure(Config config);
    void setServer(CwsServer type);
  }

  @VisibleForTesting
  static class SoapFactoryImpl implements SoapFactory {
    private final AuthenticationService dsAuthenticationService;
    private final Authentication_Service authenticationService;
    private final DocumentManagement_Service documentManagementService;
    private final ContentService_Service contentServiceService;
    private final MemberService_Service memberServiceService;
    private final Collaboration_Service collaborationService;
    private String directoryServicesUrl;
    private String webServicesUrl;
    private boolean iis;

    SoapFactoryImpl() {
      this.dsAuthenticationService = new AuthenticationService(
          AuthenticationService.class.getResource("Authentication-ds.wsdl"));
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
      return this.webServicesUrl + serviceName + (iis ? ".svc" : "");
    }

    @Override
    public com.opentext.ecm.services.authws.Authentication
        newDsAuthentication() {
      if (this.directoryServicesUrl.isEmpty()) {
        return null;
      }
      com.opentext.ecm.services.authws.Authentication dsAuthenticationPort =
          this.dsAuthenticationService.getAuthenticationPort();
      ((BindingProvider) dsAuthenticationPort).getRequestContext().put(
          BindingProvider.ENDPOINT_ADDRESS_PROPERTY,
          this.directoryServicesUrl + "Authentication");
      return dsAuthenticationPort;
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
      this.directoryServicesUrl =
          config.getValue("opentext.directoryServicesUrl");
      if (!this.directoryServicesUrl.isEmpty()) {
        if (!this.directoryServicesUrl.endsWith("/")) {
          this.directoryServicesUrl += "/";
        }
      }
      this.webServicesUrl = config.getValue("opentext.webServicesUrl");
      String server = config.getValue("opentext.webServicesServer");
      if (server.isEmpty()) {
        this.iis = true;
      } else {
        this.iis = CwsServer.IIS.name().equalsIgnoreCase(server);
      }
    }

    @Override
    public void setServer(CwsServer server) {
      this.iis = (CwsServer.IIS == server);
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

  private static boolean isActive(Member member) {
    if (member.isDeleted()) {
      return false;
    }
    if ("User".equals(member.getType())) {
      if (!((User) member).getPrivileges().isLoginEnabled()) {
        return false;
      }
    }
    return true;
  }

  @VisibleForTesting
  static String getLocalNamespace(String globalNamespace, String displayUrl) {
    URI uri = URI.create(displayUrl);
    String localNamespace = uri.getHost();
    if (localNamespace == null) {
      throw new InvalidConfigurationException(displayUrl);
    }
    localNamespace = localNamespace.replace('.', '-');
    int port = uri.getPort();
    if (port != -1) {
      localNamespace += "_" + port;
    }
    return globalNamespace + "_" + localNamespace;
  }
}
