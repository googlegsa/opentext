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

import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.common.base.Joiner;
import com.google.common.collect.Lists;
import com.google.common.collect.Sets;
import com.google.enterprise.adaptor.Acl;
import com.google.enterprise.adaptor.AdaptorContext;
import com.google.enterprise.adaptor.Config;
import com.google.enterprise.adaptor.DocId;
import com.google.enterprise.adaptor.DocIdPusher;
import com.google.enterprise.adaptor.GroupPrincipal;
import com.google.enterprise.adaptor.InvalidConfigurationException;
import com.google.enterprise.adaptor.Principal;
import com.google.enterprise.adaptor.Request;
import com.google.enterprise.adaptor.Response;
import com.google.enterprise.adaptor.UserPrincipal;

import com.opentext.livelink.service.collaboration.Collaboration;
import com.opentext.livelink.service.collaboration.DiscussionItem;
import com.opentext.livelink.service.collaboration.MilestoneInfo;
import com.opentext.livelink.service.collaboration.NewsInfo;
import com.opentext.livelink.service.collaboration.ProjectInfo;
import com.opentext.livelink.service.collaboration.ProjectStatus;
import com.opentext.livelink.service.collaboration.TaskInfo;
import com.opentext.livelink.service.collaboration.TaskPriority;
import com.opentext.livelink.service.collaboration.TaskStatus;
import com.opentext.livelink.service.core.Authentication;
import com.opentext.livelink.service.core.BooleanValue;
import com.opentext.livelink.service.core.ContentService;
import com.opentext.livelink.service.core.DateValue;
import com.opentext.livelink.service.core.IntegerValue;
import com.opentext.livelink.service.core.PrimitiveValue;
import com.opentext.livelink.service.core.RowValue;
import com.opentext.livelink.service.core.StringValue;
import com.opentext.livelink.service.core.TableValue;
import com.opentext.livelink.service.docman.Attribute;
import com.opentext.livelink.service.docman.AttributeGroup;
import com.opentext.livelink.service.docman.AttributeGroupDefinition;
import com.opentext.livelink.service.docman.DocumentManagement;
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

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Proxy;
import java.net.URI;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.activation.DataHandler;
import javax.activation.DataSource;
import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;
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
    Config config = new Config();
    config.addKey("opentext.webServicesUrl", "webServicesUrl/");
    SoapFactoryImpl factory = new SoapFactoryImpl();
    factory.configure(config);
    Authentication authentication = factory.newAuthentication();
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
    Config config = new Config();
    config.addKey("opentext.webServicesUrl", "webServicesUrl");
    SoapFactoryImpl factory = new SoapFactoryImpl();
    factory.configure(config);
    assertEquals("webServicesUrl/Authentication",
        factory.getWebServiceAddress("Authentication"));

    config.overrideKey("opentext.webServicesUrl", "webServicesUrl/");
    factory.configure(config);
    assertEquals("webServicesUrl/Authentication",
        factory.getWebServiceAddress("Authentication"));
  }

  @Test
  public void testAuthenticateUser() {
    SoapFactoryMock soapFactory = new SoapFactoryMock();
    OpentextAdaptor adaptor = new OpentextAdaptor(soapFactory);
    assertFalse("authUser called before init",
        soapFactory.authenticationMock.authenticateUserCalled);
    AdaptorContext context = ProxyAdaptorContext.getInstance();
    Config config = initConfig(adaptor, context);
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
    config.addKey("opentext.adminUsername", "");
    config.addKey("opentext.adminPassword", "");
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
    config.addKey("opentext.adminUsername", "");
    config.addKey("opentext.adminPassword", "");
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
    config.addKey("opentext.adminUsername", "");
    config.addKey("opentext.adminPassword", "");
    config.addKey("opentext.webServicesUrl",
        "http://example.com/les-services/services");
    adaptor.init(context);
  }

  @Test
  public void testAuthenticateAdminUserInvalidUser() {
    thrown.expect(InvalidConfigurationException.class);
    thrown.expectMessage("javax.xml.ws.soap.SOAPFaultException");

    SoapFactoryMock soapFactory = new SoapFactoryMock();
    OpentextAdaptor adaptor = new OpentextAdaptor(soapFactory);
    assertFalse("authUser called before init",
        soapFactory.authenticationMock.authenticateUserCalled);
    AdaptorContext context = ProxyAdaptorContext.getInstance();
    Config config = context.getConfig();
    config.addKey("opentext.username", "validuser");
    config.addKey("opentext.password", "validpassword");
    config.addKey("opentext.adminUsername", "invaliduser");
    config.addKey("opentext.adminPassword", "validpassword");
    config.addKey("opentext.webServicesUrl",
        "http://example.com/les-services/services");
    adaptor.init(context);
  }

  @Test
  public void testDefaultStartPoints() {
    SoapFactoryMock soapFactory = new SoapFactoryMock();
    OpentextAdaptor adaptor = new OpentextAdaptor(soapFactory);
    AdaptorContext context = ProxyAdaptorContext.getInstance();
    Config config = initConfig(adaptor, context);
    adaptor.init(context);
    List<StartPoint> startPoints = adaptor.getStartPoints();
    assertEquals(1, startPoints.size());
    assertStartPointEquals(startPoints.get(0),
        StartPoint.Type.VOLUME, "EnterpriseWS", 2000);
  }

  @Test
  public void testInitNoStartPoints() {
    thrown.expect(InvalidConfigurationException.class);
    thrown.expectMessage("No valid opentext.src values");

    SoapFactoryMock soapFactory = new SoapFactoryMock();
    OpentextAdaptor adaptor = new OpentextAdaptor(soapFactory);
    AdaptorContext context = ProxyAdaptorContext.getInstance();
    Config config = context.getConfig();
    adaptor.initConfig(config);
    config.overrideKey("opentext.username", "validuser");
    config.overrideKey("opentext.password", "validpassword");
    config.overrideKey("opentext.webServicesUrl",
        "http://example.com/les-services/services");
    config.overrideKey("opentext.src", "");
    adaptor.init(context);
  }

  @Test
  public void testNodeStartPoints() {
    List<StartPoint> startPoints
        = OpentextAdaptor.getStartPoints("11, 12, 13", ",");
    assertEquals(3, startPoints.size());
    assertStartPointEquals(startPoints.get(0),
        StartPoint.Type.NODE, "11", 11);
    assertStartPointEquals(startPoints.get(1),
        StartPoint.Type.NODE, "12", 12);
    assertStartPointEquals(startPoints.get(2),
        StartPoint.Type.NODE, "13", 13);
  }

  @Test
  public void testMixedStartPoints() {
    List<StartPoint> startPoints =
        OpentextAdaptor.getStartPoints("11, 12, EnterpriseWS", ",");
    assertEquals(3, startPoints.size());
    assertStartPointEquals(startPoints.get(0),
        StartPoint.Type.NODE, "11", 11);
    assertStartPointEquals(startPoints.get(1),
        StartPoint.Type.NODE, "12", 12);
    assertStartPointEquals(startPoints.get(2),
        StartPoint.Type.VOLUME, "EnterpriseWS", -1);
  }

  @Test
  public void testInvalidStartPoints() {
    List<StartPoint> startPoints =
        OpentextAdaptor.getStartPoints(
            "11x, 12, EnterpriseWS, My Favorite Folder", ",");
    assertEquals(2, startPoints.size());
    assertStartPointEquals(startPoints.get(0),
        StartPoint.Type.NODE, "12", 12);
    assertStartPointEquals(startPoints.get(1),
        StartPoint.Type.VOLUME, "EnterpriseWS", -1);
  }

  @Test
  public void testNoValidStartPoints() {
    List<StartPoint> startPoints = OpentextAdaptor.getStartPoints(
        "11x, , My Favorite Folder", ",");
    assertEquals(0, startPoints.size());
  }

  @Test
  public void testStartPointSeparator() {
    List<StartPoint> startPoints = OpentextAdaptor.getStartPoints(
        "11x : 12 : EnterpriseWS : My Favorite Folder", ":");
    assertEquals(2, startPoints.size());
    assertStartPointEquals(startPoints.get(0),
        StartPoint.Type.NODE, "12", 12);
    assertStartPointEquals(startPoints.get(1),
        StartPoint.Type.VOLUME, "EnterpriseWS", -1);
  }

  @Test
  public void testDefaultExcludedNodeTypes() {
    SoapFactoryMock soapFactory = new SoapFactoryMock();
    OpentextAdaptor adaptor = new OpentextAdaptor(soapFactory);
    AdaptorContext context = ProxyAdaptorContext.getInstance();
    Config config = initConfig(adaptor, context);
    adaptor.init(context);
    List<String> excludedNodeTypes = adaptor.getExcludedNodeTypes();
    assertEquals(0, excludedNodeTypes.size());
  }

  @Test
  public void testGetExcludedNodeTypes() {
    List<String> excludedNodeTypes =
        OpentextAdaptor.getExcludedNodeTypes("Folder, 432", ",");
    assertEquals(
        Lists.newArrayList("Folder", "GenericNode:432"), excludedNodeTypes);
  }

  @Test
  public void testEmptyExcludedNodeTypes() {
    List<String> excludedNodeTypes =
        OpentextAdaptor.getExcludedNodeTypes("", ",");
    assertEquals(0, excludedNodeTypes.size());
  }

  @Test
  public void testDefaultGetDocIds() throws InterruptedException {
    SoapFactoryMock soapFactory = new SoapFactoryMock();
    OpentextAdaptor adaptor = new OpentextAdaptor(soapFactory);
    AdaptorContext context = ProxyAdaptorContext.getInstance();
    Config config = initConfig(adaptor, context);
    adaptor.init(context);

    DocIdPusherMock docIdPusherMock = new DocIdPusherMock();
    adaptor.getDocIds(
        Proxies.newProxyInstance(DocIdPusher.class, docIdPusherMock));
    assertEquals(1, docIdPusherMock.docIds.size());
    assertEquals(
        "EnterpriseWS:2000", docIdPusherMock.docIds.get(0).getUniqueId());
  }

  @Test
  public void testValidateDocIds() throws InterruptedException {
    SoapFactoryMock soapFactory = new SoapFactoryMock();
    OpentextAdaptor adaptor = new OpentextAdaptor(soapFactory);
    AdaptorContext context = ProxyAdaptorContext.getInstance();
    Config config = initConfig(adaptor, context);
    config.overrideKey("opentext.src", "1001, 1002, 1003");
    adaptor.init(context);

    DocIdPusherMock docIdPusherMock = new DocIdPusherMock();
    adaptor.getDocIds(
        Proxies.newProxyInstance(DocIdPusher.class, docIdPusherMock));
    assertEquals(2, docIdPusherMock.docIds.size());
    assertEquals("1001:1001", docIdPusherMock.docIds.get(0).getUniqueId());
    assertEquals("1003:1003", docIdPusherMock.docIds.get(1).getUniqueId());
  }

  @Test
  public void testGetNodeStartPoint() throws InterruptedException {
    SoapFactoryMock soapFactory = new SoapFactoryMock();
    OpentextAdaptor adaptor = new OpentextAdaptor(soapFactory);
    AdaptorContext context = ProxyAdaptorContext.getInstance();
    Config config = initConfig(adaptor, context);
    config.overrideKey("opentext.src", "EnterpriseWS");
    adaptor.init(context);

    DocumentManagement documentManagement =
        soapFactory.newDocumentManagement("token");
    Node node = adaptor.getNode(documentManagement,
        new OpentextDocId(new DocId("EnterpriseWS:2000")));
    assertNotNull(node);
    assertEquals(2000, node.getID());
    assertEquals("Enterprise Workspace", node.getName());

    assertNull(adaptor.getNode(documentManagement,
            new OpentextDocId(new DocId("InvalidStartPoint:1111"))));
  }

  @Test
  public void testGetNodePath() throws InterruptedException {
    SoapFactoryMock soapFactory = new SoapFactoryMock();
    OpentextAdaptor adaptor = new OpentextAdaptor(soapFactory);
    AdaptorContext context = ProxyAdaptorContext.getInstance();
    Config config = initConfig(adaptor, context);
    adaptor.init(context);

    DocumentManagement documentManagement =
        soapFactory.newDocumentManagement("token");

    NodeMock testNode = new NodeMock(3214, "Important Document");
    testNode.setStartPointId(2000);
    testNode.setPath("folder 1", "folder 2", "Important Document");
    soapFactory.documentManagementMock.addNode(testNode);

    DocId docId =
        new DocId("EnterpriseWS/folder+1/folder+2/Important+Document:3214");
    Node node = adaptor.getNode(documentManagement, new OpentextDocId(docId));

    assertNotNull("Couldn't find test node", node);
    assertEquals(3214, node.getID());
    assertEquals("Important Document", node.getName());
  }

  @Test
  public void testGetNodePathWithVolume() throws InterruptedException {
    SoapFactoryMock soapFactory = new SoapFactoryMock();

    NodeMock projectNode = new NodeMock(3214, "Important Project");
    projectNode.setStartPointId(2000);
    projectNode.setParentID(2000);
    projectNode.setPath("Important Project");
    soapFactory.documentManagementMock.addNode(projectNode);

    NodeMock folderInProjectNode = new NodeMock(4100, "Folder in Project");
    folderInProjectNode.setStartPointId(2000);
    folderInProjectNode.setParentID(-1 * projectNode.getID());
    folderInProjectNode.setPath("Important Project", "Folder in Project");
    soapFactory.documentManagementMock.addNode(folderInProjectNode);

    NodeMock documentNode = new NodeMock(5100, "Document under Project");
    documentNode.setStartPointId(2000);
    documentNode.setParentID(folderInProjectNode.getID());
    documentNode.setPath(
        "Important Project", "Folder in Project", "Document under Project");
    soapFactory.documentManagementMock.addNode(documentNode);

    OpentextAdaptor adaptor = new OpentextAdaptor(soapFactory);
    AdaptorContext context = ProxyAdaptorContext.getInstance();
    Config config = initConfig(adaptor, context);
    config.overrideKey("opentext.src", "EnterpriseWS," + projectNode.getID());
    adaptor.init(context);

    DocumentManagement documentManagement =
        soapFactory.newDocumentManagement("token");

    DocId docId = new DocId("EnterpriseWS/Important+Project/Folder+in+Project:"
        + folderInProjectNode.getID());
    Node node = adaptor.getNode(documentManagement, new OpentextDocId(docId));
    assertNotNull("Couldn't find test node", node);
    assertEquals(folderInProjectNode.getID(), node.getID());
    assertEquals(folderInProjectNode.getName(), node.getName());

    docId = new DocId("EnterpriseWS/Important+Project/Folder+in+Project/"
        + "Document+under+Project:" + documentNode.getID());
    node = adaptor.getNode(documentManagement, new OpentextDocId(docId));
    assertNotNull("Couldn't find test node", node);
    assertEquals(documentNode.getID(), node.getID());
    assertEquals(documentNode.getName(), node.getName());

    // Test nodes with the project as the start point.
    docId = new DocId(projectNode.getID() + "/Folder+in+Project/"
        + "Document+under+Project:" + documentNode.getID());
    node = adaptor.getNode(documentManagement, new OpentextDocId(docId));
    assertNotNull("Couldn't find test node", node);
    assertEquals(documentNode.getID(), node.getID());
    assertEquals(documentNode.getName(), node.getName());

    docId = new DocId(projectNode.getID()
        + "/Folder+in+Project:" + folderInProjectNode.getID());
    node = adaptor.getNode(documentManagement, new OpentextDocId(docId));
    assertNotNull("Couldn't find test node", node);
    assertEquals(folderInProjectNode.getID(), node.getID());
    assertEquals(folderInProjectNode.getName(), node.getName());
  }

  @Test
  public void testGetChildDocId() {
    SoapFactoryMock soapFactory = new SoapFactoryMock();
    OpentextAdaptor adaptor = new OpentextAdaptor(soapFactory);

    OpentextDocId parentOpentextDocId =
        new OpentextDocId(new DocId("456:456"));
    DocId childDocId =
        adaptor.getChildDocId(parentOpentextDocId, "Child Name", 123);
    assertEquals("456/Child+Name:123", childDocId.getUniqueId());
    parentOpentextDocId =
        new OpentextDocId(new DocId("EnterpriseWS/Folder/Container/Doc:678"));
    childDocId =
        adaptor.getChildDocId(parentOpentextDocId, "Child Name", 123);
    assertEquals("EnterpriseWS/Folder/Container/Doc/Child+Name:123",
        childDocId.getUniqueId());
  }

  @Test
  public void testDoContainer() throws IOException {
    SoapFactoryMock soapFactory = new SoapFactoryMock();

    // Set up a test folder with content.
    NodeMock containerNode = new NodeMock(3000, "Folder");
    containerNode.setStartPointId(2000);
    containerNode.setPath("Folder");
    soapFactory.documentManagementMock.addNode(containerNode);
    for (int i = 1; i <= 3; i++) {
      NodeMock testNode = new NodeMock(4000 + i, "Document " + i);
      testNode.setStartPointId(2000);
      testNode.setPath("Folder", "Document " + i);
      soapFactory.documentManagementMock.addNode(testNode);
    }

    OpentextAdaptor adaptor = new OpentextAdaptor(soapFactory);
    AdaptorContext context = ProxyAdaptorContext.getInstance();
    Config config = initConfig(adaptor, context);
    adaptor.init(context);

    ResponseMock responseMock = new ResponseMock();
    Response response = Proxies.newProxyInstance(Response.class,
        responseMock);

    DocumentManagement documentManagement =
        soapFactory.newDocumentManagement("token");
    adaptor.doContainer(documentManagement,
        new OpentextDocId(new DocId("2000/Folder:3000")),
        containerNode, response);

    // I think the links don't get relativized because I'm not
    // creating anything with a scheme in the tests.
    String expected = "<!DOCTYPE html>\n"
        + "<html><head><title>Folder 2000/Folder:3000</title></head>"
        + "<body><h1>Folder 2000/Folder:3000</h1>"
        + "<li><a href=\"2000/Folder/Document+1:4001\">Document 1</a></li>"
        + "<li><a href=\"2000/Folder/Document+2:4002\">Document 2</a></li>"
        + "<li><a href=\"2000/Folder/Document+3:4003\">Document 3</a></li>"
        + "</body></html>";
    assertEquals(expected,
        responseMock.outputStream.toString("UTF-8"));
  }

  @Test
  public void testGetDisplayUrl() {
    SoapFactoryMock soapFactory = new SoapFactoryMock();
    OpentextAdaptor adaptor = new OpentextAdaptor(soapFactory);
    AdaptorContext context = ProxyAdaptorContext.getInstance();
    Config config = initConfig(adaptor, context);
    config.addKey("opentext.displayUrl.objAction.111", "actionFor111");
    adaptor.init(context);

    URI displayUrl = adaptor.getDisplayUrl("Document", 12345);
    assertEquals("http://example.com/otcs/livelink.exe" +
        "?func=ll&objAction=overview&objId=12345", displayUrl.toString());

    displayUrl = adaptor.getDisplayUrl("UnknownType", 12345);
    assertEquals("http://example.com/otcs/livelink.exe" +
        "?func=ll&objAction=properties&objId=12345", displayUrl.toString());

    displayUrl = adaptor.getDisplayUrl("GenericNode:111", 12345);
    assertEquals("http://example.com/otcs/livelink.exe" +
        "?func=ll&objAction=actionFor111&objId=12345", displayUrl.toString());
  }

  @Test
  public void testGetDisplayUrlPathInfo() {
    SoapFactoryMock soapFactory = new SoapFactoryMock();
    OpentextAdaptor adaptor = new OpentextAdaptor(soapFactory);
    AdaptorContext context = ProxyAdaptorContext.getInstance();
    Config config = initConfig(adaptor, context);
    config.addKey(
        "opentext.displayUrl.queryString.Document", "/open/{1}");
    config.addKey(
        "opentext.displayUrl.queryString.111", "/open111/{1}");
    adaptor.init(context);

    URI displayUrl = adaptor.getDisplayUrl("Document", 12345);
    assertEquals("http://example.com/otcs/livelink.exe/open/12345",
        displayUrl.toString());
    displayUrl = adaptor.getDisplayUrl("GenericNode:111", 12345);
    assertEquals("http://example.com/otcs/livelink.exe/open111/12345",
        displayUrl.toString());
  }

  @Test
  public void testDoDocumentNoVersions() throws IOException {
    OpentextDocId testDocId =
        new OpentextDocId(new DocId("2000/Document Name:3143"));

    thrown.expect(RuntimeException.class);
    thrown.expectMessage(
        "Document does not support versions: " + testDocId);

    SoapFactoryMock soapFactory = new SoapFactoryMock();
    NodeMock documentNode = new NodeMock(3143, "Document Name");
    documentNode.setIsVersionable(false);
    soapFactory.documentManagementMock.addNode(documentNode);

    OpentextAdaptor adaptor = new OpentextAdaptor(soapFactory);
    AdaptorContext context = ProxyAdaptorContext.getInstance();
    Config config = initConfig(adaptor, context);
    adaptor.init(context);

    ResponseMock responseMock = new ResponseMock();
    Response response = Proxies.newProxyInstance(Response.class,
        responseMock);

    DocumentManagement documentManagement =
        soapFactory.newDocumentManagement("token");
    adaptor.doDocument(documentManagement, testDocId, documentNode, response);
  }

  @Test
  public void testDoDocument() throws IOException {
    SoapFactoryMock soapFactory = new SoapFactoryMock();

    GregorianCalendar lastModified =
        new GregorianCalendar(2015, 1, 3, 9, 42, 42);
    NodeMock documentNode =
        new NodeMock(3143, "Title of Document", "Document");
    documentNode.setVersion(1, "text/plain", lastModified);
    soapFactory.documentManagementMock.addNode(documentNode);

    OpentextAdaptor adaptor = new OpentextAdaptor(soapFactory);
    AdaptorContext context = ProxyAdaptorContext.getInstance();
    Config config = initConfig(adaptor, context);
    adaptor.init(context);

    ResponseMock responseMock = new ResponseMock();
    Response response = Proxies.newProxyInstance(Response.class,
        responseMock);

    DocumentManagement documentManagement =
        soapFactory.newDocumentManagement("token");
    adaptor.doDocument(documentManagement,
        new OpentextDocId(new DocId("2000/Document:3143")),
        documentNode, response);

    assertEquals("text/plain", responseMock.contentType);
    assertEquals(lastModified.getTime(), responseMock.lastModified);
    assertEquals("http://example.com/otcs/livelink.exe" +
        "?func=ll&objAction=overview&objId=3143",
        responseMock.displayUrl.toString());
    assertEquals("this is the content",
        responseMock.outputStream.toString("UTF-8"));
  }

  @Test
  public void testDocWithExcludedNodeType() throws IOException {
    SoapFactoryMock soapFactory = new SoapFactoryMock();

    NodeMock documentNode =
        new NodeMock(3143, "Title of Document", "Alias");
    documentNode.setStartPointId(2000);
    documentNode.setPath(documentNode.getName());
    soapFactory.documentManagementMock.addNode(documentNode);

    OpentextAdaptor adaptor = new OpentextAdaptor(soapFactory);
    AdaptorContext context = ProxyAdaptorContext.getInstance();
    Config config = initConfig(adaptor, context);
    config.overrideKey("opentext.excludedNodeTypes", "Alias");
    adaptor.init(context);

    ResponseMock responseMock = new ResponseMock();
    Response response = Proxies.newProxyInstance(Response.class,
        responseMock);

    RequestMock requestMock = new RequestMock(
        new DocId("EnterpriseWS/Title+of+Document:3143"));
    Request request = Proxies.newProxyInstance(Request.class,
        requestMock);

    adaptor.getDocContent(request, response);
    assertTrue(responseMock.notFound());
  }

  @Test
  public void testPrimitiveValueIndexAllAttributes() {
    // Create the definition for the attribute.
    Attribute attribute = new PrimitiveAttribute();
    attribute.setKey("5432.1.2");
    attribute.setSearchable(false);
    Map<String, Attribute> attrDefinitionCache =
        new HashMap<String, Attribute>();
    attrDefinitionCache.put(attribute.getKey(), attribute);

    // Create the test attribute.
    StringValue stringValue = new StringValue();
    stringValue.setDescription("attribute name");
    stringValue.setKey("5432.1.2");
    stringValue.getValues().add("first value");
    stringValue.getValues().add("second value");
    stringValue.getValues().add("third value");

    SoapFactoryMock soapFactory = new SoapFactoryMock();
    OpentextAdaptor adaptor = new OpentextAdaptor(soapFactory);
    AdaptorContext context = ProxyAdaptorContext.getInstance();
    Config config = initConfig(adaptor, context);
    config.overrideKey("opentext.indexSearchableAttributesOnly", "false");
    adaptor.init(context);

    ResponseMock responseMock = new ResponseMock();
    adaptor.doPrimitiveValue(stringValue,
        Proxies.newProxyInstance(Response.class, responseMock),
        attrDefinitionCache, null);

    Map<String, List<String>> metadata = responseMock.getMetadata();
    List<String> values = metadata.get("attribute name");
    assertNotNull(values);
    assertEquals(
        Lists.newArrayList("first value", "second value", "third value"),
        values);
  }

  @Test
  public void testPrimitiveValueIndexSearchableAttributes() {
    // Create the definition for the attribute.
    Attribute attribute = new Attribute();
    attribute.setKey("5432.1.1");
    attribute.setSearchable(false);
    Map<String, Attribute> attrDefinitionCache =
        new HashMap<String, Attribute>();
    attrDefinitionCache.put(attribute.getKey(), attribute);

    // Create the test attribute.
    StringValue stringValue = new StringValue();
    stringValue.setDescription("attribute name");
    stringValue.setKey("5432.1.1");
    stringValue.getValues().add("first value");
    stringValue.getValues().add("second value");
    stringValue.getValues().add("third value");

    SoapFactoryMock soapFactory = new SoapFactoryMock();
    OpentextAdaptor adaptor = new OpentextAdaptor(soapFactory);
    AdaptorContext context = ProxyAdaptorContext.getInstance();
    Config config = initConfig(adaptor, context);
    config.overrideKey("opentext.indexSearchableAttributesOnly", "true");
    adaptor.init(context);

    // When the attribute is not searchable, no metadata is returned.
    ResponseMock responseMock = new ResponseMock();
    adaptor.doPrimitiveValue(stringValue,
        Proxies.newProxyInstance(Response.class, responseMock),
        attrDefinitionCache, null);
    Map<String, List<String>> metadata = responseMock.getMetadata();
    List<String> values = metadata.get("attribute name");
    assertNull(values);

    // When the attribute is searchable, metadata is returned.
    attribute.setSearchable(true);
    responseMock = new ResponseMock();
    adaptor.doPrimitiveValue(stringValue,
        Proxies.newProxyInstance(Response.class, responseMock),
        attrDefinitionCache, null);
    metadata = responseMock.getMetadata();
    values = metadata.get("attribute name");
    assertNotNull(values);
  }

  @Test
  public void testPrimitiveValueUserAttributes() {
    // Create the definition for the attribute.
    Attribute attribute = new UserAttribute();
    attribute.setKey("5432.1.1");
    attribute.setSearchable(true);
    Map<String, Attribute> attrDefinitionCache =
        new HashMap<String, Attribute>();
    attrDefinitionCache.put(attribute.getKey(), attribute);

    // Create the test attribute.
    IntegerValue integerValue = new IntegerValue();
    integerValue.setDescription("user attribute name");
    integerValue.setKey("5432.1.1");
    integerValue.getValues().add(new Long(14985));
    // Include an id with no corresponding Member; API puts
    // null in the member list when a member can't be found.
    integerValue.getValues().add(new Long(14986));

    // Create the corresponding member.
    Member member = getMember(14985, "testuser1", "User");

    SoapFactoryMock soapFactory = new SoapFactoryMock();
    OpentextAdaptor adaptor = new OpentextAdaptor(soapFactory);
    ResponseMock responseMock = new ResponseMock();
    soapFactory.memberServiceMock.addMember(member);
    adaptor.doPrimitiveValue(integerValue,
        Proxies.newProxyInstance(Response.class, responseMock),
        attrDefinitionCache, soapFactory.newMemberService(null));

    Map<String, List<String>> metadata = responseMock.getMetadata();
    List<String> values = metadata.get("user attribute name");
    assertNotNull(values);
    assertEquals(Lists.newArrayList("testuser1"), values);
  }

  @Test
  public void testPrimitiveValueDateAttributes() {
    // Create the definition for the attribute.
    Attribute attribute = new UserAttribute();
    attribute.setKey("5432.1.1");
    attribute.setSearchable(true);
    Map<String, Attribute> attrDefinitionCache =
        new HashMap<String, Attribute>();
    attrDefinitionCache.put(attribute.getKey(), attribute);

    // Create the test attribute.
    DateValue dateValue = new DateValue();
    dateValue.setDescription("date attribute name");
    dateValue.setKey("5432.1.1");
    dateValue.getValues().add(
        getXmlGregorianCalendar(1998, 11, 12, 14, 15, 16));

    SoapFactoryMock soapFactory = new SoapFactoryMock();
    OpentextAdaptor adaptor = new OpentextAdaptor(soapFactory);
    AdaptorContext context = ProxyAdaptorContext.getInstance();
    Config config = initConfig(adaptor, context);
    adaptor.init(context);
    ResponseMock responseMock = new ResponseMock();
    adaptor.doPrimitiveValue(dateValue,
        Proxies.newProxyInstance(Response.class, responseMock),
        attrDefinitionCache, soapFactory.newMemberService(null));

    Map<String, List<String>> metadata = responseMock.getMetadata();
    List<String> values = metadata.get("date attribute name");
    assertNotNull(values);
    assertEquals(Lists.newArrayList("1998-12-12"), values);
  }

  @Test
  public void testTableValue() {
    // Create the definition for the attributes.
    Map<String, Attribute> attrDefinitionCache =
        new HashMap<String, Attribute>();
    SetAttribute setAttribute = new SetAttribute();
    Attribute attribute = new PrimitiveAttribute();
    attribute.setKey("5432.1.1");
    attribute.setSearchable(true);
    attrDefinitionCache.put(attribute.getKey(), attribute);
    setAttribute.getAttributes().add(attribute);
    attribute = new PrimitiveAttribute();
    attribute.setKey("5432.1.2");
    attribute.setSearchable(true);
    attrDefinitionCache.put(attribute.getKey(), attribute);
    setAttribute.getAttributes().add(attribute);

    // Create the test attributes.
    StringValue stringValue = new StringValue();
    stringValue.setDescription("string attribute name");
    stringValue.setKey("5432.1.1");
    stringValue.getValues().add("first value");
    stringValue.getValues().add("second value");
    stringValue.getValues().add("third value");
    BooleanValue booleanValue = new BooleanValue();
    booleanValue.setDescription("boolean attribute name");
    booleanValue.setKey("5432.1.2");
    booleanValue.getValues().add(Boolean.TRUE);
    RowValue rowValue = new RowValue();
    rowValue.getValues().add(stringValue);
    rowValue.getValues().add(booleanValue);
    TableValue tableValue = new TableValue();
    tableValue.getValues().add(rowValue);

    SoapFactoryMock soapFactory = new SoapFactoryMock();
    OpentextAdaptor adaptor = new OpentextAdaptor(soapFactory);
    ResponseMock responseMock = new ResponseMock();
    adaptor.doTableValue(tableValue,
        Proxies.newProxyInstance(Response.class, responseMock),
        attrDefinitionCache, null);

    Map<String, List<String>> metadata = responseMock.getMetadata();
    List<String> values = metadata.get("string attribute name");
    assertNotNull(values);
    assertEquals(
        Lists.newArrayList("first value", "second value", "third value"),
        values);
    values = metadata.get("boolean attribute name");
    assertNotNull(values);
    assertEquals(Lists.newArrayList("true"), values);
  }

  @Test
  public void testDoCategories() {
    // Create the definition for the category+attributes.
    AttributeGroupDefinition categoryDefinition =
        new AttributeGroupDefinition();
    categoryDefinition.setID(5432);
    categoryDefinition.setKey("5432.1");
    PrimitiveAttribute attribute = new PrimitiveAttribute();
    attribute.setKey("5432.1.1");
    attribute.setSearchable(true);
    categoryDefinition.getAttributes().add(attribute);
    attribute = new PrimitiveAttribute();
    attribute.setKey("5432.1.2");
    attribute.setSearchable(true);
    categoryDefinition.getAttributes().add(attribute);

    // Create the test attributes (metadata).
    StringValue stringValue = new StringValue();
    stringValue.setDescription("string attribute name");
    stringValue.setKey("5432.1.1");
    stringValue.getValues().add("first value");
    stringValue.getValues().add("second value");
    stringValue.getValues().add("third value");
    BooleanValue booleanValue = new BooleanValue();
    booleanValue.setDescription("boolean attribute name");
    booleanValue.setKey("5432.1.2");
    booleanValue.getValues().add(Boolean.TRUE);
    AttributeGroup attributeGroup = new AttributeGroup();
    attributeGroup.setType("Category");
    attributeGroup.setKey("5432.1");
    attributeGroup.getValues().add(stringValue);
    attributeGroup.getValues().add(booleanValue);
    Metadata metadata = new Metadata();
    metadata.getAttributeGroups().add(attributeGroup);

    // Set up the adaptor instance with the test data.
    SoapFactoryMock soapFactory = new SoapFactoryMock();
    OpentextAdaptor adaptor = new OpentextAdaptor(soapFactory);
    AdaptorContext context = ProxyAdaptorContext.getInstance();
    Config config = initConfig(adaptor, context);
    adaptor.init(context);

    NodeMock documentNode =
        new NodeMock(3143, "Title of Document", "Document");
    documentNode.setMetadata(metadata);
    soapFactory.documentManagementMock.addNode(documentNode);
    soapFactory.documentManagementMock.addCategoryDefinition(
        categoryDefinition);

    ResponseMock responseMock = new ResponseMock();
    adaptor.doCategories(soapFactory.newDocumentManagement("token"),
        documentNode,
        Proxies.newProxyInstance(Response.class, responseMock));
    Map<String, List<String>> responseMetadata = responseMock.getMetadata();
    List<String> values = responseMetadata.get("string attribute name");
    assertNotNull(values);
    assertEquals(
        Lists.newArrayList("first value", "second value", "third value"),
        values);
    values = responseMetadata.get("boolean attribute name");
    assertNotNull(values);
    assertEquals(Lists.newArrayList("true"), values);
  }

  @Test
  public void testShouldIndexNonCategory() {
    SoapFactoryMock soapFactory = new SoapFactoryMock();
    OpentextAdaptor adaptor = new OpentextAdaptor(soapFactory);
    AdaptorContext context = ProxyAdaptorContext.getInstance();
    Config config = initConfig(adaptor, context);
    adaptor.init(context);

    AttributeGroup attributeGroup = new AttributeGroup();
    attributeGroup.setType("NotACategory");
    assertFalse(adaptor.shouldIndex(attributeGroup));
  }

  @Test
  public void testShouldIndexNoCategoryId() {
    SoapFactoryMock soapFactory = new SoapFactoryMock();
    OpentextAdaptor adaptor = new OpentextAdaptor(soapFactory);
    AdaptorContext context = ProxyAdaptorContext.getInstance();
    Config config = initConfig(adaptor, context);
    adaptor.init(context);

    AttributeGroup attributeGroup = new AttributeGroup();
    attributeGroup.setType("Category");
    attributeGroup.setKey("random key");
    assertFalse(adaptor.shouldIndex(attributeGroup));
  }

  @Test
  public void testShouldIndexInIncludeList() {
    SoapFactoryMock soapFactory = new SoapFactoryMock();
    OpentextAdaptor adaptor = new OpentextAdaptor(soapFactory);
    AdaptorContext context = ProxyAdaptorContext.getInstance();
    Config config = initConfig(adaptor, context);
    config.overrideKey("opentext.includedCategories", "12345, 23456");
    adaptor.init(context);

    AttributeGroup attributeGroup = new AttributeGroup();
    attributeGroup.setType("Category");
    attributeGroup.setKey("12345.3");
    assertTrue(adaptor.shouldIndex(attributeGroup));
  }

  @Test
  public void testShouldIndexNotInIncludeList() {
    SoapFactoryMock soapFactory = new SoapFactoryMock();
    OpentextAdaptor adaptor = new OpentextAdaptor(soapFactory);
    AdaptorContext context = ProxyAdaptorContext.getInstance();
    Config config = initConfig(adaptor, context);
    config.overrideKey("opentext.includedCategories", "12345, 23456");
    adaptor.init(context);

    AttributeGroup attributeGroup = new AttributeGroup();
    attributeGroup.setType("Category");
    attributeGroup.setKey("92345.3");
    assertFalse(adaptor.shouldIndex(attributeGroup));
  }

  @Test
  public void testShouldIndexInExcludeList() {
    SoapFactoryMock soapFactory = new SoapFactoryMock();
    OpentextAdaptor adaptor = new OpentextAdaptor(soapFactory);
    AdaptorContext context = ProxyAdaptorContext.getInstance();
    Config config = initConfig(adaptor, context);
    config.overrideKey("opentext.excludedCategories", "12345, 23456");
    adaptor.init(context);

    AttributeGroup attributeGroup = new AttributeGroup();
    attributeGroup.setType("Category");
    attributeGroup.setKey("12345.3");
    assertFalse(adaptor.shouldIndex(attributeGroup));
  }

  @Test
  public void testShouldIndexNotInExcludeList() {
    SoapFactoryMock soapFactory = new SoapFactoryMock();
    OpentextAdaptor adaptor = new OpentextAdaptor(soapFactory);
    AdaptorContext context = ProxyAdaptorContext.getInstance();
    Config config = initConfig(adaptor, context);
    config.overrideKey("opentext.excludedCategories", "12345, 23456");
    adaptor.init(context);

    AttributeGroup attributeGroup = new AttributeGroup();
    attributeGroup.setType("Category");
    attributeGroup.setKey("82345.3");
    assertTrue(adaptor.shouldIndex(attributeGroup));
  }

  @Test
  public void testShouldIndexInBothIncludeAndExcludeList() {
    SoapFactoryMock soapFactory = new SoapFactoryMock();
    OpentextAdaptor adaptor = new OpentextAdaptor(soapFactory);
    AdaptorContext context = ProxyAdaptorContext.getInstance();
    Config config = initConfig(adaptor, context);
    config.overrideKey("opentext.includedCategories", "12345, 23456");
    config.overrideKey("opentext.excludedCategories", "12345, 23456");
    adaptor.init(context);

    AttributeGroup attributeGroup = new AttributeGroup();
    attributeGroup.setType("Category");
    attributeGroup.setKey("12345.3");
    assertFalse(adaptor.shouldIndex(attributeGroup));
  }

  @Test
  public void testIncludeCategoryName() {
    AttributeGroupDefinition categoryDefinition =
        new AttributeGroupDefinition();
    categoryDefinition.setID(82345);
    categoryDefinition.setKey("82345.3");

    AttributeGroup attributeGroup = new AttributeGroup();
    attributeGroup.setType("Category");
    attributeGroup.setKey("82345.3");
    attributeGroup.setDisplayName("Category Display Name");
    Metadata metadata = new Metadata();
    metadata.getAttributeGroups().add(attributeGroup);

    SoapFactoryMock soapFactory = new SoapFactoryMock();
    OpentextAdaptor adaptor = new OpentextAdaptor(soapFactory);
    AdaptorContext context = ProxyAdaptorContext.getInstance();
    Config config = initConfig(adaptor, context);
    config.overrideKey("opentext.indexCategoryNames", "true");
    adaptor.init(context);

    NodeMock documentNode =
        new NodeMock(3143, "Title of Document", "Document");
    documentNode.setMetadata(metadata);
    soapFactory.documentManagementMock.addNode(documentNode);
    soapFactory.documentManagementMock.addCategoryDefinition(
        categoryDefinition);

    ResponseMock responseMock = new ResponseMock();
    adaptor.doCategories(soapFactory.newDocumentManagement("token"),
        documentNode,
        Proxies.newProxyInstance(Response.class, responseMock));
    Map<String, List<String>> responseMetadata = responseMock.getMetadata();
    assertEquals(
        "Category Display Name", responseMetadata.get("Category").get(0));
  }

  @Test
  public void testGetIncludedNodeFeatures() {
    Map<String, String> configuredFeatures = new HashMap<String, String>();
    configuredFeatures.put("NamedType", "Feature1, Feature2");
    configuredFeatures.put("124", "OtherFeature");

    Map<String, List<String>> includedFeatures =
        OpentextAdaptor.getIncludedNodeFeatures(configuredFeatures, ",");
    assertEquals(2, includedFeatures.size());
    assertEquals(Lists.newArrayList("Feature1", "Feature2"),
        includedFeatures.get("NamedType"));
    assertEquals(Lists.newArrayList("OtherFeature"),
        includedFeatures.get("GenericNode:124"));
  }

  @Test
  public void testGetIncludedNodeFeaturesEmpty() {
    Map<String, String> configuredFeatures = new HashMap<String, String>();

    Map<String, List<String>> includedFeatures =
        OpentextAdaptor.getIncludedNodeFeatures(configuredFeatures, ",");
    assertEquals(0, includedFeatures.size());
  }

  @Test
  public void testFixTypeKeys() {
    Map<String, String> original = new HashMap<String, String>();
    original.put("Document", "document value");
    original.put("123", "123 value");
    original.put("GenericNode:456", "456 value");
    Map<String, String> result = OpentextAdaptor.fixTypeKeys(original);
    assertEquals(original.size(), result.size());
    assertNull(result.get("123"));
    assertEquals("123 value", result.get("GenericNode:123"));
    assertEquals("document value", result.get("Document"));
    assertEquals("456 value", result.get("GenericNode:456"));
  }

  @Test
  public void testGetCanonicalType() {
    assertNull(OpentextAdaptor.getCanonicalType(null));
    assertEquals("TextType", OpentextAdaptor.getCanonicalType("TextType"));
    assertEquals("GenericNode:123",
        OpentextAdaptor.getCanonicalType("123"));
    assertEquals("GenericNode:123",
        OpentextAdaptor.getCanonicalType("GenericNode:123"));
  }

  @Test
  public void testDoNodeFeatures() {
    SoapFactoryMock soapFactory = new SoapFactoryMock();
    OpentextAdaptor adaptor = new OpentextAdaptor(soapFactory);
    AdaptorContext context = ProxyAdaptorContext.getInstance();
    Config config = initConfig(adaptor, context);
    config.addKey("opentext.includedNodeFeatures.NodeType",
        "Feature1,Feature2");
    adaptor.init(context);

    NodeMock node = new NodeMock(3143, "Node Name", "NodeType");
    NodeFeature feature = new NodeFeature();
    feature.setName("Feature1");
    feature.setBooleanValue(true);
    feature.setType("Boolean");
    node.getFeatures().add(feature);

    ResponseMock responseMock = new ResponseMock();
    adaptor.doNodeFeatures(
        node, Proxies.newProxyInstance(Response.class, responseMock));
    Map<String, List<String>> responseMetadata = responseMock.getMetadata();
    assertEquals(1, responseMetadata.size());
    assertEquals("true", responseMetadata.get("Feature1").get(0));
    assertNull(responseMetadata.get("Feature2"));
  }

  @Test
  public void testDoNodeFeaturesWithDate() {
    SoapFactoryMock soapFactory = new SoapFactoryMock();
    OpentextAdaptor adaptor = new OpentextAdaptor(soapFactory);
    AdaptorContext context = ProxyAdaptorContext.getInstance();
    Config config = initConfig(adaptor, context);
    config.addKey("opentext.includedNodeFeatures.NodeType",
        "Feature1,Feature2");
    adaptor.init(context);

    NodeMock node = new NodeMock(3143, "Node Name", "NodeType");
    NodeFeature feature = new NodeFeature();
    feature.setName("Feature1");
    feature.setDateValue(getXmlGregorianCalendar(2011, 01, 01, 01, 01, 01));
    feature.setType("Date");
    node.getFeatures().add(feature);

    ResponseMock responseMock = new ResponseMock();
    adaptor.doNodeFeatures(
        node, Proxies.newProxyInstance(Response.class, responseMock));
    Map<String, List<String>> responseMetadata = responseMock.getMetadata();
    assertEquals(1, responseMetadata.size());
    assertEquals("2011-02-01", responseMetadata.get("Feature1").get(0));
    assertNull(responseMetadata.get("Feature2"));
  }

  @Test
  public void testDoNodeProperties() {
    SoapFactoryMock soapFactory = new SoapFactoryMock();
    OpentextAdaptor adaptor = new OpentextAdaptor(soapFactory);
    AdaptorContext context = ProxyAdaptorContext.getInstance();
    Config config = initConfig(adaptor, context);
    adaptor.init(context);
    Member member = getMember(14985, "testuser1", "User");
    soapFactory.memberServiceMock.addMember(member);

    NodeMock node = new NodeMock(54678, "Node Name");
    node.setComment("Node comment");
    node.setCreateDate(2012, 3, 1, 4, 34, 21);
    node.setModifyDate(2013, 3, 1, 4, 34, 21);
    node.setCreatedBy(new Long(14985));
    node.setType("NodeType");
    node.setDisplayType("Node Display Type");
    node.setVolumeID(new Long(-321));
    NodeVersionInfo versionInfo = new NodeVersionInfo();
    versionInfo.setMimeType("test/mime-type");
    node.setVersionInfo(versionInfo);

    ResponseMock responseMock = new ResponseMock();
    adaptor.doNodeProperties(soapFactory.newDocumentManagement("token"),
        node, Proxies.newProxyInstance(Response.class, responseMock));
    Map<String, List<String>> responseMetadata = responseMock.getMetadata();

    assertEquals("54678", responseMetadata.get("ID").get(0));
    assertEquals("Node Name", responseMetadata.get("Name").get(0));
    assertEquals("Node comment", responseMetadata.get("Comment").get(0));
    assertEquals("2012-04-01", responseMetadata.get("CreateDate").get(0));
    assertEquals("2013-04-01", responseMetadata.get("ModifyDate").get(0));
    assertEquals("testuser1", responseMetadata.get("CreatedBy").get(0));
    assertEquals("NodeType", responseMetadata.get("SubType").get(0));
    assertEquals(
        "Node Display Type", responseMetadata.get("DisplayType").get(0));
    assertEquals("-321", responseMetadata.get("VolumeID").get(0));
    assertEquals("test/mime-type", responseMetadata.get("MimeType").get(0));
  }

  @Test
  public void testDoNodePropertiesCustomDateFormat() {
    SoapFactoryMock soapFactory = new SoapFactoryMock();
    OpentextAdaptor adaptor = new OpentextAdaptor(soapFactory);
    AdaptorContext context = ProxyAdaptorContext.getInstance();
    Config config = initConfig(adaptor, context);
    config.overrideKey("opentext.metadataDateFormat", "MM dd, yyyy");
    adaptor.init(context);

    NodeMock node = new NodeMock(54678, "Node Name", "NodeType");
    node.setCreateDate(2012, 3, 1, 4, 34, 21);
    node.setModifyDate(2013, 3, 1, 4, 34, 21);

    ResponseMock responseMock = new ResponseMock();
    adaptor.doNodeProperties(soapFactory.newDocumentManagement("token"),
        node, Proxies.newProxyInstance(Response.class, responseMock));
    Map<String, List<String>> responseMetadata = responseMock.getMetadata();

    assertEquals("04 01, 2012", responseMetadata.get("CreateDate").get(0));
    assertEquals("04 01, 2013", responseMetadata.get("ModifyDate").get(0));
  }

  @Test
  public void testDoNode() throws IOException {
    NodeMock node = new NodeMock(432, "Test Node");
    SoapFactoryMock soapFactory = new SoapFactoryMock();
    OpentextAdaptor adaptor = new OpentextAdaptor(soapFactory);
    AdaptorContext context = ProxyAdaptorContext.getInstance();
    Config config = initConfig(adaptor, context);
    adaptor.init(context);
    ResponseMock responseMock = new ResponseMock();
    adaptor.doNode(soapFactory.newDocumentManagement("token"),
        new OpentextDocId(new DocId("432:432")),
        node,
        Proxies.newProxyInstance(Response.class, responseMock));
    String expected = "<!DOCTYPE html>\n"
        + "<html><head><title>Test Node</title></head>"
        + "<body><h1>Test Node</h1>"
        + "</body></html>";
    assertEquals(expected,
        responseMock.outputStream.toString("UTF-8"));
  }

  @Test
  public void testDoCollection() throws IOException {
    SoapFactoryMock soapFactory = new SoapFactoryMock();
    NodeMock containerNode =
        new NodeMock(3000, "CollectionName", "Collection");
    containerNode.setStartPointId(2000);
    containerNode.setPath("CollectionName");
    soapFactory.documentManagementMock.addNode(containerNode);
    for (int i = 1; i <= 3; i++) {
      NodeMock testNode = new NodeMock(4000 + i, "Document " + i);
      testNode.setStartPointId(2000);
      testNode.setPath("CollectionName", "Document " + i);
      soapFactory.documentManagementMock.addNode(testNode);
    }
    OpentextAdaptor adaptor = new OpentextAdaptor(soapFactory);
    AdaptorContext context = ProxyAdaptorContext.getInstance();
    Config config = initConfig(adaptor, context);
    adaptor.init(context);
    ResponseMock responseMock = new ResponseMock();
    adaptor.doCollection(soapFactory.newDocumentManagement("token"),
        new OpentextDocId(new DocId("2000/CollectionName:3000")),
        containerNode,
        Proxies.newProxyInstance(Response.class, responseMock));
    String expected = "<!DOCTYPE html>\n"
        + "<html><head><title>CollectionName</title></head>"
        + "<body><h1>CollectionName</h1>"
        + "<p>Document 1</p>"
        + "<p>Document 2</p>"
        + "<p>Document 3</p>"
        + "</body></html>";
    assertEquals(expected,
        responseMock.outputStream.toString("UTF-8"));
  }

  @Test
  public void testDoCollectionErrorGettingContents() throws IOException {
    class DocumentManagementMockError extends DocumentManagementMock {
      public List<Node> listNodes(long containerNodeId, boolean partialData) {
        throw getSoapFaultException("error retrieving child nodes",
            "uri", "local", "prefix");
      }
    };
    SoapFactoryMock soapFactory = new SoapFactoryMock();
    NodeMock containerNode =
        new NodeMock(3000, "CollectionName", "Collection");
    OpentextAdaptor adaptor = new OpentextAdaptor(soapFactory);
    AdaptorContext context = ProxyAdaptorContext.getInstance();
    Config config = initConfig(adaptor, context);
    adaptor.init(context);
    ResponseMock responseMock = new ResponseMock();
    adaptor.doCollection(
        soapFactory.newDocumentManagement(new DocumentManagementMockError()),
        new OpentextDocId(new DocId("2000/Folder:3000")),
        containerNode,
        Proxies.newProxyInstance(Response.class, responseMock));

    String expected = "<!DOCTYPE html>\n"
        + "<html><head><title>CollectionName</title></head>"
        + "<body><h1>CollectionName</h1>"
        + "</body></html>";
    assertEquals(expected,
        responseMock.outputStream.toString("UTF-8"));
  }

  @Test
  public void testDoMilestone() throws IOException {
    MilestoneInfo milestoneInfo = new MilestoneInfo();
    milestoneInfo.setID(3000);
    milestoneInfo.setActualDate(
        getXmlGregorianCalendar(2011, 01, 01, 01, 01, 01));
    milestoneInfo.setDuration(45);
    milestoneInfo.setNumActive(2);
    milestoneInfo.setNumCancelled(0);
    milestoneInfo.setNumCompleted(3);
    milestoneInfo.setNumInprocess(5);
    milestoneInfo.setNumIssue(2);
    milestoneInfo.setNumLate(0);
    milestoneInfo.setNumOnHold(4);
    milestoneInfo.setNumPending(7);
    milestoneInfo.setNumTasks(8);
    milestoneInfo.setOriginalTargetDate(
        getXmlGregorianCalendar(2012, 01, 01, 01, 01, 01));
    milestoneInfo.setPercentCancelled(15.0);
    milestoneInfo.setPercentComplete(55.0);
    milestoneInfo.setPercentInprocess(32.0);
    milestoneInfo.setPercentIssue(11.0);
    milestoneInfo.setPercentLate(4.0);
    milestoneInfo.setPercentOnHold(45.0);
    milestoneInfo.setPercentPending(13.0);
    milestoneInfo.setResources(99);
    milestoneInfo.setTargetDate(
        getXmlGregorianCalendar(2013, 01, 01, 01, 01, 01));
    SoapFactoryMock soapFactory = new SoapFactoryMock();
    NodeMock milestoneNode =
        new NodeMock(3000, "TestMilestone", "Milestone");
    milestoneNode.setStartPointId(2000);
    milestoneNode.setPath("TestMilestone");
    for (int i = 1; i <= 3; i++) {
      NodeMock testNode = new NodeMock(4000 + i, "Document " + i);
      testNode.setStartPointId(2000);
      testNode.setPath("TestMilestone", "Document " + i);
      soapFactory.documentManagementMock.addNode(testNode);
    }
    soapFactory.documentManagementMock.addNode(milestoneNode);
    soapFactory.collaborationMock.addMilestoneInfo(milestoneInfo);
    OpentextAdaptor adaptor = new OpentextAdaptor(soapFactory);
    AdaptorContext context = ProxyAdaptorContext.getInstance();
    Config config = initConfig(adaptor, context);
    adaptor.init(context);
    ResponseMock responseMock = new ResponseMock();
    adaptor.doMilestone(soapFactory.newDocumentManagement("token"),
        new OpentextDocId(new DocId("2000/TestMilestone:3000")),
        milestoneNode,
        Proxies.newProxyInstance(Response.class, responseMock));
    String expected = "<!DOCTYPE html>\n"
        + "<html><head><title>TestMilestone</title></head>"
        + "<body><h1>TestMilestone</h1>"
        + "</body></html>";
    assertEquals(expected,
        responseMock.outputStream.toString("UTF-8"));
    Map<String, List<String>> responseMetadata = responseMock.getMetadata();
    assertEquals("2011-02-01", responseMetadata.get("ActualDate").get(0));
    assertEquals("45", responseMetadata.get("Duration").get(0));
    assertEquals("2", responseMetadata.get("NumActive").get(0));
    assertEquals("0", responseMetadata.get("NumCancelled").get(0));
    assertEquals("3", responseMetadata.get("NumCompleted").get(0));
    assertEquals("5", responseMetadata.get("NumInProcess").get(0));
    assertEquals("2", responseMetadata.get("NumIssue").get(0));
    assertEquals("0", responseMetadata.get("NumLate").get(0));
    assertEquals("4", responseMetadata.get("NumOnHold").get(0));
    assertEquals("7", responseMetadata.get("NumPending").get(0));
    assertEquals("8", responseMetadata.get("NumTasks").get(0));
    assertEquals("2012-02-01",
        responseMetadata.get("OriginalTargetDate").get(0));
    assertEquals("15.0", responseMetadata.get("PercentCancelled").get(0));
    assertEquals("55.0", responseMetadata.get("PercentComplete").get(0));
    assertEquals("32.0", responseMetadata.get("PercentInProcess").get(0));
    assertEquals("11.0", responseMetadata.get("PercentIssue").get(0));
    assertEquals("4.0", responseMetadata.get("PercentLate").get(0));
    assertEquals("45.0", responseMetadata.get("PercentOnHold").get(0));
    assertEquals("13.0", responseMetadata.get("PercentPending").get(0));
    assertEquals("99", responseMetadata.get("Resources").get(0));
    assertEquals("2013-02-01", responseMetadata.get("TargetDate").get(0));
    List<String> anchors = responseMock.getAnchors();
    assertEquals(3, anchors.size());
    assertEquals(
        Lists.newArrayList("Document 1", "Document 2", "Document 3"),
        anchors);
  }

  @Test
  public void testDoNews() throws IOException {
    NewsInfo newsInfo = new NewsInfo();
    newsInfo.setCreatedBy(new Long(1001));
    newsInfo.setEffectiveDate(
        getXmlGregorianCalendar(2013, 01, 01, 01, 01, 01));
    newsInfo.setExpirationDate(
        getXmlGregorianCalendar(2013, 01, 11, 01, 01, 01));
    newsInfo.setHeadline("This Is The Headline");
    newsInfo.setID(12345);
    newsInfo.setName("NewsInfoName");
    newsInfo.setStory("This is the news story.");
    SoapFactoryMock soapFactory = new SoapFactoryMock();
    NodeMock newsNode = new NodeMock(12345, "NewsInfoName", "News");
    newsNode.setStartPointId(2000);
    newsNode.setPath("NewsInfoName");
    for (int i = 1; i <= 3; i++) {
      NodeMock testNode = new NodeMock(4000 + i, "Document " + i);
      testNode.setStartPointId(2000);
      testNode.setPath("NewsInfoName", "Document " + i);
      soapFactory.documentManagementMock.addNode(testNode);
    }
    soapFactory.documentManagementMock.addNode(newsNode);
    soapFactory.collaborationMock.addNewsInfo(newsInfo);
    OpentextAdaptor adaptor = new OpentextAdaptor(soapFactory);
    AdaptorContext context = ProxyAdaptorContext.getInstance();
    Config config = initConfig(adaptor, context);
    adaptor.init(context);
    ResponseMock responseMock = new ResponseMock();
    adaptor.doNews(soapFactory.newDocumentManagement("token"),
        new OpentextDocId(new DocId("2000/News+Info+Name:12345")),
        newsNode,
        Proxies.newProxyInstance(Response.class, responseMock));
    String expected = "<!DOCTYPE html>\n"
        + "<html><head><title>NewsInfoName</title></head>"
        + "<body><h1>This Is The Headline</h1>"
        + "<p>This is the news story.</p>"
        + "</body></html>";
    assertEquals(expected,
        responseMock.outputStream.toString("UTF-8"));
    Map<String, List<String>> responseMetadata = responseMock.getMetadata();
    assertEquals("2013-02-01", responseMetadata.get("EffectiveDate").get(0));
    assertEquals("2013-02-11", responseMetadata.get("ExpirationDate").get(0));
    List<String> anchors = responseMock.getAnchors();
    assertEquals(3, anchors.size());
    assertEquals(
        Lists.newArrayList("Document 1", "Document 2", "Document 3"),
        anchors);
  }

  @Test
  public void testDoNewsErrorGettingAttachments() throws IOException {
    class CollaborationMockError extends CollaborationMock {
      public NewsInfo getNews(long id) {
        throw getSoapFaultException("error retrieving news info",
            "uri", "local", "prefix");
      }
    };
    SoapFactoryMock soapFactory = new SoapFactoryMock();
    soapFactory.collaborationMock = new CollaborationMockError();
    NodeMock newsNode = new NodeMock(12345, "NewsName", "News");
    newsNode.setStartPointId(2000);
    newsNode.setPath("NewsName");
    for (int i = 1; i <= 3; i++) {
      NodeMock testNode = new NodeMock(4000 + i, "Document " + i);
      testNode.setStartPointId(2000);
      testNode.setPath("NewsName", "Document " + i);
      soapFactory.documentManagementMock.addNode(testNode);
    }
    soapFactory.documentManagementMock.addNode(newsNode);
    OpentextAdaptor adaptor = new OpentextAdaptor(soapFactory);
    AdaptorContext context = ProxyAdaptorContext.getInstance();
    Config config = initConfig(adaptor, context);
    adaptor.init(context);
    ResponseMock responseMock = new ResponseMock();
    adaptor.doNews(soapFactory.newDocumentManagement("token"),
        new OpentextDocId(new DocId("2000/News+Name:12345")),
        newsNode,
        Proxies.newProxyInstance(Response.class, responseMock));
    String expected = "<!DOCTYPE html>\n"
        + "<html><head><title>Folder 2000/News+Name:12345</title>"
        + "</head><body><h1>Folder 2000/News+Name:12345</h1>"
        + "<li><a href=\"2000/News+Name/Document+1:4001\">Document 1</a></li>"
        + "<li><a href=\"2000/News+Name/Document+2:4002\">Document 2</a></li>"
        + "<li><a href=\"2000/News+Name/Document+3:4003\">Document 3</a></li>"
        + "</body></html>";
    assertEquals(expected,
        responseMock.outputStream.toString("UTF-8"));
  }

  @Test
  public void testDoProject() throws IOException {
    ProjectInfo projectInfo = new ProjectInfo();
    projectInfo.setCreatedBy(new Long(1001));
    projectInfo.setGoals("These are the goals.");
    projectInfo.setID(3000);
    projectInfo.setInitiatives("These are the initiatives.");
    projectInfo.setMission("This is the mission.");
    projectInfo.setName("ProjectName");
    projectInfo.setObjectives("These are the objectives.");
    projectInfo.setPublicAccess(false);
    projectInfo.setStartDate(
        getXmlGregorianCalendar(2013, 01, 01, 01, 01, 01));
    projectInfo.setStatus(ProjectStatus.PENDING);
    projectInfo.setTargetDate(
        getXmlGregorianCalendar(2014, 01, 01, 01, 01, 01));
    SoapFactoryMock soapFactory = new SoapFactoryMock();
    NodeMock projectNode = new NodeMock(3000, "ProjectName", "Project");
    projectNode.setStartPointId(2000);
    projectNode.setPath("ProjectName");
    for (int i = 1; i <= 3; i++) {
      NodeMock testNode = new NodeMock(4000 + i, "Document " + i);
      testNode.setStartPointId(2000);
      testNode.setPath("ProjectName", "Document " + i);
      soapFactory.documentManagementMock.addNode(testNode);
    }
    soapFactory.documentManagementMock.addNode(projectNode);
    soapFactory.collaborationMock.addProjectInfo(projectInfo);
    OpentextAdaptor adaptor = new OpentextAdaptor(soapFactory);
    AdaptorContext context = ProxyAdaptorContext.getInstance();
    Config config = initConfig(adaptor, context);
    adaptor.init(context);
    ResponseMock responseMock = new ResponseMock();
    adaptor.doProject(soapFactory.newDocumentManagement("token"),
        new OpentextDocId(new DocId("2000/Project+Name:3000")),
        projectNode,
        Proxies.newProxyInstance(Response.class, responseMock));
    String expected = "<!DOCTYPE html>\n"
        + "<html><head><title>ProjectName</title></head>"
        + "<body><h1>ProjectName</h1>"
        + "</body></html>";
    assertEquals(expected,
        responseMock.outputStream.toString("UTF-8"));
    Map<String, List<String>> responseMetadata = responseMock.getMetadata();
    assertEquals("2013-02-01", responseMetadata.get("StartDate").get(0));
    assertEquals("2014-02-01", responseMetadata.get("TargetDate").get(0));
    assertEquals("These are the goals.",
        responseMetadata.get("Goals").get(0));
    assertEquals("These are the initiatives.",
        responseMetadata.get("Initiatives").get(0));
    assertEquals("This is the mission.",
        responseMetadata.get("Mission").get(0));
    assertEquals("These are the objectives.",
        responseMetadata.get("Objectives").get(0));
    assertEquals("PENDING", responseMetadata.get("Status").get(0));
    List<String> anchors = responseMock.getAnchors();
    assertEquals(3, anchors.size());
    assertEquals(
        Lists.newArrayList("Document 1", "Document 2", "Document 3"),
        anchors);
  }

  @Test
  public void testDoProjectErrorGettingContents() throws IOException {
    class CollaborationMockError extends CollaborationMock {
      public ProjectInfo getProject(long id) {
        throw getSoapFaultException("error retrieving project info",
            "uri", "local", "prefix");
      }
    };
    SoapFactoryMock soapFactory = new SoapFactoryMock();
    soapFactory.collaborationMock = new CollaborationMockError();
    NodeMock projectNode = new NodeMock(3000, "ProjectName", "Project");
    projectNode.setStartPointId(2000);
    projectNode.setPath("ProjectName");
    for (int i = 1; i <= 3; i++) {
      NodeMock testNode = new NodeMock(4000 + i, "Document " + i);
      testNode.setStartPointId(2000);
      testNode.setPath("ProjectName", "Document " + i);
      soapFactory.documentManagementMock.addNode(testNode);
    }
    soapFactory.documentManagementMock.addNode(projectNode);
    OpentextAdaptor adaptor = new OpentextAdaptor(soapFactory);
    AdaptorContext context = ProxyAdaptorContext.getInstance();
    Config config = initConfig(adaptor, context);
    adaptor.init(context);
    ResponseMock responseMock = new ResponseMock();
    adaptor.doProject(soapFactory.newDocumentManagement("token"),
        new OpentextDocId(new DocId("2000/ProjectName:3000")),
        projectNode,
        Proxies.newProxyInstance(Response.class, responseMock));
    String expected = "<!DOCTYPE html>\n"
        + "<html><head><title>Folder 2000/ProjectName:3000</title>"
        + "</head><body><h1>Folder 2000/ProjectName:3000</h1>"
        + "<li><a href=\"2000/ProjectName/Document+1:4001\">"
        + "Document 1</a></li>"
        + "<li><a href=\"2000/ProjectName/Document+2:4002\">"
        + "Document 2</a></li>"
        + "<li><a href=\"2000/ProjectName/Document+3:4003\">"
        + "Document 3</a></li>"
        + "</body></html>";
    assertEquals(expected,
        responseMock.outputStream.toString("UTF-8"));
  }

  @Test
  public void testDoTopicReply() throws IOException {
    DiscussionItem discussionItem = new DiscussionItem();
    discussionItem.setContent("Discussion item content.");
    discussionItem.setID(3000);
    discussionItem.setOrdering(3);
    discussionItem.setPostedBy(1001);
    discussionItem.setPostedDate(
        getXmlGregorianCalendar(2013, 01, 01, 01, 01, 01));
    discussionItem.setSubject("Discussion item subject.");
    SoapFactoryMock soapFactory = new SoapFactoryMock();
    NodeMock discussionNode =
        new NodeMock(3000, "Discussion item subject.", "Topic");
    discussionNode.setStartPointId(2000);
    discussionNode.setPath("Discussion item subject.");
    for (int i = 1; i <= 3; i++) {
      NodeMock testNode = new NodeMock(4000 + i, "Document " + i);
      testNode.setStartPointId(2000);
      testNode.setPath("Discussion item subject.", "Document " + i);
      soapFactory.documentManagementMock.addNode(testNode);
    }
    // Create the corresponding member.
    Member member = getMember(1001, "testuser1", "User");
    soapFactory.memberServiceMock.addMember(member);
    soapFactory.documentManagementMock.addNode(discussionNode);
    soapFactory.collaborationMock.addDiscussionItem(discussionItem);
    OpentextAdaptor adaptor = new OpentextAdaptor(soapFactory);
    AdaptorContext context = ProxyAdaptorContext.getInstance();
    Config config = initConfig(adaptor, context);
    adaptor.init(context);
    ResponseMock responseMock = new ResponseMock();
    adaptor.doTopicReply(soapFactory.newDocumentManagement("token"),
        new OpentextDocId(new DocId("2000/Project+Name:3000")),
        discussionNode,
        Proxies.newProxyInstance(Response.class, responseMock));
    String expected = "<!DOCTYPE html>\n"
        + "<html><head><title>Discussion item subject.</title></head>"
        + "<body><h1>Discussion item subject.</h1>"
        + "<p>Discussion item content.</p>"
        + "</body></html>";
    assertEquals(expected,
        responseMock.outputStream.toString("UTF-8"));
    Map<String, List<String>> responseMetadata = responseMock.getMetadata();
    assertEquals("2013-02-01", responseMetadata.get("PostedDate").get(0));
    assertEquals("testuser1", responseMetadata.get("PostedBy").get(0));
    List<String> anchors = responseMock.getAnchors();
    assertEquals(3, anchors.size());
    assertEquals(
        Lists.newArrayList("Document 1", "Document 2", "Document 3"),
        anchors);
  }

  @Test
  public void testDoTopicReplyErrorGettingContents() throws IOException {
    class CollaborationMockError extends CollaborationMock {
      public DiscussionItem getTopicReply(long id) {
        throw getSoapFaultException("error retrieving discussion item",
            "uri", "local", "prefix");
      }
    };
    SoapFactoryMock soapFactory = new SoapFactoryMock();
    NodeMock discussionNode =
        new NodeMock(3000, "Discussion item subject.", "Topic");
    discussionNode.setStartPointId(2000);
    discussionNode.setPath("Discussion item subject.");
    for (int i = 1; i <= 3; i++) {
      NodeMock testNode = new NodeMock(4000 + i, "Document " + i);
      testNode.setStartPointId(2000);
      testNode.setPath("Discussion item subject.", "Document " + i);
      soapFactory.documentManagementMock.addNode(testNode);
    }
    soapFactory.documentManagementMock.addNode(discussionNode);
    OpentextAdaptor adaptor = new OpentextAdaptor(soapFactory);
    AdaptorContext context = ProxyAdaptorContext.getInstance();
    Config config = initConfig(adaptor, context);
    adaptor.init(context);
    ResponseMock responseMock = new ResponseMock();
    adaptor.doTopicReply(soapFactory.newDocumentManagement("token"),
        new OpentextDocId(new DocId("2000/Discussion+item+subject.:3000")),
        discussionNode,
        Proxies.newProxyInstance(Response.class, responseMock));
    String expected = "<!DOCTYPE html>\n"
        + "<html><head><title>Folder 2000/Discussion+item+subject.:3000"
        + "</title>"
        + "</head><body><h1>Folder 2000/Discussion+item+subject.:3000</h1>"
        + "<li><a href=\"2000/Discussion+item+subject./Document+1:4001\">"
        + "Document 1</a></li>"
        + "<li><a href=\"2000/Discussion+item+subject./Document+2:4002\">"
        + "Document 2</a></li>"
        + "<li><a href=\"2000/Discussion+item+subject./Document+3:4003\">"
        + "Document 3</a></li>"
        + "</body></html>";
    assertEquals(expected,
        responseMock.outputStream.toString("UTF-8"));
  }

  @Test
  public void testDoTask() throws IOException {
    TaskInfo taskInfo = new TaskInfo();
    taskInfo.setAssignedTo(new Long(1001));
    taskInfo.setComments("These are the comments.");
    taskInfo.setCompletionDate(
        getXmlGregorianCalendar(2013, 01, 01, 01, 01, 01));
    taskInfo.setDateAssigned(
        getXmlGregorianCalendar(2012, 01, 01, 01, 01, 01));
    taskInfo.setDueDate(
        getXmlGregorianCalendar(2014, 01, 01, 01, 01, 01));
    taskInfo.setID(3000);
    taskInfo.setInstructions("These are the instructions.");
    taskInfo.setMilestone(54678);
    taskInfo.setName("TaskName");
    taskInfo.setPriority(TaskPriority.LOW);
    taskInfo.setStartDate(
        getXmlGregorianCalendar(2012, 01, 01, 01, 01, 01));
    taskInfo.setStatus(TaskStatus.PENDING);
    Member member = getMember(1001, "testuser1", "User");
    SoapFactoryMock soapFactory = new SoapFactoryMock();
    soapFactory.memberServiceMock.addMember(member);
    NodeMock taskNode = new NodeMock(3000, "TaskName", "Task");
    taskNode.setStartPointId(2000);
    taskNode.setPath("TaskName");
    for (int i = 1; i <= 3; i++) {
      NodeMock testNode = new NodeMock(4000 + i, "Document " + i);
      testNode.setStartPointId(2000);
      testNode.setPath("TaskName", "Document " + i);
      soapFactory.documentManagementMock.addNode(testNode);
    }
    soapFactory.documentManagementMock.addNode(taskNode);
    soapFactory.collaborationMock.addTaskInfo(taskInfo);
    OpentextAdaptor adaptor = new OpentextAdaptor(soapFactory);
    AdaptorContext context = ProxyAdaptorContext.getInstance();
    Config config = initConfig(adaptor, context);
    adaptor.init(context);
    ResponseMock responseMock = new ResponseMock();
    adaptor.doTask(soapFactory.newDocumentManagement("token"),
        new OpentextDocId(new DocId("2000/TaskName:3000")),
        taskNode,
        Proxies.newProxyInstance(Response.class, responseMock));
    String expected = "<!DOCTYPE html>\n"
        + "<html><head><title>TaskName</title></head>"
        + "<body><h1>TaskName</h1>"
        + "<p>These are the comments.</p>"
        + "<p>These are the instructions.</p>"
        + "</body></html>";
    assertEquals(expected,
        responseMock.outputStream.toString("UTF-8"));
    Map<String, List<String>> responseMetadata = responseMock.getMetadata();
    assertEquals("testuser1", responseMetadata.get("AssignedTo").get(0));
    assertEquals("2013-02-01", responseMetadata.get("CompletionDate").get(0));
    assertEquals("2012-02-01", responseMetadata.get("DateAssigned").get(0));
    assertEquals("2014-02-01", responseMetadata.get("DueDate").get(0));
    assertEquals("2012-02-01", responseMetadata.get("StartDate").get(0));
    assertEquals("LOW", responseMetadata.get("Priority").get(0));
    assertEquals("PENDING", responseMetadata.get("Status").get(0));
    List<String> anchors = responseMock.getAnchors();
    assertEquals(3, anchors.size());
    assertEquals(
        Lists.newArrayList("Document 1", "Document 2", "Document 3"),
        anchors);
  }

  @Test
  public void testDoTaskErrorGettingContents() throws IOException {
    class CollaborationMockError extends CollaborationMock {
      public TaskInfo getTask(long id) {
        throw getSoapFaultException("error retrieving task info",
            "uri", "local", "prefix");
      }
    };
    SoapFactoryMock soapFactory = new SoapFactoryMock();
    soapFactory.collaborationMock = new CollaborationMockError();
    NodeMock taskNode = new NodeMock(3000, "TaskName", "Task");
    taskNode.setStartPointId(2000);
    taskNode.setPath("TaskName");
    for (int i = 1; i <= 3; i++) {
      NodeMock testNode = new NodeMock(4000 + i, "Document " + i);
      testNode.setStartPointId(2000);
      testNode.setPath("TaskName", "Document " + i);
      soapFactory.documentManagementMock.addNode(testNode);
    }
    soapFactory.documentManagementMock.addNode(taskNode);
    OpentextAdaptor adaptor = new OpentextAdaptor(soapFactory);
    AdaptorContext context = ProxyAdaptorContext.getInstance();
    Config config = initConfig(adaptor, context);
    adaptor.init(context);
    ResponseMock responseMock = new ResponseMock();
    adaptor.doTask(soapFactory.newDocumentManagement("token"),
        new OpentextDocId(new DocId("2000/TaskName:3000")),
        taskNode,
        Proxies.newProxyInstance(Response.class, responseMock));
    String expected = "<!DOCTYPE html>\n"
        + "<html><head><title>Folder 2000/TaskName:3000</title>"
        + "</head><body><h1>Folder 2000/TaskName:3000</h1>"
        + "<li><a href=\"2000/TaskName/Document+1:4001\">Document 1</a></li>"
        + "<li><a href=\"2000/TaskName/Document+2:4002\">Document 2</a></li>"
        + "<li><a href=\"2000/TaskName/Document+3:4003\">Document 3</a></li>"
        + "</body></html>";
    assertEquals(expected,
        responseMock.outputStream.toString("UTF-8"));
  }

  @Test
  public void testAclOwnerRight() throws IOException {
    Member owner = getMember(1001, "testuser1", "User");
    NodeRights nodeRights = new NodeRights();
    nodeRights.setOwnerRight(getNodeRight(owner.getID(), "Owner"));
    NodeMock documentNode = new NodeMock(3000, "DocumentName", "Document");
    SoapFactoryMock soapFactory = new SoapFactoryMock();
    soapFactory.documentManagementMock
        .setNodeRights(documentNode.getID(), nodeRights);
    soapFactory.memberServiceMock.addMember(owner);
    OpentextAdaptor adaptor = new OpentextAdaptor(soapFactory);
    ResponseMock responseMock = new ResponseMock();
    adaptor.doAcl(soapFactory.newDocumentManagement("token"),
        new OpentextDocId(new DocId("2000/DocumentName:3000")),
        documentNode,
        Proxies.newProxyInstance(Response.class, responseMock));
    assertEquals(
        Sets.newHashSet(new UserPrincipal(owner.getName())),
        responseMock.getAcl().getPermits());
  }

  @Test
  public void testAclOwnerGroupRight() throws IOException {
    Member ownerGroup = getMember(1002, "DefaultGroup", "Group");
    NodeRights nodeRights = new NodeRights();
    nodeRights.setOwnerGroupRight(
        getNodeRight(ownerGroup.getID(), "OwnerGroup"));
    NodeMock documentNode = new NodeMock(3000, "DocumentName", "Document");
    SoapFactoryMock soapFactory = new SoapFactoryMock();
    soapFactory.documentManagementMock
        .setNodeRights(documentNode.getID(), nodeRights);
    soapFactory.memberServiceMock.addMember(ownerGroup);
    OpentextAdaptor adaptor = new OpentextAdaptor(soapFactory);
    ResponseMock responseMock = new ResponseMock();
    adaptor.doAcl(soapFactory.newDocumentManagement("token"),
        new OpentextDocId(new DocId("2000/DocumentName:3000")),
        documentNode,
        Proxies.newProxyInstance(Response.class, responseMock));
    assertEquals(
        Sets.newHashSet(new GroupPrincipal(ownerGroup.getName())),
        responseMock.getAcl().getPermits());
  }

  @Test
  public void testAclPublicRight() throws IOException {
    NodeRights nodeRights = new NodeRights();
    nodeRights.setPublicRight(getNodeRight(-1, "Public"));
    NodeMock documentNode = new NodeMock(3000, "DocumentName", "Document");
    SoapFactoryMock soapFactory = new SoapFactoryMock();
    soapFactory.documentManagementMock
        .setNodeRights(documentNode.getID(), nodeRights);
    OpentextAdaptor adaptor = new OpentextAdaptor(soapFactory);
    ResponseMock responseMock = new ResponseMock();
    adaptor.doAcl(soapFactory.newDocumentManagement("token"),
        new OpentextDocId(new DocId("2000/DocumentName:3000")),
        documentNode,
        Proxies.newProxyInstance(Response.class, responseMock));
    assertEquals(
        Sets.newHashSet(new GroupPrincipal("Public Access")),
        responseMock.getAcl().getPermits());
  }

  @Test
  public void testAclAclRights() throws IOException {
    Member aclUser = getMember(1001, "testuser1", "User");
    NodeRights nodeRights = new NodeRights();
    nodeRights.getACLRights().add(getNodeRight(aclUser.getID(), "ACL"));
    NodeMock documentNode = new NodeMock(3000, "DocumentName", "Document");
    SoapFactoryMock soapFactory = new SoapFactoryMock();
    soapFactory.documentManagementMock
        .setNodeRights(documentNode.getID(), nodeRights);
    soapFactory.memberServiceMock.addMember(aclUser);
    OpentextAdaptor adaptor = new OpentextAdaptor(soapFactory);
    ResponseMock responseMock = new ResponseMock();
    adaptor.doAcl(soapFactory.newDocumentManagement("token"),
        new OpentextDocId(new DocId("2000/DocumentName:3000")),
        documentNode,
        Proxies.newProxyInstance(Response.class, responseMock));
    assertEquals(
        Sets.newHashSet(new UserPrincipal(aclUser.getName())),
        responseMock.getAcl().getPermits());
  }

  /**
   * This test emulates an item within a project whose ACLs
   * reference the parent project's Members/Guests/Coordinators
   * groups.
   */
  @Test
  public void testAclProjectMember() throws IOException {
    Member owner = getMember(1001, "testuser1", "User");
    Member ownerGroup = getMember(1002, "DefaultGroup", "Group");
    Member guestUser = getMember(1003, "GuestUser", "User");
    Member projectCoordinators =
        getMember(54321, "Coordinators", "ProjectGroup");
    Member projectMembers = getMember(54322, "Members", "ProjectGroup");
    Member projectGuests = getMember(54323, "Guests", "ProjectGroup");
    Member projectGroup1 = getMember(98765, "Group1", "ProjectGroup");
    Member projectGroup2 = getMember(98767, "Group2", "ProjectGroup");
    NodeRights nodeRights = new NodeRights();
    nodeRights.setOwnerRight(getNodeRight(owner.getID(), "Owner"));
    nodeRights.setOwnerGroupRight(
        getNodeRight(ownerGroup.getID(), "OwnerGroup"));
    nodeRights.getACLRights().add(
        getNodeRight(projectGroup1.getID(), "ACL"));
    nodeRights.getACLRights().add(
        getNodeRight(projectGroup2.getID(), "ACL"));
    SoapFactoryMock soapFactory = new SoapFactoryMock();
    soapFactory.memberServiceMock.addMember(owner);
    soapFactory.memberServiceMock.addMember(ownerGroup);
    soapFactory.memberServiceMock.addMember(guestUser);
    soapFactory.memberServiceMock.addMember(projectCoordinators);
    soapFactory.memberServiceMock.addMember(projectMembers);
    soapFactory.memberServiceMock.addMember(projectGuests);
    soapFactory.memberServiceMock.addMember(projectGroup1);
    soapFactory.memberServiceMock.addMember(projectGroup2);
    soapFactory.memberServiceMock.addMemberToGroup(
        projectCoordinators.getID(), owner);
    soapFactory.memberServiceMock.addMemberToGroup(
        projectMembers.getID(), ownerGroup);
    soapFactory.memberServiceMock.addMemberToGroup(
        projectGuests.getID(), guestUser);
    soapFactory.memberServiceMock.addMemberToGroup(
        projectGroup1.getID(), projectCoordinators);
    soapFactory.memberServiceMock.addMemberToGroup(
        projectGroup1.getID(), projectMembers);
    soapFactory.memberServiceMock.addMemberToGroup(
        projectGroup2.getID(), projectGuests);
    NodeMock documentNode = new NodeMock(3000, "DocumentName", "Document");
    soapFactory.documentManagementMock
        .setNodeRights(documentNode.getID(), nodeRights);
    OpentextAdaptor adaptor = new OpentextAdaptor(soapFactory);
    ResponseMock responseMock = new ResponseMock();
    adaptor.doAcl(soapFactory.newDocumentManagement("token"),
        new OpentextDocId(new DocId("2000/DocumentName:3000")),
        documentNode,
        Proxies.newProxyInstance(Response.class, responseMock));
    assertEquals(
        Sets.newHashSet(new UserPrincipal(owner.getName()),
            new UserPrincipal(guestUser.getName()),
            new GroupPrincipal(ownerGroup.getName())),
        responseMock.getAcl().getPermits());;
  }

  @Test
  public void testAclNoPermissions() throws IOException {
    thrown.expect(RuntimeException.class);
    thrown.expectMessage(
        "No ACL information for DocId(2000/DocumentName:3000)");

    NodeRight nodeRight = getNodeRight(-1, "Public");
    nodeRight.getPermissions().setSeeContentsPermission(false);
    NodeRights nodeRights = new NodeRights();
    nodeRights.setPublicRight(nodeRight);
    NodeMock documentNode = new NodeMock(3000, "DocumentName", "Document");
    SoapFactoryMock soapFactory = new SoapFactoryMock();
    soapFactory.documentManagementMock
        .setNodeRights(documentNode.getID(), nodeRights);
    OpentextAdaptor adaptor = new OpentextAdaptor(soapFactory);
    ResponseMock responseMock = new ResponseMock();
    adaptor.doAcl(soapFactory.newDocumentManagement("token"),
        new OpentextDocId(new DocId("2000/DocumentName:3000")),
        documentNode,
        Proxies.newProxyInstance(Response.class, responseMock));
  }

  @Test
  public void testAclInvalidAdminUser() throws IOException {
    thrown.expect(SOAPFaultException.class);
    thrown.expectMessage("Failed to authenticate as admin");

    class AuthenticationMockError extends AuthenticationMock {
      public String authenticateUser(String username, String password) {
        throw getSoapFaultException("Failed to authenticate as admin",
            "urn:Core.service.livelink.opentext.com",
            "Core.LoginFailed", "ns0");
      }
    };
    SoapFactoryMock soapFactory = new SoapFactoryMock();
    NodeMock documentNode = new NodeMock(3000, "DocumentName", "Document");
    OpentextAdaptor adaptor = new OpentextAdaptor(soapFactory);
    AdaptorContext context = ProxyAdaptorContext.getInstance();
    Config config = initConfig(adaptor, context);
    config.overrideKey("opentext.adminUsername", "validuser");
    config.overrideKey("opentext.adminPassword", "validpassword");
    adaptor.init(context);
    // Replace authenticationMock after calling init so we don't
    // just get the error there; we want to trigger it in doAcl
    // to verify that the exception's rethrown.
    soapFactory.authenticationMock = new AuthenticationMockError();
    ResponseMock responseMock = new ResponseMock();
    adaptor.doAcl(soapFactory.newDocumentManagement("token"),
        new OpentextDocId(new DocId("2000/DocumentName:3000")),
        documentNode,
        Proxies.newProxyInstance(Response.class, responseMock));
  }

  @Test
  public void testAclGetNodeRightsError() throws IOException {
    thrown.expect(SOAPFaultException.class);
    thrown.expectMessage("Failed to get node rights");

    class DocumentManagementMockError extends DocumentManagementMock {
      public NodeRights getNodeRights(long id) {
        throw getSoapFaultException("Failed to get node rights",
            "uri", "local", "ns0");
      }
    };
    SoapFactoryMock soapFactory = new SoapFactoryMock();
    soapFactory.documentManagementMock = new DocumentManagementMockError();
    NodeMock documentNode = new NodeMock(3000, "DocumentName", "Document");
    OpentextAdaptor adaptor = new OpentextAdaptor(soapFactory);
    ResponseMock responseMock = new ResponseMock();
    adaptor.doAcl(soapFactory.newDocumentManagement("token"),
        new OpentextDocId(new DocId("2000/DocumentName:3000")),
        documentNode,
        Proxies.newProxyInstance(Response.class, responseMock));
  }

  @Test
  public void testAclGetMemberByIdError() throws IOException {
    thrown.expect(SOAPFaultException.class);
    thrown.expectMessage("Failed to get member by id");

    class MemberServiceMockError extends MemberServiceMock {
      public Member getMemberById(long id) {
        throw getSoapFaultException("Failed to get member by id",
            "uri", "local", "ns0");
      }
    };
    Member member = getMember(1001, "testuser1", "User");
    NodeRights nodeRights = new NodeRights();
    nodeRights.setOwnerRight(getNodeRight(member.getID(), "Owner"));
    NodeMock documentNode = new NodeMock(3000, "DocumentName", "Document");
    SoapFactoryMock soapFactory = new SoapFactoryMock();
    soapFactory.documentManagementMock
        .setNodeRights(documentNode.getID(), nodeRights);
    soapFactory.memberServiceMock = new MemberServiceMockError();
    soapFactory.memberServiceMock.addMember(member);
    OpentextAdaptor adaptor = new OpentextAdaptor(soapFactory);
    ResponseMock responseMock = new ResponseMock();
    adaptor.doAcl(soapFactory.newDocumentManagement("token"),
        new OpentextDocId(new DocId("2000/DocumentName:3000")),
        documentNode,
        Proxies.newProxyInstance(Response.class, responseMock));
  }

  @Test
  public void testAclListMembersError() throws IOException {
    thrown.expect(SOAPFaultException.class);
    thrown.expectMessage("Failed to list members");

    class MemberServiceMockError extends MemberServiceMock {
      public Member getMemberById(long id) {
        throw getSoapFaultException("Failed to get member by id",
            "uri", "MemberService.MemberTypeNotValid", "ns0");
      }

      public List<Member> listMembers(long id) {
        throw getSoapFaultException("Failed to list members",
            "uri", "local", "ns0");
      }
    };
    Member member = getMember(1001, "testuser1", "User");
    NodeRights nodeRights = new NodeRights();
    nodeRights.setOwnerRight(getNodeRight(member.getID(), "Owner"));
    NodeMock documentNode = new NodeMock(3000, "DocumentName", "Document");
    SoapFactoryMock soapFactory = new SoapFactoryMock();
    soapFactory.documentManagementMock
        .setNodeRights(documentNode.getID(), nodeRights);
    soapFactory.memberServiceMock = new MemberServiceMockError();
    soapFactory.memberServiceMock.addMember(member);
    OpentextAdaptor adaptor = new OpentextAdaptor(soapFactory);
    ResponseMock responseMock = new ResponseMock();
    adaptor.doAcl(soapFactory.newDocumentManagement("token"),
        new OpentextDocId(new DocId("2000/DocumentName:3000")),
        documentNode,
        Proxies.newProxyInstance(Response.class, responseMock));
  }

  private class SoapFactoryMock implements SoapFactory {
    private AuthenticationMock authenticationMock;
    private DocumentManagementMock documentManagementMock;
    private ContentServiceMock contentServiceMock;
    private MemberServiceMock memberServiceMock;
    private CollaborationMock collaborationMock;

    private SoapFactoryMock() {
      this.authenticationMock = new AuthenticationMock();
      this.documentManagementMock = new DocumentManagementMock();
      this.contentServiceMock = new ContentServiceMock();
      this.memberServiceMock = new MemberServiceMock();
      this.collaborationMock = new CollaborationMock();
    }

    @Override
    public Authentication newAuthentication() {
      return Proxies.newProxyInstance(Authentication.class,
          this.authenticationMock);
    }

    @Override
    public DocumentManagement newDocumentManagement(
        String authenticationToken) {
      return Proxies.newProxyInstance(DocumentManagement.class,
          this.documentManagementMock);
    }

    private DocumentManagement newDocumentManagement(
        DocumentManagementMock documentManagementMock) {
      return Proxies.newProxyInstance(DocumentManagement.class,
          documentManagementMock);
    }

    @Override
    public ContentService newContentService(
        DocumentManagement documentManagement) {
      return Proxies.newProxyInstance(ContentService.class,
          this.contentServiceMock);
    }

    @Override
    public MemberService newMemberService(
        DocumentManagement documentManagement) {
      return Proxies.newProxyInstance(MemberService.class,
          this.memberServiceMock);
    }

    @Override
    public Collaboration newCollaboration(
        DocumentManagement documentManagement) {
      return Proxies.newProxyInstance(Collaboration.class,
          this.collaborationMock);
    }

    @Override
    public void configure(Config config) {
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

  private class DocIdPusherMock {
    private List<DocId> docIds;

    public DocId pushDocIds(Iterable<DocId> docIds) {
      this.docIds = Lists.newArrayList(docIds);
      return null;
    }
  }

  private class DocumentManagementMock {
    List<NodeMock> nodes = new ArrayList<NodeMock>();
    List<AttributeGroupDefinition> categoryDefinitions;
    Map<Long, NodeRights> nodeRights = new HashMap<Long, NodeRights>();

    DocumentManagementMock() {
      this.nodes.add(new NodeMock(2000, "Enterprise Workspace"));
      this.nodes.add(new NodeMock(1001, "test node 1001"));
      this.nodes.add(new NodeMock(1003, "test node 1003"));
    }

    private void addNode(NodeMock node) {
      nodes.add(node);
    }

    private NodeMock findNode(long nodeId) {
      for (NodeMock node : this.nodes) {
        if (node.getID() == nodeId) {
          return node;
        }
      }
      return null;
    }

    private void addCategoryDefinition(
        AttributeGroupDefinition categoryDefinition) {
      if (this.categoryDefinitions == null) {
        this.categoryDefinitions =
            new ArrayList<AttributeGroupDefinition>();
      }
      this.categoryDefinitions.add(categoryDefinition);
    }

    private void setNodeRights(long id, NodeRights nodeRights) {
      this.nodeRights.put(id, nodeRights);
    }

    public Node getNode(long nodeId) {
      if (nodeId == 1002) // Invalid ID for testing.
        return null;
      return findNode(nodeId);
    }

    public Node getRootNode(String rootNodeType) {
      if ("EnterpriseWS".equals(rootNodeType)) {
        return findNode(2000);
      }
      return null;
    }

    public Node getNodeByPath(long containerNodeId, List<String> path) {
      for (NodeMock node : this.nodes) {
        if (node.getStartPointId() == containerNodeId &&
            node.getPath().equals(path)) {
          return node;
        }
      }
      return null;
    }

    // TODO: use parent id instead.
    public List<Node> listNodes(long containerNodeId, boolean partialData) {
      List<Node> results = new ArrayList<Node>();
      NodeMock containerNode = findNode(containerNodeId);
      List<String> containerPath = containerNode.getPath();
      for (NodeMock node : this.nodes) {
        List<String> nodePath = node.getPath();
        if (nodePath == null) {
          continue;
        }
        if ((containerPath.size() + 1) == nodePath.size() &&
            containerPath.equals(nodePath.subList(0, nodePath.size() - 1))) {
          results.add(node);
        }
      }
      return results;
    }

    public Version getVersion(long nodeId, long versionNumber) {
      NodeMock node = findNode(nodeId);
      return node.getVersion();
    }

    public String getVersionContentsContext(long nodeId, long versionNumber) {
      return "versioncontext";
    }

    public AttributeGroupDefinition getAttributeGroupDefinition(
        String type, String key) {
      for (AttributeGroupDefinition categoryDef : this.categoryDefinitions) {
        if (key.equals(categoryDef.getKey())) {
          return categoryDef;
        }
      }
      return null;
    }

    public NodeRights getNodeRights(long id) {
      NodeRights nodeRights = this.nodeRights.get(id);
      if (nodeRights != null) {
        return nodeRights;
      }
      throw getSoapFaultException("no node rights", "uri", "local", "prefix");
    }
  }

  private class ContentServiceMock {
    public DataHandler downloadContent(String contextId) {
      DataSource dataSource = new DataSource() {
          public String getContentType() {
            return "text/plain";
          }

          public InputStream getInputStream() throws IOException {
            return new ByteArrayInputStream(
                "this is the content".getBytes(UTF_8));
          }

          public String getName() {
            return "DataSourceName";
          }

          public OutputStream getOutputStream() throws IOException {
            throw new IOException("Not available");
          }
        };

      return new DataHandler(dataSource);
    }
  }

  private class MemberServiceMock {
    private List<Member> members = new ArrayList<Member>();
    private Map<Long, List<Member>> groupMembers =
        new HashMap<Long, List<Member>>();

    private void addMember(Member member) {
      this.members.add(member);
    }

    private void addMemberToGroup(long group, Member member) {
      List<Member> members = this.groupMembers.get(group);
      if (members == null) {
        members = new ArrayList<Member>();
      }
      members.add(member);
      this.groupMembers.put(group, members);
    }

    public Member getMemberById(long id) {
      for (Member member : this.members) {
        if (member.getID() == id) {
          if (!("User".equals(member.getType())
                  || "Group".equals(member.getType()))) {
            // This method is documented to throw this exception
            // if the returned member type is not a group or a
            // user.
            throw getSoapFaultException(
                "MemberService.MemberTypeNotValid", "uri",
                "MemberService.MemberTypeNotValid", "prefix");
          }
          return member;
        }
      }
      return null;
    }

    public List<Member> getMembersByID(List<Long> idList) {
      List<Member> memberList = new ArrayList<Member>();
      for (Long id : idList) {
        for (Member member : this.members) {
          if (member.getID() == id) {
            memberList.add(member);
          } else {
            memberList.add(null);
          }
        }
      }
      return memberList;
    }

    public List<Member> listMembers(long id) {
      List<Member> members = this.groupMembers.get(id);
      if (members == null) {
        members = new ArrayList<Member>();
      }
      return members;
    }
  }

  private class CollaborationMock {
    private List<MilestoneInfo> milestoneInfo =
        new ArrayList<MilestoneInfo>();
    private List<NewsInfo> newsInfo =
        new ArrayList<NewsInfo>();
    private List<ProjectInfo> projectInfo =
        new ArrayList<ProjectInfo>();
    private List<DiscussionItem> discussionItems =
        new ArrayList<DiscussionItem>();
    private List<TaskInfo> taskInfo =
        new ArrayList<TaskInfo>();

    public MilestoneInfo getMilestone(long id) {
      for (MilestoneInfo info : this.milestoneInfo) {
        if (info.getID() == id) {
          return info;
        }
      }
      throw getSoapFaultException("Collaboration.ObjectIDInvalid", "uri",
          "Collaboration.ObjectIDInvalid", "prefix");
    }

    public NewsInfo getNews(long id) {
      for (NewsInfo info : this.newsInfo) {
        if (info.getID() == id) {
          return info;
        }
      }
      throw getSoapFaultException("Collaboration.ObjectIDInvalid", "uri",
          "Collaboration.ObjectIDInvalid", "prefix");
    }

    public ProjectInfo getProject(long id) {
      for (ProjectInfo info : this.projectInfo) {
        if (info.getID() == id) {
          return info;
        }
      }
      throw getSoapFaultException("Collaboration.ObjectIDInvalid", "uri",
          "Collaboration.ObjectIDInvalid", "prefix");
    }

    public DiscussionItem getTopicReply(long id) {
      for (DiscussionItem item : this.discussionItems) {
        if (item.getID() == id) {
          return item;
        }
      }
      throw getSoapFaultException("Collaboration.ObjectIDInvalid", "uri",
          "Collaboration.ObjectIDInvalid", "prefix");
    }

    public TaskInfo getTask(long id) {
      for (TaskInfo info : this.taskInfo) {
        if (info.getID() == id) {
          return info;
        }
      }
      throw getSoapFaultException("Collaboration.ObjectIDInvalid", "uri",
          "Collaboration.ObjectIDInvalid", "prefix");
    }

    private void addMilestoneInfo(MilestoneInfo milestoneInfo) {
      this.milestoneInfo.add(milestoneInfo);
    }

    private void addNewsInfo(NewsInfo newsInfo) {
      this.newsInfo.add(newsInfo);
    }

    private void addProjectInfo(ProjectInfo projectInfo) {
      this.projectInfo.add(projectInfo);
    }

    private void addDiscussionItem(DiscussionItem discussionItem) {
      this.discussionItems.add(discussionItem);
    }

    private void addTaskInfo(TaskInfo taskInfo) {
      this.taskInfo.add(taskInfo);
    }
  }

  private class NodeMock extends Node {
    private long id;
    private String name;
    private boolean isVersionable;
    private String objectType;
    private long parentId;
    private Metadata metadata;
    private XMLGregorianCalendar modifyDate;
    private XMLGregorianCalendar createDate;
    private NodeVersionInfo nodeVersionInfo;

    private List<String> path;
    private long startPointId;
    private Version version;

    private NodeMock(long id, String name) {
      this.id = id;
      this.name = name;
      this.isVersionable = true;
    }

    private NodeMock(long id, String name, String objectType) {
      this(id, name);
      this.objectType = objectType;
    }

    @Override
    public long getID() {
      return this.id;
    }

    @Override
    public String getName() {
      return this.name;
    }

    @Override
    public boolean isIsVersionable() {
      return isVersionable;
    }

    @Override
    public void setIsVersionable(boolean isVersionable) {
      this.isVersionable = isVersionable;
    }

    @Override
    public String getType() {
      return this.objectType;
    }

    @Override
    public void setType(String objectType) {
      this.objectType = objectType;
    }

    @Override
    public void setParentID(long parentId) {
      this.parentId = parentId;
    }

    @Override
    public long getParentID() {
      return this.parentId;
    }

    @Override
    public Metadata getMetadata() {
      return this.metadata;
    }

    @Override
    public void setMetadata(Metadata metadata) {
      this.metadata = metadata;
    }

    @Override
    public XMLGregorianCalendar getModifyDate() {
      return this.modifyDate;
    }

    @Override
    public XMLGregorianCalendar getCreateDate() {
      return this.createDate;
    }

    @Override
    public NodeVersionInfo getVersionInfo() {
      return this.nodeVersionInfo;
    }

    @Override
    public void setVersionInfo(NodeVersionInfo nodeVersionInfo) {
      this.nodeVersionInfo = nodeVersionInfo;
    }

    // For testing getNodeByPath
    long getStartPointId() {
      return this.startPointId;
    }

    void setStartPointId(long startPointId) {
      this.startPointId = startPointId;
    }

    // For testing getNodeByPath
    List<String> getPath() {
      return this.path;
    }

    void setPath(String... path) {
      this.path = Arrays.asList(path);
    }

    Version getVersion() {
      return this.version;
    }

    void setVersion(long versionNumber, String contentType,
        GregorianCalendar modifyDate) {
      this.version
          = new VersionMock(versionNumber, contentType, modifyDate);
    }

    private void setModifyDate(int year, int month, int dayOfMonth,
        int hourOfDay, int minute, int second) {
      this.modifyDate = getXmlGregorianCalendar(
          year, month, dayOfMonth, hourOfDay, minute, second);
    }

    private void setCreateDate(int year, int month, int dayOfMonth,
        int hourOfDay, int minute, int second) {
      this.createDate = getXmlGregorianCalendar(
          year, month, dayOfMonth, hourOfDay, minute, second);
    }

    public String toString() {
      StringBuilder builder = new StringBuilder();
      builder.append(name)
          .append("(").append(id).append(")")
          .append("[").append(startPointId).append("/");
      Joiner.on("/").appendTo(builder, path);
      builder.append("]");
      return builder.toString();
    }
  }

  private class VersionMock extends Version {
    private long versionNumber;
    private String contentType;
    private GregorianCalendar modifyDate;

    private VersionMock(long versionNumber, String contentType,
        GregorianCalendar modifyDate) {
      this.versionNumber = versionNumber;
      this.contentType = contentType;
      this.modifyDate = modifyDate;
    }

    @Override
    public long getNumber() {
      return this.versionNumber;
    }

    @Override
    public String getMimeType() {
      return this.contentType;
    }

    @Override
    public XMLGregorianCalendar getModifyDate() {
      try {
        return
            DatatypeFactory.newInstance().newXMLGregorianCalendar(modifyDate);
      } catch (DatatypeConfigurationException datatypeException) {
        return null;
      }
    }
  }

  private class RequestMock {
    private DocId docId;

    RequestMock(DocId docId) {
      this.docId = docId;
    }

    public DocId getDocId() {
      return this.docId;
    }
  }

  private class ResponseMock {
    private ByteArrayOutputStream outputStream;
    private String contentType;
    private Date lastModified;
    private URI displayUrl;
    private boolean notFound = false;
    private Map<String, List<String>> metadata =
        new HashMap<String, List<String>>();
    private List<String> anchors = new ArrayList<String>();
    private Acl acl;

    ResponseMock() {
      this.outputStream = new ByteArrayOutputStream();
    }

    public OutputStream getOutputStream() {
      return outputStream;
    }

    public void setContentType(String contentType) {
      this.contentType = contentType;
    }

    public void setLastModified(Date lastModified) {
      this.lastModified = lastModified;
    }

    public void setDisplayUrl(URI displayUrl) {
      this.displayUrl = displayUrl;
    }

    public void respondNotFound() {
      this.notFound = true;
    }

    public void addMetadata(String name, String value) {
      List<String> values = this.metadata.get(name);
      if (values == null) {
        values = new ArrayList<String>();
        this.metadata.put(name, values);
      }
      values.add(value);
    }

    public void addAnchor(URI uri, String text) {
      this.anchors.add(text);
    }

    public void setAcl(Acl acl) {
      this.acl = acl;
    }

    private boolean notFound() {
      return this.notFound;
    }

    private Map<String, List<String>> getMetadata() {
      return this.metadata;
    }

    private List<String> getAnchors() {
      return this.anchors;
    }

    private Acl getAcl() {
      return this.acl;
    }
  }

  void assertStartPointEquals(StartPoint actual,
      StartPoint.Type expectedType, String expectedName, int expectedNodeId) {
    assertEquals(expectedType, actual.getType());
    assertEquals(expectedName, actual.getName());
    assertEquals(expectedNodeId, actual.getNodeId());
  }

  // Set all the required config properties.
  private Config initConfig(OpentextAdaptor adaptor, AdaptorContext context) {
    Config config = context.getConfig();
    adaptor.initConfig(config);
    config.overrideKey("opentext.username", "validuser");
    config.overrideKey("opentext.password", "validpassword");
    config.overrideKey("opentext.webServicesUrl",
        "http://example.com/les-services/services");
    config.overrideKey("opentext.displayUrl.contentServerUrl",
        "http://example.com/otcs/livelink.exe");
    return config;
  }

  private XMLGregorianCalendar getXmlGregorianCalendar(
      int year, int month, int dayOfMonth,
      int hourOfDay, int minute, int second) {
    GregorianCalendar calendar = new GregorianCalendar(
        year, month, dayOfMonth, hourOfDay, minute, second);
    try {
      return DatatypeFactory.newInstance().newXMLGregorianCalendar(calendar);
    } catch (DatatypeConfigurationException datatypeException) {
      return null;
    }
  }

  private NodeRight getNodeRight(long rightId, String type) {
    NodePermissions nodePermissions = new NodePermissions();
    nodePermissions.setSeeContentsPermission(true);
    NodeRight nodeRight = new NodeRight();
    nodeRight.setRightID(rightId);
    nodeRight.setType(type);
    nodeRight.setPermissions(nodePermissions);
    return nodeRight;
  }

  /* Specifying the member type is required in order for
   * MemberService.getMemberById to work correctly, even though
   * in many cases we only need the name, not the type.
   */
  private Member getMember(long id, String name, String type) {
    Member member = new Member();
    member.setID(id);
    member.setName(name);
    member.setType(type);
    return member;
  }
}
