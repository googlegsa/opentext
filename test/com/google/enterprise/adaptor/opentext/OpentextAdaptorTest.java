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
import com.google.enterprise.adaptor.AdaptorContext;
import com.google.enterprise.adaptor.Config;
import com.google.enterprise.adaptor.DocId;
import com.google.enterprise.adaptor.DocIdPusher;
import com.google.enterprise.adaptor.InvalidConfigurationException;
import com.google.enterprise.adaptor.Request;
import com.google.enterprise.adaptor.Response;

import com.opentext.livelink.service.core.Authentication;
import com.opentext.livelink.service.core.ContentService;
import com.opentext.livelink.service.docman.DocumentManagement;
import com.opentext.livelink.service.docman.Node;
import com.opentext.livelink.service.docman.Version;

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
import java.util.List;

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
    assertEquals(2, excludedNodeTypes.size());
    assertEquals(Lists.newArrayList("Alias", "URL"), excludedNodeTypes);
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
    adaptor.init(context);

    URI displayUrl = adaptor.getDisplayUrl("Document", 12345);
    assertEquals("http://example.com/otcs/livelink.exe" +
        "?func=ll&objAction=overview&objId=12345", displayUrl.toString());

    displayUrl = adaptor.getDisplayUrl("UnknownType", 12345);
    assertEquals("http://example.com/otcs/livelink.exe" +
        "?func=ll&objAction=properties&objId=12345", displayUrl.toString());
  }

  @Test
  public void testGetDisplayUrlPathInfo() {
    SoapFactoryMock soapFactory = new SoapFactoryMock();
    OpentextAdaptor adaptor = new OpentextAdaptor(soapFactory);
    AdaptorContext context = ProxyAdaptorContext.getInstance();
    Config config = initConfig(adaptor, context);
    config.overrideKey(
        "opentext.displayUrl.queryString.Document", "/open/{1}");
    adaptor.init(context);

    URI displayUrl = adaptor.getDisplayUrl("Document", 12345);
    assertEquals("http://example.com/otcs/livelink.exe/open/12345",
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

  private class SoapFactoryMock implements SoapFactory {
    private AuthenticationMock authenticationMock;
    private DocumentManagementMock documentManagementMock;
    private ContentServiceMock contentServiceMock;

    private SoapFactoryMock() {
      this.authenticationMock = new AuthenticationMock();
      this.documentManagementMock = new DocumentManagementMock();
      this.contentServiceMock = new ContentServiceMock();
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

    @Override
    public ContentService newContentService(
        DocumentManagement documentManagement) {
      return Proxies.newProxyInstance(ContentService.class,
          this.contentServiceMock);
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

  private class NodeMock extends Node {
    private long id;
    private String name;
    private boolean isVersionable;
    private String objectType;
    private long parentId;

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
    public void setParentID(long parentId) {
      this.parentId = parentId;
    }

    @Override
    public long getParentID() {
      return this.parentId;
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

    private boolean notFound() {
      return this.notFound;
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
}
