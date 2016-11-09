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

import static org.junit.Assert.assertEquals;

import com.google.common.collect.Lists;
import com.google.enterprise.adaptor.DocId;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.util.ArrayList;

/**
 * Tests the OpentextDocId class.
 */
public class OpentextDocIdTest {
  @Rule
  public ExpectedException thrown = ExpectedException.none();

  @Test
  public void testVolumeStartPoint() {
    DocId adaptorDocId = new DocId("EnterpriseWS:2000");
    OpentextDocId docId = new OpentextDocId(adaptorDocId);
    assertEquals(adaptorDocId, docId.getDocId());
    ArrayList<String> expectedPath = Lists.newArrayList("EnterpriseWS");
    assertEquals(expectedPath, docId.getPath());
    assertEquals("EnterpriseWS", docId.getEncodedPath());
    assertEquals(2000, docId.getNodeId());
  }

  @Test
  public void testNodeStartPoint() {
    DocId adaptorDocId = new DocId("4321:4321");
    OpentextDocId docId = new OpentextDocId(adaptorDocId);
    assertEquals(adaptorDocId, docId.getDocId());
    ArrayList<String> expectedPath = Lists.newArrayList("4321");
    assertEquals(expectedPath, docId.getPath());
    assertEquals("4321", docId.getEncodedPath());
    assertEquals(4321, docId.getNodeId());
  }

  @Test
  public void testInvalidIdMissingNodeId() {
    thrown.expect(IllegalArgumentException.class);
    thrown.expectMessage("InvalidId");

    DocId adaptorDocId = new DocId("InvalidId");
    OpentextDocId docId = new OpentextDocId(adaptorDocId);
  }

  @Test
  public void testInvalidIdExtraComponents() {
    thrown.expect(IllegalArgumentException.class);
    thrown.expectMessage("InvalidId:234:543");

    DocId adaptorDocId = new DocId("InvalidId:234:543");
    OpentextDocId docId = new OpentextDocId(adaptorDocId);
  }

  @Test
  public void testPath() {
    DocId adaptorDocId = new DocId("StartPoint/folder+1/folder+1/node:4321");
    OpentextDocId docId = new OpentextDocId(adaptorDocId);
    assertEquals(adaptorDocId, docId.getDocId());
    ArrayList<String> expectedPath =
        Lists.newArrayList("StartPoint", "folder 1", "folder 1", "node");
    assertEquals(expectedPath, docId.getPath());
    assertEquals("StartPoint/folder+1/folder+1/node", docId.getEncodedPath());
    assertEquals(4321, docId.getNodeId());
  }

  @Test
  public void testPathWhenItemContainsSlash() {
    DocId adaptorDocId =
        new DocId("StartPoint/folder+1%2fqualifier/node:4321");
    OpentextDocId docId = new OpentextDocId(adaptorDocId);
    assertEquals(adaptorDocId, docId.getDocId());
    ArrayList<String> expectedPath =
        Lists.newArrayList("StartPoint", "folder 1/qualifier", "node");
    assertEquals(expectedPath, docId.getPath());
    assertEquals(
        "StartPoint/folder+1%2fqualifier/node", docId.getEncodedPath());
    assertEquals(4321, docId.getNodeId());
  }
}
