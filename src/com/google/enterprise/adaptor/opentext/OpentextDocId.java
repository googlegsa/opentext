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

import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.enterprise.adaptor.DocId;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.Arrays;
import java.util.List;

class OpentextDocId {

  private DocId docId;
  private List<String> path;

  /** The original uniqueId without the appended node id. Used to
   * construct child ids. */
  private String encodedPath;
  private long nodeId = -1;

  OpentextDocId(DocId docId) {
    this.docId = docId;

    String uniqueId = docId.getUniqueId();
    String[] idElements = uniqueId.split(":");
    if (idElements.length != 2) {
      throw new IllegalArgumentException(uniqueId);
    }
    this.encodedPath = idElements[0];
    String[] pathElements = idElements[0].split("/");
    for (int i = 0; i < pathElements.length; i++) {
      try {
        pathElements[i] = URLDecoder.decode(pathElements[i], UTF_8.name());
      } catch (UnsupportedEncodingException unsupportedEncoding) {
        // UTF-8 is required to be supported; URLDecoder.decode
        // doesn't know that.
      }
    }
    this.path = Arrays.asList(pathElements);

    try {
      this.nodeId = Long.parseLong(idElements[1]);
    } catch (NumberFormatException numberFormatException) {
      throw new IllegalArgumentException(uniqueId, numberFormatException);
    }
  }

  DocId getDocId() {
    return this.docId;
  }

  List<String> getPath() {
    return this.path;
  }

  String getEncodedPath() {
    return this.encodedPath;
  }

  long getNodeId() {
    return this.nodeId;
  }

  @Override
  public String toString() {
    return this.docId.toString();
  }
}
