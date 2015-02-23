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

class StartPoint {
  enum Type {
    VOLUME,
    NODE,
  }

  private Type type;
  /** The config parameter string. */
  private String name;
  /** The node id on the server. */
  private int nodeId = -1;

  StartPoint(String srcElement) {
    switch (srcElement) {
      case "EnterpriseWS": {
        this.type = Type.VOLUME;
        this.name = srcElement;
        break;
      }

      default: {
        try {
          this.nodeId = Integer.parseInt(srcElement);
          this.type = Type.NODE;
          this.name = srcElement;
          break;
        } catch (NumberFormatException numberFormatException) {
          throw new AssertionError();
        }
      }
    }
  }

  Type getType() {
    return this.type;
  }

  String getName() {
    return this.name;
  }

  int getNodeId() {
    return this.nodeId;
  }

  @Override
  public String toString() {
    return this.name;
  }
}
