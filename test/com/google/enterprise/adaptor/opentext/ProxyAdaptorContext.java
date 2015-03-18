// Copyright 2015 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package com.google.enterprise.adaptor.opentext;

import com.google.enterprise.adaptor.AdaptorContext;
import com.google.enterprise.adaptor.Config;
import com.google.enterprise.adaptor.DocId;
import com.google.enterprise.adaptor.DocIdEncoder;
import com.google.enterprise.adaptor.SensitiveValueDecoder;

import java.lang.reflect.Proxy;
import java.net.URI;

class ProxyAdaptorContext {
  public static AdaptorContext getInstance() {
    return Proxies.newProxyInstance(AdaptorContext.class,
        new AdaptorContextMock());
  }

  private static class AdaptorContextMock {
    private final Config config = new Config();

    public Config getConfig() {
      return config;
    }

    public SensitiveValueDecoder getSensitiveValueDecoder() {
      return new SensitiveValueDecoder() {
        public String decodeValue(String nonReadable) {
          return nonReadable;
        }
      };
    }

    public DocIdEncoder getDocIdEncoder() {
      return new DocIdEncoder() {
        public URI encodeDocId(DocId docId) {
          return URI.create(docId.getUniqueId());
        }
      };
    }
  }
}
