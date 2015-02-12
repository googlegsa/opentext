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

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;

/**
 * Handles method calls on a proxy interface by using reflection to
 * map the calls to methods on a target object. The target classes
 * should simply implement the proxy interface methods they need
 * (without using {@code @Override}). The called methods in the target
 * class can obtain their own name by calling {@link #getMethodName}.
 */
final class Proxies {
  /**
   * Gets a new proxy instance that delegates calls to the given
   * target using reflection.
   *
   * @param clazz the {@code Interface} for the proxy class to implement
   * @param target an instance of a class implementing the required
   *     subset of methods in the proxy interface
   */
  public static <T> T newProxyInstance(Class<T> clazz, Object target) {
    return clazz.cast(Proxy.newProxyInstance(clazz.getClassLoader(),
        new Class<?>[] { clazz },
        new ReflectionInvocationHandler(target)));
  }

  /** The name of the current method. */
  private static final ThreadLocal<String> methodName
      = new ThreadLocal<String>();

  /** Gets the name of the current method. */
  public static String getMethodName() {
    return methodName.get();
  }

  private static class ReflectionInvocationHandler
      implements InvocationHandler {
    private final Object target;

    private ReflectionInvocationHandler(Object target) {
      this.target = target;
    }

    /**
     * Looks up the given method name and parameter types on the
     * target's class and invokes the method on {@code target}.
     *
     * @throws UnsupportedOperationException if the called method does
     *     not exist or is inaccessible
     * @throws IllegalArgumentException if a narrowing conversion is
     *     required from the actual arguments to the proxy interface
     *     method's parameter types
     */
    @Override
    public Object invoke(Object proxy, Method method, Object[] args)
        throws Throwable {
      try {
        methodName.set(method.getName());
        Method targetMethod = target.getClass().getMethod(method.getName(),
            method.getParameterTypes());
        return targetMethod.invoke(target, args);
      } catch (NoSuchMethodException e) {
        throw new UnsupportedOperationException(e);
      } catch (IllegalAccessException e) {
        throw new UnsupportedOperationException(e);
      } catch (InvocationTargetException e) {
        throw e.getCause();
      } finally {
        methodName.remove();
      }
    }
  }
}
