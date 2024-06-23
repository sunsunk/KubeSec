/*
 * Copyright The Microcks Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.github.microcks.util.el.function;

import java.security.SecureRandom;
import java.util.Random;

/**
 * This is a base class for random data generator that holds a secure random generator.
 * @author laurent
 */
public abstract class AbstractRandomELFunction implements ELFunction {

   private static Random random = new SecureRandom();

   /** Default protected constructor to hide the implicit one. */
   protected AbstractRandomELFunction() {
   }

   /** Get a random generator. */
   protected static Random getRandom() {
      return random;
   }
}
