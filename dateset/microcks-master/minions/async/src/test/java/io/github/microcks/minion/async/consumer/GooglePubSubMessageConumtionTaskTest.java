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
package io.github.microcks.minion.async.consumer;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * This is a test case for GooglePubSubMessageConsumptionTask.
 * @author laurent
 */
public class GooglePubSubMessageConumtionTaskTest {

   @Test
   public void testAcceptEndpoint() {

      assertTrue(GooglePubSubMessageConsumptionTask.acceptEndpoint("googlepubsub://my-own-project-id/my-topic"));
   }

   @Test
   public void testAcceptEndpointFailures() {

      assertFalse(GooglePubSubMessageConsumptionTask.acceptEndpoint("googlepubsub:///my-own-project-id"));

      assertFalse(GooglePubSubMessageConsumptionTask.acceptEndpoint("googlepubsub:///my-own-project-id/my/topic/name"));

      assertFalse(GooglePubSubMessageConsumptionTask.acceptEndpoint("rabbit://localhost/x/testChannel"));
   }
}
