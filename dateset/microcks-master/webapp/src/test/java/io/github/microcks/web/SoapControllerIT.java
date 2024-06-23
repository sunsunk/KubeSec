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
package io.github.microcks.web;

import org.junit.Test;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static org.junit.Assert.*;

/**
 * Test case for the Soap mock controller.
 * @author laurent
 */
public class SoapControllerIT extends AbstractBaseIT {

   @Test
   public void testHelloSoapWSMocking() {
      // Upload Hello Service SoapUI project.
      uploadArtifactFile("target/test-classes/io/github/microcks/util/soapui/HelloService-soapui-project.xml", true);

      // Create SOAP 1.2 headers for sayHello operation.
      HttpHeaders headers = new HttpHeaders();
      headers.put("Content-type", Collections.singletonList("application/soap+xml;action=sayHello"));

      // Build the request.
      String request = "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:hel=\"http://www.example.com/hello\">\n"
            + "   <soapenv:Header/>\n" + "   <soapenv:Body>\n" + "      <hel:sayHello>\n"
            + "         <name>Karla</name>\n" + "      </hel:sayHello>\n" + "   </soapenv:Body>\n"
            + "</soapenv:Envelope>";
      HttpEntity<String> entity = new HttpEntity<>(request, headers);

      // Execute and assert.
      ResponseEntity<String> response = restTemplate.postForEntity("/soap/HelloService+Mock/0.9", entity, String.class);
      assertEquals(200, response.getStatusCode().value());
      assertEquals(
            "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:hel=\"http://www.example.com/hello\">\n"
                  + "   <soapenv:Header/>\n" + "   <soapenv:Body>\n" + "      <hel:sayHelloResponse>\n"
                  + "         <sayHello>Hello Karla !</sayHello>\n" + "      </hel:sayHelloResponse>\n"
                  + "   </soapenv:Body>\n" + "</soapenv:Envelope>",
            response.getBody());
      assertEquals("application/soap+xml;charset=UTF-8", response.getHeaders().getContentType().toString());

      // Create SOAP 1.1 headers for sayHello operation.
      headers = new HttpHeaders();
      headers.put("SOAPAction", Collections.singletonList("\"sayHello\""));

      // Build the request.
      request = "<soap-env:Envelope xmlns:soap-env=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:hel=\"http://www.example.com/hello\">\n"
            + "   <soap-env:Header/>\n" + "   <soap-env:Body>\n" + "      <hel:sayHello>\n"
            + "         <name>Andrew</name>\n" + "      </hel:sayHello>\n" + "   </soap-env:Body>\n"
            + "</soap-env:Envelope>";
      entity = new HttpEntity<>(request, headers);

      // Execute and assert, content-type is different for SOAP 1.1.
      response = restTemplate.postForEntity("/soap/HelloService+Mock/0.9", entity, String.class);
      assertEquals(200, response.getStatusCode().value());
      assertEquals(
            "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:hel=\"http://www.example.com/hello\">\n"
                  + "   <soapenv:Header/>\n" + "   <soapenv:Body>\n" + "      <hel:sayHelloResponse>\n"
                  + "         <sayHello>Hello Andrew !</sayHello>\n" + "      </hel:sayHelloResponse>\n"
                  + "   </soapenv:Body>\n" + "</soapenv:Envelope>",
            response.getBody());
      assertEquals("text/xml;charset=UTF-8", response.getHeaders().getContentType().toString());

      // Test exception case.
      request = "<soap-env:Envelope xmlns:soap-env=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:hel=\"http://www.example.com/hello\">\n"
            + "   <soap-env:Header/>\n" + "   <soap-env:Body>\n" + "      <hel:sayHello>\n"
            + "         <name>World</name>\n" + "      </hel:sayHello>\n" + "   </soap-env:Body>\n"
            + "</soap-env:Envelope>";
      entity = new HttpEntity<>(request, headers);

      // Execute and assert.
      response = restTemplate.postForEntity("/soap/HelloService+Mock/0.9", entity, String.class);
      assertEquals(500, response.getStatusCode().value());
      assertEquals(
            "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:hel=\"http://www.example.com/hello\">\n"
                  + "   <soapenv:Header/>\n" + "   <soapenv:Body>\n" + "      <soapenv:Fault>\n"
                  + "         <faultcode>soapenv:Sender</faultcode>\n"
                  + "         <faultstring>Unknown name</faultstring>\n" + "         <detail>\n"
                  + "            <hel:HelloException>\n" + "               <code>999</code>\n"
                  + "            </hel:HelloException>\n" + "         </detail>\n" + "      </soapenv:Fault>\n"
                  + "   </soapenv:Body>\n" + "</soapenv:Envelope>",
            response.getBody());
   }

   @Test
   public void testHelloRandomSoapWSMocking() {
      // given list of responses
      List<String> okResponses = new ArrayList<>();
      List<String> koResponses = new ArrayList<>();
      okResponses.add(
            "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:hel=\"http://www.example.com/hello\">\n"
                  + "   <soapenv:Header/>\n" + "   <soapenv:Body>\n" + "      <hel:sayHelloResponse>\n"
                  + "         <sayHello>Hello Karla !</sayHello>\n" + "      </hel:sayHelloResponse>\n"
                  + "   </soapenv:Body>\n" + "</soapenv:Envelope>");
      okResponses.add(
            "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:hel=\"http://www.example.com/hello\">\n"
                  + "   <soapenv:Header/>\n" + "   <soapenv:Body>\n" + "      <hel:sayHelloResponse>\n"
                  + "         <sayHello>Hello Andrew !</sayHello>\n" + "      </hel:sayHelloResponse>\n"
                  + "   </soapenv:Body>\n" + "</soapenv:Envelope>");
      koResponses.add(
            "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:hel=\"http://www.example.com/hello\">\n"
                  + "   <soapenv:Header/>\n" + "   <soapenv:Body>\n" + "      <soapenv:Fault>\n"
                  + "         <faultcode>soapenv:Sender</faultcode>\n"
                  + "         <faultstring>Unknown name</faultstring>\n" + "         <detail>\n"
                  + "            <hel:HelloException>\n" + "               <code>999</code>\n"
                  + "            </hel:HelloException>\n" + "         </detail>\n" + "      </soapenv:Fault>\n"
                  + "   </soapenv:Body>\n" + "</soapenv:Envelope>");


      // Upload Hello Service SoapUI project.
      uploadArtifactFile("target/test-classes/io/github/microcks/util/soapui/HelloService-random-soapui-project.xml",
            true);

      // Create SOAP 1.2 headers for sayHello operation.
      HttpHeaders headers = new HttpHeaders();
      headers.put("Content-type", Collections.singletonList("application/soap+xml;action=sayHello"));

      // Build the request.
      String request = "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:hel=\"http://www.example.com/hello\">\n"
            + "   <soapenv:Header/>\n" + "   <soapenv:Body>\n" + "      <hel:sayHello>\n"
            + "         <name>whatever</name>\n" + "      </hel:sayHello>\n" + "   </soapenv:Body>\n"
            + "</soapenv:Envelope>";
      HttpEntity<String> entity = new HttpEntity<>(request, headers);

      // Execute and assert.
      for (int i = 0; i < 10; ++i) {
         ResponseEntity<String> response = restTemplate.postForEntity("/soap/HelloService+Mock/0.9", entity,
               String.class);
         switch (response.getStatusCode().value()) {
            case 200:
               assertTrue(okResponses.contains(response.getBody()));
               break;
            case 500:
               assertTrue(koResponses.contains(response.getBody()));
               break;
            default:
               fail();
         }
      }
   }
}
