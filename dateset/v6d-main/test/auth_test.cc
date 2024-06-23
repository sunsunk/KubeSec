/** Copyright 2020-2023 Alibaba Group Holding Limited.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include <memory>
#include <string>
#include <thread>

#include "arrow/api.h"
#include "arrow/io/api.h"

#include "basic/ds/array.h"
#include "client/client.h"
#include "client/ds/object_meta.h"
#include "common/util/logging.h"

using namespace vineyard;  // NOLINT(build/namespaces)

int main(int argc, char** argv) {
  if (argc < 2) {
    printf("usage ./auth_test <ipc_socket>");
    return 1;
  }
  std::string ipc_socket = std::string(argv[1]);

  Client client;
  {
    auto s = client.Connect(ipc_socket);
    LOG(INFO) << "connect status: " << s;
    CHECK(s.IsConnectionError());
  }
  {
    auto s = client.Connect(ipc_socket, "test1", "pass1111");
    LOG(INFO) << "connect status: " << s;
    CHECK(s.IsConnectionError());
  }
  {
    auto s = client.Connect(ipc_socket, "test1", "pass1");
    LOG(INFO) << "connect status: " << s;
    CHECK(s.ok());
  }

  LOG(INFO) << "Passed auth tests...";

  client.Disconnect();

  return 0;
}
