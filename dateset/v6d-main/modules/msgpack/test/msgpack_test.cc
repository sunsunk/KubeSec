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

#include "arrow/status.h"
#include "arrow/util/io_util.h"
#include "arrow/util/logging.h"

#include "basic/ds/array.h"
#include "client/client.h"
#include "client/ds/object_meta.h"
#include "common/util/logging.h"
#include "msgpack/packed_object.h"

using namespace vineyard;  // NOLINT(build/namespaces)
using vineyard::PackedObject;
using vineyard::VBuffer;

int main(int argc, char** argv) {
  if (argc < 2) {
    printf("usage ./msgpack_test <ipc_socket>");
    return 1;
  }
  std::string ipc_socket = std::string(argv[1]);

  Client client;
  VINEYARD_CHECK_OK(client.Connect(ipc_socket));
  LOG(INFO) << "Connected to IPCServer: " << ipc_socket;

  std::vector<double> double_array = {1.0, 7.0, 3.0, 4.0, 2.0};
  ArrayBuilder<double> builder(client, double_array);
  auto sealed_double_array =
      std::dynamic_pointer_cast<Array<double>>(builder.Seal(client));
  LOG(INFO) << "successfully sealed...";

  PackedObject packed(sealed_double_array);

  LOG(INFO) << "Passed msgpack array tests...";

  client.Disconnect();

  return 0;
}
