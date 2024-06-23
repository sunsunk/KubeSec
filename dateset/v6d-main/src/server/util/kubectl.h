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

#ifndef SRC_SERVER_UTIL_KUBECTL_H_
#define SRC_SERVER_UTIL_KUBECTL_H_

#include <list>
#include <memory>
#include <string>

#include "common/util/callback.h"
#include "common/util/json.h"
#include "server/util/proc.h"

namespace vineyard {

class Kubectl {
 public:
  explicit Kubectl(asio::io_context& context);

  ~Kubectl();

  void CreateObject(const json& cluster_meta, const json& object);

  void DeleteObject(const json& object);

  void Finish();

  std::list<std::string> const& Diagnostic() const {
    return proc_->Diagnostic();
  }

 private:
  std::shared_ptr<Process> proc_;

  void Create(const std::string& content, callback_t<> callback);

  void Delete(const std::string& content, callback_t<> callback);
};

}  // namespace vineyard

#endif  // SRC_SERVER_UTIL_KUBECTL_H_
