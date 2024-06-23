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

#ifndef MODULES_LLM_CACHE_HASH_HASH_ALGORITHM_H_
#define MODULES_LLM_CACHE_HASH_HASH_ALGORITHM_H_

#include <string>

#include "MurmurHash3/MurmurHash3.h"
#include "cityhash/cityhash.hpp"

namespace vineyard {

class IHashAlgorithm {
 public:
  virtual ~IHashAlgorithm() {}
  virtual uint32_t hash(const std::string& input) = 0;
};

class MurmurHash3Algorithm : public IHashAlgorithm {
 public:
  uint32_t hash(const std::string& input) override {
    uint32_t value;
    MurmurHash3_x86_32(input.c_str(), input.size(), 0, &value);
    return value;
  }
};

class CityHashAlgorithm : public IHashAlgorithm {
 public:
  uint32_t hash(const std::string& input) override {
    uint32_t value;
    value = city::detail::CityHash32(input.c_str(), input.size());
    return value;
  }
};

}  // namespace vineyard

#endif  // MODULES_LLM_CACHE_HASH_HASH_ALGORITHM_H_
