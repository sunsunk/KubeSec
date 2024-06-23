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

#include "graph/fragment/graph_schema.h"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#include "arrow/api.h"
#include "arrow/io/api.h"

#include "basic/ds/arrow_utils.h"
#include "common/util/json.h"
#include "common/util/logging.h"

namespace vineyard {

namespace detail {

inline std::string ArrowDateTypeUnitToString(
    arrow::TimeUnit::type const& unit) {
  switch (unit) {
  case arrow::TimeUnit::SECOND:
    return "[S]";
  case arrow::TimeUnit::MILLI:
    return "[MS]";
  case arrow::TimeUnit::MICRO:
    return "[US]";
  case arrow::TimeUnit::NANO:
    return "[NS]";
  default:
    return "Unsupported time unit: '" + std::to_string(static_cast<int>(unit)) +
           "'";
  }
}

inline arrow::TimeUnit::type ArrowDateTypeUnitFromString(const char* unit) {
  if (std::strncmp(unit, "[S]", 3) == 0) {
    return arrow::TimeUnit::SECOND;
  } else if (std::strncmp(unit, "[MS]", 4) == 0) {
    return arrow::TimeUnit::MILLI;
  } else if (std::strncmp(unit, "[US]", 4) == 0) {
    return arrow::TimeUnit::MICRO;
  } else if (std::strncmp(unit, "[NS]", 4) == 0) {
    return arrow::TimeUnit::NANO;
  } else {
    LOG(ERROR) << "Unsupported time unit: '" << unit << "'";
    return arrow::TimeUnit::SECOND;
  }
}

inline arrow::TimeUnit::type ArrowDateTypeUnitFromString(
    std::string const& unit) {
  return ArrowDateTypeUnitFromString(unit.c_str());
}

std::string PropertyTypeToString(PropertyType type) {
  if (type == nullptr) {
    return "NULL";
  } else if (arrow::boolean()->Equals(type)) {
    return "BOOL";
  } else if (arrow::int8()->Equals(type)) {
    return "BYTE";
  } else if (arrow::int16()->Equals(type)) {
    return "SHORT";
  } else if (arrow::int32()->Equals(type)) {
    return "INT";
  } else if (arrow::int64()->Equals(type)) {
    return "LONG";
  } else if (arrow::float32()->Equals(type)) {
    return "FLOAT";
  } else if (arrow::uint8()->Equals(type)) {
    return "UBYTE";
  } else if (arrow::uint16()->Equals(type)) {
    return "USHORT";
  } else if (arrow::uint32()->Equals(type)) {
    return "UINT";
  } else if (arrow::uint64()->Equals(type)) {
    return "ULONG";
  } else if (arrow::float64()->Equals(type)) {
    return "DOUBLE";
  } else if (arrow::utf8()->Equals(type)) {
    return "STRING";
  } else if (arrow::large_utf8()->Equals(type)) {
    return "STRING";
  } else if (arrow::date32()->Equals(type)) {
    return "DATE32[DAY]";
  } else if (arrow::date64()->Equals(type)) {
    return "DATE64[MS]";
  } else if (type->id() == arrow::Type::TIME32) {
    auto time32_type = std::dynamic_pointer_cast<arrow::Time32Type>(type);
    const std::string unit = ArrowDateTypeUnitToString(time32_type->unit());
    return "TIME[32]" + unit;
  } else if (type->id() == arrow::Type::TIME64) {
    auto time64_type = std::dynamic_pointer_cast<arrow::Time64Type>(type);
    const std::string unit = ArrowDateTypeUnitToString(time64_type->unit());
    return "TIME[64]" + unit;
  } else if (type->id() == arrow::Type::TIMESTAMP) {
    auto timestamp_type = std::dynamic_pointer_cast<arrow::TimestampType>(type);
    const std::string unit = ArrowDateTypeUnitToString(timestamp_type->unit());
    const std::string timezone = timestamp_type->timezone();
    return "TIMESTAMP" + unit + "[" + timezone + "]";
  } else if (type->id() == arrow::Type::LIST) {
    auto ty = std::dynamic_pointer_cast<arrow::ListType>(type);
    return "LIST" + PropertyTypeToString(ty->value_type());
  } else if (type->id() == arrow::Type::LARGE_LIST) {
    auto ty = std::dynamic_pointer_cast<arrow::LargeListType>(type);
    return "LARGELIST" + PropertyTypeToString(ty->value_type());
  } else if (type->id() == arrow::Type::FIXED_SIZE_LIST) {
    auto ty = std::dynamic_pointer_cast<arrow::FixedSizeListType>(type);
    return "FIXEDLIST" + PropertyTypeToString(ty->value_type()) +
           std::to_string(ty->list_size());
  } else if (arrow::null()->Equals(type)) {
    return "NULL";
  }
  LOG(ERROR) << "Unsupported arrow type " << type->ToString();
  return "NULL";
}

std::string toupper(const std::string& s) {
  std::string upper_s = s;
  std::transform(s.begin(), s.end(), upper_s.begin(),
                 [](unsigned char c) { return std::toupper(c); });
  return upper_s;
}

PropertyType PropertyTypeFromString(const std::string& type) {
  auto type_upper = toupper(type);
  if (type_upper == "BOOL") {
    return arrow::boolean();
  } else if (type_upper == "BYTE") {
    return arrow::int8();
  } else if (type_upper == "SHORT") {
    return arrow::int16();
  } else if (type_upper == "INT") {
    return arrow::int32();
  } else if (type_upper == "LONG") {
    return arrow::int64();
  } else if (type_upper == "UBYTE") {
    return arrow::uint8();
  } else if (type_upper == "USHORT") {
    return arrow::uint16();
  } else if (type_upper == "UINT") {
    return arrow::uint32();
  } else if (type_upper == "ULONG") {
    return arrow::uint64();
  } else if (type_upper == "FLOAT") {
    return arrow::float32();
  } else if (type_upper == "DOUBLE") {
    return arrow::float64();
  } else if (type_upper == "STRING") {
    return arrow::large_utf8();
  } else if (type_upper == "DATE32[DAY]") {
    return arrow::date32();
  } else if (type_upper == "DATE64[MS]") {
    return arrow::date64();
  } else if (type_upper.substr(0, std::string("TIME[32]").length()) ==
             std::string("TIME[32]")) {
    const std::string unit_content =
        type_upper.substr(std::string("TIME[32]").length());
    arrow::TimeUnit::type unit = DefaultTimeUnit;
    if (unit_content.length() >= 3) {
      unit = ArrowDateTypeUnitFromString(unit_content);
    }
    return arrow::time32(unit);
  } else if (type_upper.substr(0, std::string("TIME[64]").length()) ==
             std::string("TIME[64]")) {
    const std::string unit_content =
        type_upper.substr(std::string("TIME[64]").length());
    arrow::TimeUnit::type unit = DefaultTimeUnit;
    if (unit_content.length() >= 3) {
      unit = ArrowDateTypeUnitFromString(unit_content);
    }
    return arrow::time64(unit);
  } else if (type_upper.substr(0, std::string("TIMESTAMP").length()) ==
             std::string("TIMESTAMP")) {
    const std::string unit_content =
        type_upper.substr(std::string("TIMESTAMP").length());
    arrow::TimeUnit::type unit = DefaultTimeUnit;
    if (unit_content.length() >= 3) {
      unit = ArrowDateTypeUnitFromString(unit_content);
      std::string timezone =
          type_upper.substr(std::string("TIMESTAMP").length() +
                            ArrowDateTypeUnitToString(unit).length());
      timezone = timezone.substr(1, timezone.length() - 2);
      return arrow::timestamp(unit);
    }
    return arrow::timestamp(DefaultTimeUnit);
  } else if (type_upper == "LISTINT") {
    return arrow::list(arrow::int32());
  } else if (type_upper == "LISTLONG") {
    return arrow::list(arrow::int64());
  } else if (type_upper == "LISTFLOAT") {
    return arrow::list(arrow::float32());
  } else if (type_upper == "LISTDOUBLE") {
    return arrow::list(arrow::float64());
  } else if (type_upper == "LISTSTRING") {
    return arrow::list(arrow::large_utf8());
  } else if (type_upper == "LARGELISTINT") {
    return arrow::large_list(arrow::int32());
  } else if (type_upper == "LARGELISTLONG") {
    return arrow::large_list(arrow::int64());
  } else if (type_upper == "LARGELISTFLOAT") {
    return arrow::large_list(arrow::float32());
  } else if (type_upper == "LARGELISTDOUBLE") {
    return arrow::large_list(arrow::float64());
  } else if (type_upper == "LARGELISTSTRING") {
    return arrow::large_list(arrow::large_utf8());
  } else if (type_upper.substr(0, std::string("FIXEDLIST").length()) ==
             std::string("FIXEDLIST")) {
    auto type_prefix_length = std::string("FIXEDLIST").size();
    if (type_upper.find("INT") == type_prefix_length) {
      int32_t list_size = std::stoi(type_upper.substr(type_prefix_length + 3));
      return arrow::fixed_size_list(arrow::int32(), list_size);
    } else if (type_upper.find("LONG") == type_prefix_length) {
      int32_t list_size = std::stoi(type_upper.substr(type_prefix_length + 4));
      return arrow::fixed_size_list(arrow::int64(), list_size);
    } else if (type_upper.find("FLOAT") == type_prefix_length) {
      int32_t list_size = std::stoi(type_upper.substr(type_prefix_length + 5));
      return arrow::fixed_size_list(arrow::float32(), list_size);
    } else if (type_upper.find("DOUBLE") == type_prefix_length) {
      int32_t list_size = std::stoi(type_upper.substr(type_prefix_length + 6));
      return arrow::fixed_size_list(arrow::float64(), list_size);
    } else if (type_upper.find("STRING") == type_prefix_length) {
      int32_t list_size = std::stoi(type_upper.substr(type_prefix_length + 6));
      return arrow::fixed_size_list(arrow::large_utf8(), list_size);
    } else {
      LOG(ERROR) << "Unsupported property type: '" << type_upper << "'";
      return arrow::null();
    }
  } else if (type_upper == "NULL") {
    return arrow::null();
  } else {
    return type_name_to_arrow_type(type);
  }
}

}  // namespace detail

json Entry::PropertyDef::ToJSON() const {
  json root;
  root["id"] = id;
  root["name"] = name;
  root["data_type"] = detail::PropertyTypeToString(type);
  return root;
}

void Entry::PropertyDef::FromJSON(const json& root) {
  id = root["id"].get<PropertyId>();
  name = root["name"].get_ref<std::string const&>();
  type = detail::PropertyTypeFromString(
      root["data_type"].get_ref<std::string const&>());
}

void Entry::AddProperty(const std::string& name, PropertyType type) {
  props_.emplace_back(PropertyDef{
      .id = static_cast<int>(props_.size()), .name = name, .type = type});
  valid_properties.push_back(1);
}

void Entry::RemoveProperty(const std::string& name) {
  for (auto const& prop : props_) {
    if (prop.name == name) {
      this->RemoveProperty(prop.id);
      break;
    }
  }
}

void Entry::RemoveProperty(const size_t index) {
  // the next new property id will be generated based on the property size.
  valid_properties[index] = 0;
}

void Entry::AddPrimaryKey(const std::string& key_name) {
  primary_keys.emplace_back(key_name);
}

void Entry::AddPrimaryKeys(const std::vector<std::string>& key_name_list) {
  for (auto const& key_name : key_name_list) {
    primary_keys.emplace_back(key_name);
  }
}

void Entry::AddPrimaryKeys(size_t key_count,
                           const std::vector<std::string>& key_name_list) {
  for (size_t idx = 0; idx < key_count; ++idx) {
    primary_keys.emplace_back(key_name_list[idx]);
  }
}

void Entry::AddRelation(const std::string& src, const std::string& dst) {
  relations.emplace_back(src, dst);
}

size_t Entry::property_num() const {
  return std::accumulate(valid_properties.begin(), valid_properties.end(), 0);
}

std::vector<Entry::PropertyDef> Entry::properties() const {
  std::vector<Entry::PropertyDef> res;
  for (size_t i = 0; i < valid_properties.size(); ++i) {
    if (valid_properties[i]) {
      res.push_back(props_[i]);
    }
  }
  return res;
}

Entry::PropertyId Entry::GetPropertyId(const std::string& name) const {
  for (const auto& prop : props_) {
    if (prop.name == name && valid_properties[prop.id]) {
      return prop.id;
    }
  }
  return -1;
}

std::string Entry::GetPropertyName(PropertyId prop_id) const {
  for (const auto& prop : props_) {
    if (prop.id == prop_id && valid_properties[prop.id]) {
      return prop.name;
    }
  }
  return "";
}

PropertyType Entry::GetPropertyType(PropertyId prop_id) const {
  for (const auto& prop : props_) {
    if (prop.id == prop_id && valid_properties[prop.id]) {
      return prop.type;
    }
  }
  return arrow::null();
}

json Entry::ToJSON() const {
  json root;
  root["id"] = id;
  root["label"] = label;
  root["type"] = type;
  json prop_array = json::array(), pk_array = json::array(),
       index_array = json::array(), relation_array = json::array();
  // propertyDefList
  for (const auto& prop : props_) {
    prop_array.emplace_back(prop.ToJSON());
  }
  root["propertyDefList"] = prop_array;
  // indexes
  if (!primary_keys.empty()) {
    json pk_array_tree = json::object();
    for (const auto& pk : primary_keys) {
      pk_array.emplace_back(pk);
    }
    pk_array_tree["propertyNames"] = pk_array;
    index_array.emplace_back(pk_array_tree);
  }
  root["indexes"] = index_array;
  // rawRelationShips
  if (!relations.empty()) {
    for (const auto& rel : relations) {
      json edge_tree;
      edge_tree["srcVertexLabel"] = rel.first;
      edge_tree["dstVertexLabel"] = rel.second;
      relation_array.emplace_back(edge_tree);
    }
  }
  root["rawRelationShips"] = relation_array;
  // mappings
  if (!mapping.empty()) {
    put_container(root, "mapping", mapping);
  }
  if (!reverse_mapping.empty()) {
    put_container(root, "reverse_mapping", reverse_mapping);
  }
  root["valid_properties"] = json(valid_properties);
  return root;
}

void Entry::FromJSON(const json& root) {
  id = root["id"].get<LabelId>();
  label = root["label"].get_ref<std::string const&>();
  type = root["type"].get_ref<std::string const&>();
  // propertyDefList
  const json& prop_array = root["propertyDefList"];
  for (const auto& item : prop_array) {
    PropertyDef prop;
    prop.FromJSON(item);
    props_.emplace_back(prop);
  }
  // indexes
  if (root.contains("indexes")) {
    for (const auto& index_arr_kv : root["indexes"]) {
      auto pk_arr = index_arr_kv["propertyNames"];
      if (!pk_arr.is_null()) {
        for (const auto& item : pk_arr) {
          primary_keys.emplace_back(item.get_ref<std::string const&>());
        }
        break;
      }
    }
  }
  // rawRelationShips
  if (root.contains("rawRelationShips")) {
    for (const auto& index_arr_kv : root["rawRelationShips"]) {
      auto src = index_arr_kv["srcVertexLabel"];
      auto dst = index_arr_kv["dstVertexLabel"];
      if (!src.is_null() && !dst.is_null()) {
        relations.emplace_back(src.get_ref<std::string const&>(),
                               dst.get_ref<std::string const&>());
      }
    }
  }
  // mapping
  if (root.contains("mapping")) {
    vineyard::get_container(root, "mapping", mapping);
  }
  if (root.contains("reverse_mapping")) {
    vineyard::get_container(root, "reverse_mapping", reverse_mapping);
  }
  if (root.contains("valid_properties")) {
    valid_properties = root["valid_properties"].get<std::vector<int>>();
  }
}

const std::string PropertyGraphSchema::VERTEX_TYPE_NAME = "VERTEX";
const std::string PropertyGraphSchema::EDGE_TYPE_NAME = "EDGE";

PropertyGraphSchema::PropertyId PropertyGraphSchema::GetVertexPropertyId(
    LabelId label_id, const std::string& name) const {
  if (label_id >= 0 &&
      label_id < static_cast<LabelId>(valid_vertices_.size()) &&
      valid_vertices_[label_id]) {
    return vertex_entries_[label_id].GetPropertyId(name);
  }
  return -1;
}

PropertyType PropertyGraphSchema::GetVertexPropertyType(
    LabelId label_id, PropertyId prop_id) const {
  if (label_id >= 0 &&
      label_id < static_cast<LabelId>(valid_vertices_.size()) &&
      valid_vertices_[label_id]) {
    return vertex_entries_[label_id].GetPropertyType(prop_id);
  }
  return arrow::null();
}

std::string PropertyGraphSchema::GetVertexPropertyName(
    LabelId label_id, PropertyId prop_id) const {
  if (label_id >= 0 &&
      label_id < static_cast<LabelId>(valid_vertices_.size()) &&
      valid_vertices_[label_id]) {
    return vertex_entries_[label_id].GetPropertyName(prop_id);
  }
  return "";
}

PropertyGraphSchema::PropertyId PropertyGraphSchema::GetEdgePropertyId(
    LabelId label_id, const std::string& name) const {
  if (label_id >= 0 && label_id < static_cast<LabelId>(valid_edges_.size()) &&
      valid_edges_[label_id]) {
    return edge_entries_[label_id].GetPropertyId(name);
  }
  return -1;
}

PropertyType PropertyGraphSchema::GetEdgePropertyType(
    LabelId label_id, PropertyId prop_id) const {
  if (label_id >= 0 && label_id < static_cast<LabelId>(valid_edges_.size()) &&
      valid_edges_[label_id]) {
    return edge_entries_[label_id].GetPropertyType(prop_id);
  }
  return arrow::null();
}

std::string PropertyGraphSchema::GetEdgePropertyName(LabelId label_id,
                                                     PropertyId prop_id) const {
  if (label_id >= 0 && label_id < static_cast<LabelId>(valid_edges_.size()) &&
      valid_edges_[label_id]) {
    return edge_entries_[label_id].GetPropertyName(prop_id);
  }
  return "";
}

PropertyGraphSchema::LabelId PropertyGraphSchema::GetVertexLabelId(
    const std::string& name) const {
  for (const auto& entry : vertex_entries_) {
    if (entry.label == name && valid_vertices_[entry.id]) {
      return entry.id;
    }
  }
  return -1;
}

std::string PropertyGraphSchema::GetVertexLabelName(LabelId label_id) const {
  if (label_id >= 0 &&
      label_id < static_cast<LabelId>(valid_vertices_.size()) &&
      valid_vertices_[label_id]) {
    return vertex_entries_[label_id].label;
  }
  return "";
}

PropertyGraphSchema::LabelId PropertyGraphSchema::GetEdgeLabelId(
    const std::string& name) const {
  for (const auto& entry : edge_entries_) {
    if (entry.label == name && valid_edges_[entry.id]) {
      return entry.id;
    }
  }
  return -1;
}

std::string PropertyGraphSchema::GetEdgeLabelName(LabelId label_id) const {
  if (label_id >= 0 && label_id < static_cast<LabelId>(valid_edges_.size()) &&
      valid_edges_[label_id]) {
    return edge_entries_[label_id].label;
  }
  return "";
}

Entry* PropertyGraphSchema::CreateEntry(const std::string& name,
                                        const std::string& type) {
  if (type == VERTEX_TYPE_NAME) {
    vertex_entries_.emplace_back(
        Entry{.id = static_cast<int>(vertex_entries_.size()),
              .label = name,
              .type = type});
    valid_vertices_.push_back(1);
    return &*vertex_entries_.rbegin();
  } else {
    edge_entries_.emplace_back(
        Entry{.id = static_cast<int>(edge_entries_.size()),
              .label = name,
              .type = type});
    valid_edges_.push_back(1);
    return &*edge_entries_.rbegin();
  }
}

void PropertyGraphSchema::AddEntry(const Entry& entry) {
  if (entry.type == VERTEX_TYPE_NAME) {
    vertex_entries_.push_back(entry);
    valid_vertices_.push_back(1);
  } else {
    edge_entries_.push_back(entry);
    valid_edges_.push_back(1);
  }
}

const Entry& PropertyGraphSchema::GetEntry(LabelId label_id,
                                           const std::string& type) const {
  if (type == VERTEX_TYPE_NAME) {
    return vertex_entries_[label_id];
  } else {
    return edge_entries_[label_id];
  }
}

Entry& PropertyGraphSchema::GetMutableEntry(const std::string& label,
                                            const std::string& type) {
  if (type == VERTEX_TYPE_NAME) {
    for (auto& entry : vertex_entries_) {
      if (entry.label == label) {
        return entry;
      }
    }
  } else {
    for (auto& entry : edge_entries_) {
      if (entry.label == label) {
        return entry;
      }
    }
  }
  throw std::runtime_error("Not found the entry of label " + type + " " +
                           label);
}

Entry& PropertyGraphSchema::GetMutableEntry(const LabelId label_id,
                                            const std::string& type) {
  if (type == VERTEX_TYPE_NAME) {
    return vertex_entries_[label_id];
  } else {
    return edge_entries_[label_id];
  }
}

std::vector<Entry> PropertyGraphSchema::vertex_entries() const {
  return ValidVertexEntries();
}

std::vector<Entry> PropertyGraphSchema::edge_entries() const {
  return ValidEdgeEntries();
}

std::vector<Entry> PropertyGraphSchema::AllVertexEntries() const {
  return vertex_entries_;
}

std::vector<Entry> PropertyGraphSchema::AllEdgeEntries() const {
  return edge_entries_;
}

std::vector<Entry> PropertyGraphSchema::ValidVertexEntries() const {
  std::vector<Entry> res;
  for (size_t i = 0; i < valid_vertices_.size(); ++i) {
    if (valid_vertices_[i]) {
      res.push_back(vertex_entries_[i]);
    }
  }
  return res;
}

std::vector<Entry> PropertyGraphSchema::ValidEdgeEntries() const {
  std::vector<Entry> res;
  for (size_t i = 0; i < valid_edges_.size(); ++i) {
    if (valid_edges_[i]) {
      res.push_back(edge_entries_[i]);
    }
  }
  return res;
}

bool PropertyGraphSchema::IsVertexValid(const LabelId label_id) const {
  return valid_vertices_[label_id];
}

bool PropertyGraphSchema::IsEdgeValid(const LabelId label_id) const {
  return valid_edges_[label_id];
}

std::vector<std::string> PropertyGraphSchema::GetVertexLabels() const {
  std::vector<std::string> labels;
  for (size_t i = 0; i < vertex_entries_.size(); ++i) {
    if (valid_vertices_[i]) {
      labels.emplace_back(vertex_entries_[i].label);
    }
  }
  return labels;
}

std::vector<std::string> PropertyGraphSchema::GetEdgeLabels() const {
  std::vector<std::string> labels;
  for (size_t i = 0; i < edge_entries_.size(); ++i) {
    if (valid_edges_[i]) {
      labels.emplace_back(edge_entries_[i].label);
    }
  }
  return labels;
}

std::vector<std::pair<std::string, std::string>>
PropertyGraphSchema::GetVertexPropertyListByLabel(
    const std::string& label) const {
  LabelId label_id = GetVertexLabelId(label);
  return GetVertexPropertyListByLabel(label_id);
}

std::vector<std::pair<std::string, std::string>>
PropertyGraphSchema::GetVertexPropertyListByLabel(LabelId label_id) const {
  std::vector<std::pair<std::string, std::string>> properties;
  if (label_id >= 0 &&
      label_id < static_cast<LabelId>(valid_vertices_.size()) &&
      valid_vertices_[label_id]) {
    for (auto& prop : vertex_entries_[label_id].properties()) {
      properties.emplace_back(prop.name,
                              detail::PropertyTypeToString(prop.type));
    }
  }
  return properties;
}

std::vector<std::pair<std::string, std::string>>
PropertyGraphSchema::GetEdgePropertyListByLabel(
    const std::string& label) const {
  LabelId label_id = GetEdgeLabelId(label);
  return GetEdgePropertyListByLabel(label_id);
}

std::vector<std::pair<std::string, std::string>>
PropertyGraphSchema::GetEdgePropertyListByLabel(LabelId label_id) const {
  std::vector<std::pair<std::string, std::string>> properties;
  if (label_id >= 0 && label_id < static_cast<LabelId>(valid_edges_.size()) &&
      valid_edges_[label_id]) {
    for (auto& prop : edge_entries_[label_id].properties()) {
      properties.emplace_back(prop.name,
                              detail::PropertyTypeToString(prop.type));
    }
  }
  return properties;
}

json PropertyGraphSchema::ToJSON() const {
  json root = json::object();
  this->ToJSON(root);
  return root;
}

void PropertyGraphSchema::ToJSON(json& root) const {
  root["partitionNum"] = fnum_;
  json types = json::array();
  for (const auto& entry : vertex_entries_) {
    types.emplace_back(entry.ToJSON());
  }
  for (const auto& entry : edge_entries_) {
    types.emplace_back(entry.ToJSON());
  }
  root["types"] = types;
  root["valid_vertices"] = json(valid_vertices_);
  root["valid_edges"] = json(valid_edges_);
}

void PropertyGraphSchema::FromJSON(json const& root) {
  fnum_ = root["partitionNum"].get<size_t>();
  for (const auto& item : root["types"]) {
    Entry entry;
    entry.FromJSON(item);
    if (entry.type == VERTEX_TYPE_NAME) {
      vertex_entries_.push_back(std::move(entry));
    } else {
      edge_entries_.push_back(std::move(entry));
    }
  }
  if (root.contains("valid_vertices")) {
    valid_vertices_ = root["valid_vertices"].get<std::vector<int>>();
  }
  if (root.contains("valid_edges")) {
    valid_edges_ = root["valid_edges"].get<std::vector<int>>();
  }
}

std::string PropertyGraphSchema::ToJSONString() const {
  std::stringstream ss;
  json root;
  ToJSON(root);
  return json_to_string(root);
}

void PropertyGraphSchema::FromJSONString(std::string const& schema) {
  json root = json::parse(schema);
  FromJSON(root);
}

void PropertyGraphSchema::DumpToFile(std::string const& path) {
  std::ofstream json_file;
  json_file.open(path);
  json_file << this->ToJSONString();
  json_file.close();
}

bool PropertyGraphSchema::Validate(std::string& message) {
  // We only need to check entries that are still valid.
  auto v_entries = vertex_entries();
  auto e_entries = edge_entries();

  std::vector<Entry::PropertyDef> all_props;
  for (const auto& entry : v_entries) {
    auto properties = entry.properties();
    all_props.insert(all_props.end(), properties.begin(), properties.end());
  }
  for (const auto& entry : e_entries) {
    auto properties = entry.properties();
    all_props.insert(all_props.end(), properties.begin(), properties.end());
  }
  std::sort(
      all_props.begin(), all_props.end(),
      [](const auto& lhs, const auto& rhs) { return lhs.name < rhs.name; });
  return true;
}
const std::map<std::string, int>&
PropertyGraphSchema::GetPropertyNameToIDMapping() const {
  return name_to_idx_;
}

MaxGraphSchema::MaxGraphSchema(const PropertyGraphSchema& schema) {
  const auto& v_entries = schema.vertex_entries_;
  const auto& e_entries = schema.edge_entries_;
  // Gather all property names and unique them
  std::set<std::string> prop_names;
  for (const auto& entry : v_entries) {
    for (const auto& prop : entry.props_) {
      prop_names.insert(prop.name);
    }
  }
  for (const auto& entry : e_entries) {
    for (const auto& prop : entry.props_) {
      prop_names.insert(prop.name);
    }
  }

  // Assign a id to each name.
  unique_property_names_.assign(prop_names.begin(), prop_names.end());
  std::map<std::string, int> name_to_idx;
  // mg's prop id: starts from 1
  int maximum_possible_mg_prop_id = 1 + unique_property_names_.size();
  for (size_t i = 0; i < unique_property_names_.size(); ++i) {
    name_to_idx[unique_property_names_[i]] = 1 + i;  // starts from 1
  }

  // Assign generated id to property by name.
  for (const auto& entry : v_entries) {
    Entry new_entry = entry;
    std::fill(new_entry.valid_properties.begin(),
              new_entry.valid_properties.end(), 1);
    new_entry.mapping.resize(maximum_possible_mg_prop_id, -1);
    new_entry.reverse_mapping.resize(maximum_possible_mg_prop_id, 1);
    for (auto& prop : new_entry.props_) {
      new_entry.mapping[prop.id] = name_to_idx[prop.name];
      new_entry.reverse_mapping[name_to_idx[prop.name]] = prop.id;
      prop.id = name_to_idx[prop.name];
    }
    entries_.push_back(new_entry);
  }
  int vertex_label_num = v_entries.size();
  for (const auto& entry : e_entries) {
    Entry new_entry = entry;
    std::fill(new_entry.valid_properties.begin(),
              new_entry.valid_properties.end(), 1);
    new_entry.id += vertex_label_num;
    new_entry.mapping.resize(maximum_possible_mg_prop_id, -1);
    new_entry.reverse_mapping.resize(maximum_possible_mg_prop_id, 1);
    for (auto& prop : new_entry.props_) {
      new_entry.mapping[prop.id] = name_to_idx[prop.name];
      new_entry.reverse_mapping[name_to_idx[prop.name]] = prop.id;
      prop.id = name_to_idx[prop.name];
    }
    entries_.push_back(new_entry);
  }
  fnum_ = schema.fnum();
}

MaxGraphSchema::PropertyId MaxGraphSchema::GetPropertyId(
    const std::string& name) {
  PropertyId id;
  for (const auto& entry : entries_) {
    id = entry.GetPropertyId(name);
    if (id != -1) {
      return id;
    }
  }
  return -1;
}

PropertyType MaxGraphSchema::GetPropertyType(LabelId label_id,
                                             PropertyId prop_id) {
  PropertyType type;
  for (const auto& entry : entries_) {
    if (entry.id == label_id) {
      type = entry.GetPropertyType(prop_id);
      if (!type->Equals(arrow::null())) {
        return type;
      }
    }
  }
  return arrow::null();
}

std::string MaxGraphSchema::GetPropertyName(PropertyId prop_id) {
  std::string name;
  for (const auto& entry : entries_) {
    name = entry.GetPropertyName(prop_id);
    if (!name.empty()) {
      return name;
    }
  }
  return "";
}

MaxGraphSchema::LabelId MaxGraphSchema::GetLabelId(const std::string& name) {
  for (const auto& entry : entries_) {
    if (entry.label == name) {
      return entry.id;
    }
  }
  return -1;
}

std::string MaxGraphSchema::GetLabelName(LabelId label_id) {
  for (const auto& entry : entries_) {
    if (entry.id == label_id) {
      return entry.label;
    }
  }
  return "";
}

void MaxGraphSchema::ToJSON(json& root) const {
  root["partitionNum"] = fnum_;
  json types = json::array();
  for (const auto& entry : entries_) {
    types.emplace_back(entry.ToJSON());
  }
  root["types"] = types;
  root["uniquePropertyNames"] = unique_property_names_;
}

void MaxGraphSchema::FromJSON(json const& root) {
  fnum_ = root["partitionNum"].get<size_t>();
  for (const auto& item : root["types"]) {
    Entry entry;
    entry.FromJSON(item);
    entries_.push_back(std::move(entry));
  }
}

std::string MaxGraphSchema::ToJSONString() const {
  std::stringstream ss;
  json root;
  ToJSON(root);
  return json_to_string(root);
}

void MaxGraphSchema::FromJSONString(std::string const& schema) {
  json root = json::parse(schema);
  FromJSON(root);
}

void MaxGraphSchema::DumpToFile(std::string const& path) {
  std::ofstream json_file;
  json_file.open(path);
  json_file << this->ToJSONString();
  json_file.close();
}

}  // namespace vineyard
