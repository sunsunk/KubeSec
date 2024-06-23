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

#ifndef MODULES_GRAPH_WRITER_ARROW_FRAGMENT_WRITER_H_
#define MODULES_GRAPH_WRITER_ARROW_FRAGMENT_WRITER_H_

#ifdef ENABLE_GAR

#include <algorithm>
#include <cmath>
#include <map>
#include <memory>
#include <set>
#include <sstream>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "boost/leaf/error.hpp"
#include "boost/leaf/result.hpp"

#include "grape/worker/comm_spec.h"

#include "basic/ds/arrow_utils.h"
#include "client/client.h"
#include "common/util/functions.h"
#include "io/io/i_io_adaptor.h"
#include "io/io/io_factory.h"

#include "graph/loader/fragment_loader_utils.h"
#include "graph/utils/partitioner.h"

namespace GraphArchive {
class GraphInfo;
class EdgeInfo;
class VertexInfo;
enum class AdjListType : std::uint8_t;
}  // namespace GraphArchive

namespace vineyard {

void FinishArrowArrayBuilders(
    std::vector<std::shared_ptr<arrow::ArrayBuilder>>& builders,
    std::vector<std::shared_ptr<arrow::Array>>& columns);

void ResetArrowArrayBuilders(
    std::vector<std::shared_ptr<arrow::ArrayBuilder>>& builders);

void InitializeArrayArrayBuilders(
    std::vector<std::shared_ptr<arrow::ArrayBuilder>>& builders,
    const std::set<property_graph_types::LABEL_ID_TYPE>& property_ids,
    const property_graph_types::LABEL_ID_TYPE edge_label,
    const PropertyGraphSchema& graph_schema);

std::shared_ptr<arrow::Table> AppendNullsToArrowTable(
    const std::shared_ptr<arrow::Table>& table, size_t num_rows_to_append);

template <typename FRAG_T>
class ArrowFragmentWriter {
  using oid_t = typename FRAG_T::oid_t;
  using vid_t = typename FRAG_T::vid_t;
  using eid_t = property_graph_types::EID_TYPE;
  using label_id_t = property_graph_types::LABEL_ID_TYPE;
  using vertex_range_t = typename FRAG_T::vertex_range_t;
  using internal_oid_t = typename InternalType<oid_t>::type;
  using oid_array_t = ArrowArrayType<oid_t>;
  using vid_array_t = ArrowArrayType<vid_t>;
  using vertex_map_t = typename FRAG_T::vertex_map_t;
  using oid_array_builder_t =
      typename vineyard::ConvertToArrowType<oid_t>::BuilderType;
  using nbr_t = property_graph_utils::Nbr<vid_t, eid_t>;
  using adj_list_t = typename FRAG_T::adj_list_t;

  using fragment_t = FRAG_T;

 protected:
  static constexpr const char* MARKER = "PROGRESS--GRAPH-LOADING-";

 public:
  ArrowFragmentWriter();

  /**
   * @brief Initialize ArrowFragmentWriter with graph info
   *
   * @param frag The fragment to write
   * @param comm_spec The communicator specification
   * @param graph_info_yaml The graph info yaml path
   */
  boost::leaf::result<void> Init(const std::shared_ptr<fragment_t>& frag,
                                 const grape::CommSpec& comm_spec,
                                 const std::string& graph_info_yaml);

  /**
   * @brief Initialize ArrowFragmentWriter with base graph info information
   *    The graph info will be generated from the fragment schema and the given
   *    information.
   *
   * @param frag The fragment to write
   * @param comm_spec The communicator specification
   * @param graph_name The graph name
   * @param path The path to store the fragment
   * @param vertex_block_size The vertex chunk size
   * @param edge_block_size The edge chunk size
   * @param file_type The file type to store the fragment
   * @param store_in_local Whether write the fragment to local
   */
  boost::leaf::result<void> Init(
      const std::shared_ptr<fragment_t>& frag, const grape::CommSpec& comm_spec,
      const std::string& graph_name, const std::string& out_path,
      int64_t vertex_block_size, int64_t edge_block_size,
      const std::string& file_type,
      const std::vector<std::string>& selected_vertices,
      const std::vector<std::string>& selected_edges,
      const std::unordered_map<std::string, std::vector<std::string>>&
          selected_vertex_properties,
      const std::unordered_map<std::string, std::vector<std::string>>&
          selected_edge_properties,
      bool store_in_local = false);

  ~ArrowFragmentWriter() = default;

  boost::leaf::result<void> WriteGraphInfo(const std::string& output_path);

  boost::leaf::result<void> WriteFragment();

  boost::leaf::result<void> WriteVertices();

  boost::leaf::result<void> WriteVertex(const std::string& label);

  boost::leaf::result<void> WriteEdges();

  boost::leaf::result<void> WriteEdge(const std::string& src_label,
                                      const std::string& edge_label,
                                      const std::string& dst_label);

 private:
  boost::leaf::result<void> checkInitialization();

  boost::leaf::result<void> writeEdgeImpl(
      const std::shared_ptr<GraphArchive::EdgeInfo>& edge_info,
      label_id_t src_label_id, label_id_t edge_label_id,
      label_id_t dst_label_id,
      const std::vector<int64_t>& main_start_chunk_indices,
      const std::vector<int64_t>& another_start_chunk_indices,
      const vertex_range_t& vertices, GraphArchive::AdjListType adj_list_type);

  boost::leaf::result<void> appendPropertiesToArrowArrayBuilders(
      const nbr_t& edge, const std::set<label_id_t>& property_ids,
      const label_id_t edge_label, const PropertyGraphSchema& graph_schema,
      std::vector<std::shared_ptr<arrow::ArrayBuilder>>& builders);

  boost::leaf::result<void> writeLocalVertexChunkBeginAndNum(
      const std::shared_ptr<GraphArchive::VertexInfo>& vertex_info,
      int64_t vertex_chunk_begin, int64_t vertex_chunk_num);

 private:
  std::shared_ptr<ArrowFragment<oid_t, vid_t>> frag_;
  grape::CommSpec comm_spec_;
  std::shared_ptr<GraphArchive::GraphInfo> graph_info_;
  std::map<label_id_t, int64_t> label_id_to_vnum_;

  bool store_in_local_;
};

}  // namespace vineyard

#endif  // ENABLE_GAR
#endif  // MODULES_GRAPH_WRITER_ARROW_FRAGMENT_WRITER_H_
