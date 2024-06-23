# - Config file for the vineyard package
#
# It defines the following variables
#
#  VINEYARD_INCLUDE_DIR         - include directory for vineyard
#  VINEYARD_INCLUDE_DIRS        - include directories for vineyard
#  VINEYARD_LIBRARIES           - libraries to link against
#  VINEYARDD_EXECUTABLE         - the vineyardd executable
#  VINEYARD_CODEGEN_EXECUTABLE  - the vineyard codegen executable

set(USE_ASAN @USE_ASAN@)
set(USE_LIBUNWIND @USE_LIBUNWIND@)

set(BUILD_VINEYARD_SERVER @BUILD_VINEYARD_SERVER@)
set(BUILD_VINEYARD_CLIENT @BUILD_VINEYARD_CLIENT@)
set(BUILD_VINEYARD_PYTHON_BINDINGS @BUILD_VINEYARD_PYTHON_BINDINGS@)
set(BUILD_VINEYARD_PYPI_PACKAGES @BUILD_VINEYARD_PYPI_PACKAGES@)

set(BUILD_VINEYARD_BASIC @BUILD_VINEYARD_BASIC@)
set(BUILD_VINEYARD_IO @BUILD_VINEYARD_IO@)
set(BUILD_VINEYARD_IO_KAFKA @BUILD_VINEYARD_IO_KAFKA@)
set(BUILD_VINEYARD_GRAPH @BUILD_VINEYARD_GRAPH@)
set(BUILD_VINEYARD_GRAPH_WITH_GAR @BUILD_VINEYARD_GRAPH_WITH_GAR@)
set(BUILD_VINEYARD_MALLOC @BUILD_VINEYARD_MALLOC@)
set(BUILD_VINEYARD_FUSE @BUILD_VINEYARD_FUSE@)
set(BUILD_VINEYARD_FUSE_PARQUET @BUILD_VINEYARD_FUSE_PARQUET@)
set(BUILD_VINEYARD_HOSSEINMOEIN_DATAFRAME @BUILD_VINEYARD_HOSSEINMOEIN_DATAFRAME@)

set(BUILD_VINEYARD_TESTS @BUILD_VINEYARD_TESTS@)
set(BUILD_VINEYARD_TESTS_ALL @BUILD_VINEYARD_TESTS_ALL@)
set(BUILD_VINEYARD_COVERAGE @BUILD_VINEYARD_COVERAGE@)
set(BUILD_VINEYARD_PROFILING @BUILD_VINEYARD_PROFILING@)

# find pthread
find_package(Threads)

# for finding dependencies
include(CMakeFindDependencyMacro)

# find apache-arrow
if(NOT Arrow_FOUND AND NOT TARGET arrow_shared AND NOT TARGET arrow_static)
    find_package(Arrow QUIET)
    if(NOT Arrow_FOUND)
        list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_LIST_DIR})
        find_dependency(Arrow)
    endif()
endif()

if(BUILD_VINEYARD_GRAPH)
    if(NOT TARGET grape-lite)
        find_dependency(libgrapelite)
    endif()
endif()

if(BUILD_VINEYARD_IO AND BUILD_VINEYARD_IO_KAFKA)
    list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_LIST_DIR})
    if(NOT Rdkafka_FOUND)
        find_dependency(Rdkafka)
    endif()
endif()

if(BUILD_VINEYARD_GRAPH AND BUILD_VINEYARD_GRAPH_WITH_GAR)
    if(NOT TARGET gar)
        find_dependency(gar)
    endif()
endif()

if(USE_LIBUNWIND)
    list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_LIST_DIR})
    if(NOT LIBUNWIND_LIBRARIES)
        find_package(LibUnwind QUIET)
    endif()
endif()

set(VINEYARD_HOME "${CMAKE_CURRENT_LIST_DIR}/../../..")
include("${CMAKE_CURRENT_LIST_DIR}/vineyard-targets.cmake")

set(VINEYARD_LIBRARIES @VINEYARD_INSTALL_LIBS@)
set(VINEYARD_INCLUDE_DIR "${VINEYARD_HOME}/include"
                         "${VINEYARD_HOME}/include/vineyard"
                         "${VINEYARD_HOME}/include/vineyard/contrib")
set(VINEYARD_INCLUDE_DIRS "${VINEYARD_INCLUDE_DIR}")

set(VINEYARDD_EXECUTABLE "${VINEYARD_HOME}/bin/vineyardd")

set(VINEYARD_CODEGEN_EXECUTABLE "${VINEYARD_HOME}/bin/vineyard-codegen")

include(FindPackageMessage)
find_package_message(vineyard
    "Found vineyard: ${CMAKE_CURRENT_LIST_FILE} (found version \"@VINEYARD_VERSION@\")"
    "Vineyard version: @VINEYARD_VERSION@\nVineyard libraries: ${VINEYARD_LIBRARIES}, include directories: ${VINEYARD_INCLUDE_DIRS}"
)
