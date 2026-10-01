# SPDX-License-Identifier: GPL-3.0-or-later
cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(wolfcert_est_client)

target_sources(app PRIVATE src/main.c)

if(CONFIG_WOLFCERT_SAMPLE_CA_CERT STREQUAL "")
  set(wolfcert_ca_cert "${ZEPHYR_WOLFCERT_MODULE_DIR}/examples/certs/ecc/ca-cert.pem")
else()
  get_filename_component(wolfcert_ca_cert "${CONFIG_WOLFCERT_SAMPLE_CA_CERT}"
    ABSOLUTE BASE_DIR "${CMAKE_CURRENT_SOURCE_DIR}")
endif()
if(NOT EXISTS "${wolfcert_ca_cert}" OR IS_DIRECTORY "${wolfcert_ca_cert}")
  message(FATAL_ERROR
    "trust anchor ${wolfcert_ca_cert} is not a file")
endif()

generate_inc_file_for_target(app "${wolfcert_ca_cert}"
  "${ZEPHYR_BINARY_DIR}/include/generated/est_ca_cert.inc")

# The sample sets the clock to when CMake last configured.
string(TIMESTAMP wolfcert_build_epoch "%s" UTC)
target_compile_definitions(app PRIVATE
  WOLFCERT_SAMPLE_EPOCH=${wolfcert_build_epoch})
