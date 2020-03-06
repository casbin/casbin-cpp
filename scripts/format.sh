#!/bin/bash

clang-format -i "${MESON_SOURCE_ROOT}"/lib/*.cc
clang-format -i "${MESON_SOURCE_ROOT}"/include/*.h