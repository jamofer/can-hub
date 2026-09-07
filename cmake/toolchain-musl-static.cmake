# Cross toolchain for the fully static musl builds (bootlin toolchains).
# The cross triplet and target processor come from the environment:
# CAN_HUB_CROSS_TRIPLET and CAN_HUB_PROCESSOR (see docker/static.Dockerfile).
# There is no staging sysroot any more: every dependency is built from source
# into the build tree.

set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR $ENV{CAN_HUB_PROCESSOR})

set(CMAKE_C_COMPILER $ENV{CAN_HUB_CROSS_TRIPLET}-gcc)
set(CMAKE_CXX_COMPILER $ENV{CAN_HUB_CROSS_TRIPLET}-g++)

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
