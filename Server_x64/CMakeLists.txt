cmake_minimum_required(VERSION 3.12)
project(Server VERSION 1.0)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find OpenSSL
find_package(OpenSSL REQUIRED)

# Find Boost
find_package(Boost REQUIRED)

file(GLOB_RECURSE SOURCES "src/*.cpp")
file(GLOB_RECURSE HEADERS "src/*.hpp")

# Add executable
add_library(Server STATIC ${SOURCES} ${HEADERS})

# Include OpenSSL
target_include_directories(Server PRIVATE ${OpenSSL_INCLUDE_DIR})

# Link OpenSSL libraries
target_link_libraries(Server PRIVATE ${OpenSSL_LIBRARIES})

# Include Boost
target_include_directories(Server PRIVATE ${Boost_INCLUDE_DIR})

# Link Boost libraries
target_link_libraries(Server PRIVATE ${Boost_LIBRARIES})