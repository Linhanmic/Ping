cmake_minimum_required(VERSION 3.10)

# 项目名称和版本
project(PingProject VERSION 1.0)

# 设置 C++ 标准
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# 添加可执行文件
add_executable(ping main.cpp Ping.cpp)

# 包含头文件目录
target_include_directories(ping PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

# 链接 pthread 库
find_package(Threads REQUIRED)
target_link_libraries(ping PRIVATE Threads::Threads)
