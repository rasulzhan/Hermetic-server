cmake_minimum_required(VERSION 3.10)

project(DrwinUploader C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17 -lcurl")
set(CURL_LIBRARY "-lcurl")
set(CURL_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/libs/curl-linux/include")
find_package(CURL REQUIRED)
include_directories(${CURL_INCLUDE_DIR})

string(TOLOWER "${CMAKE_SYSTEM_NAME}" system_name_lower)
message("Target system: ${system_name_lower}")

add_compile_options(
    -DGLEW_STATIC
    -DIMGUI_DEFINE_MATH_OPERATORS
    -DSDL_MAIN_HANDLED
    -Wpedantic
    # -Wall
#     -Wextra
#     -Wabi
    -g # delete on release
    )

add_definitions(
    -DIMGUI_IMPL_OPENGL_LOADER_GLEW
)

set(crypto_src
    libs/Codecrypt/src/algos_enc.cpp
    libs/Codecrypt/src/algo_suite.cpp
    libs/Codecrypt/src/algos_sig.cpp
    libs/Codecrypt/src/base64.cpp
    libs/Codecrypt/src/bvector.cpp
    libs/Codecrypt/src/chacha.cpp
    libs/Codecrypt/src/envelope.cpp
    libs/Codecrypt/src/fmtseq.cpp
    libs/Codecrypt/src/generator.cpp
    libs/Codecrypt/src/gf2m.cpp
    libs/Codecrypt/src/hash.cpp
    libs/Codecrypt/src/hashfile.cpp
    libs/Codecrypt/src/iohelpers.cpp
    libs/Codecrypt/src/ios.cpp
    libs/Codecrypt/src/keyring.cpp
    libs/Codecrypt/src/matrix.cpp
    libs/Codecrypt/src/mce_qcmdpc.cpp
    libs/Codecrypt/src/message.cpp
    libs/Codecrypt/src/permutation.cpp
    libs/Codecrypt/src/polynomial.cpp
    libs/Codecrypt/src/privfile.cpp
    libs/Codecrypt/src/pwrng.cpp
    libs/Codecrypt/src/sc.cpp
    libs/Codecrypt/src/seclock.cpp
    libs/Codecrypt/src/sencode.cpp
    libs/Codecrypt/src/serialization.cpp
    libs/Codecrypt/src/str_match.cpp
    libs/Codecrypt/src/symkey.cpp
    libs/Codecrypt/src/xsynd.cpp
    libs/Codecrypt/src/fft.cpp
)

set(imgui_sources
    libs/imgui/imgui.cpp
    libs/imgui/imgui_draw.cpp
    libs/imgui/imgui_demo.cpp
    libs/imgui/imgui_tables.cpp
    libs/imgui/imgui_widgets.cpp
    libs/imgui/backend/imgui_impl_opengl3.cpp
    libs/imgui/backend/imgui_impl_glfw.cpp
)

MESSAGE(${crypto_src})

set(glew_sources
	libs/glew/src/glew.c
)

set(server_main_sources
    src_server/main.cpp
    src_server/file_list.cpp
    src_server/ws/WebsocketServer.cpp
    src_server/client/client_copy.h
    src_server/client/client_copy.cpp
    src_server/additional/common_server.h
    common/WLoger/Source/WLoger.cpp
    common/fileSys.cpp
    common/json_worker.cpp
    common/common.h
    common/enc_dec_AES.h)

set(main_sources
    main.cpp
    src_client/uploader.cpp
    src_client/ui.cpp
    src_client/cryptographer.cpp
    src_client/settings.cpp
    src_client/popup_message.cpp
    src_client/mac_address.cpp
    src_client/ws/WebsocketClient.cpp
    common/WLoger/Source/WLoger.cpp
    common/json_worker.cpp
    common/fileSys.cpp
    common/mdump.cpp
    src_client/SettingsManager.cpp src_client/SettingsManager.h)

add_library(ffs STATIC
    libs/ffs/src/bitmap.c
    libs/ffs/src/disk.c
    libs/ffs/src/ffs_operations.c
    # libs/ffs/src/mkfs.c
    libs/ffs/src/tree.c
)

target_compile_definitions(ffs PRIVATE
    _FILE_OFFSET_BITS=64
    FUSE_USE_VERSION=22
)

target_link_libraries(ffs PRIVATE
    fuse)

target_include_directories(ffs PRIVATE
    libs/ffs/include
)
target_include_directories(ffs INTERFACE
    libs/ffs/include
)

add_executable(ffs_test ffs_test.cpp)
target_compile_definitions(ffs_test PRIVATE
    _FILE_OFFSET_BITS=64
    FUSE_USE_VERSION=22
)
target_link_libraries(ffs_test PRIVATE ffs)

if (UNIX)

    message("Unix!!!!!!!!!!!!!!!!!!!!!!!")
    set_source_files_properties(libs/glew/src/glew.c PROPERTIES LANGUAGE CXX)

    #TODO(Sedenkov): change to add subdir with CMakeLists.txt
    add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/libs/fftw3)

    add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/sftp)
    add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/libs/nativefiledialog)

    set_source_files_properties(${main_sources} PROPERTIES COMPILE_OPTIONS  "-Wall;-Wextra;")
    include_directories(
        libs/boost/bind/include
        libs/boost/config/include
        libs/boost/core/include
        libs/imgui
        libs/glew-2.1.0/include
        libs/glfw-3.3.5/include
        libs/asio-1.12.2/include
        libs/websocketpp
        libs/rapidjson/include
    )

    set_source_files_properties(${server_main_sources} PROPERTIES COMPILE_OPTIONS  "-Wall;-Wextra;")

    find_library(HAVE_BSDREADPASSPHRASE bsd)
    if (HAVE_BSDREADPASSPHRASE)
        add_definitions(-DHAVE_BSDREADPASSPHRASE=1)
    else()
        message(FATAL_ERROR "libbsd missing, you can install libbsd-dev package!")
    endif()

    add_executable(server ${server_main_sources} ${crypto_src})

    target_include_directories(server PRIVATE
            ./
            libs/curl/include
            libs/curl/include/curl
            libs
            libs/websocketpp
            libs/asio-1.12.2/include
            libs/rapidjson/include
            libs/boost/bind/include
            libs/boost/core/include
            libs/boost/config/include
            libs/Codecrypt/src
            libs/fftw3/api
            )

    target_compile_features(server PRIVATE cxx_std_17)
    target_compile_definitions(server PRIVATE
        _FILE_OFFSET_BITS=64
        FUSE_USE_VERSION=22
    )

    target_link_libraries(server curl crypto pthread fftw3 gmp bsd ffs GL GLU m sftp)

    target_link_options(server PRIVATE)

endif (UNIX)

if(WIN32)

message("WINDOWS!!!!!!!!!!!!!!!!!!!!!!!")
    set_source_files_properties(libs/glew/src/glew.c PROPERTIES LANGUAGE CXX)

    #TODO(Sedenkov): change to add subdir with CMakeLists.txt


    set_source_files_properties(${main_sources} PROPERTIES COMPILE_OPTIONS  "-Wall;-Wextra;")

    add_executable(Hermetics
                    ${main_sources}
                    ${imgui_sources}
                    ${glew_sources}
                    ${crypto_src}

    )

    include_directories(
        libs/glfw
        libs/glew-2.1.0/lib/Release/x64
        libs/glfw-3.3.5/lib-mingw-w64
        libs/asio-1.12.2/include
        libs
        libs/websocketpp
        libs/rapidjson/include
    )

    target_include_directories(Hermetics PRIVATE
        ./
        src_client/
        libs/
        libs/imgui
        libs/glfw-3.3.5/include
        libs/imgui/backend
        libs/glew/include
        libs/nativefiledialog
        libs/asio-1.12.2/include
        libs/websocketpp
        libs/boost/bind/include
        libs/Codecrypt/src
        libs/fftw3/api
    )

    target_link_directories(Hermetics PRIVATE
        libs/glfw
        libs/glew-2.1.0/lib/Release/x64
        libs/glfw-3.3.5/lib-mingw-w64
        )

    add_subdirectory(sftp ${BINARY_DIR}/sftp)
    add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/libs/nativefiledialog)
    add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/libs/fftw3)

    target_link_libraries(Hermetics PRIVATE sftp mingw32 curl opengl32 shell32 nfd gdi32 glfw3 fftw3 gmp iphlpapi)

    target_link_options(Hermetics PRIVATE -mwindows)


    set_source_files_properties(${server_main_sources} PROPERTIES COMPILE_OPTIONS  "-Wall;-Wextra;")

    add_executable(server ${server_main_sources} ${crypto_src})

    target_include_directories(server PRIVATE
            ./
            libs
            libs/websocketpp
            libs/asio-1.12.2/include
            libs/rapidjson/include
            libs/boost/bind/include
            libs/Codecrypt/src
            libs/fftw3/api
            )

    target_link_libraries(server sftp mingw32 curl opengl32 shell32 fftw3 gmp)

endif(WIN32)

add_executable(encryption_test
    encryption_test.cpp
)
add_executable(p_encryption_test
    parallel_encryption_test.cpp
)

target_include_directories(encryption_test PRIVATE
    ./
    common/
    src_client/
    libs/
    libs/imgui
    libs/glfw-3.3.5/include
    libs/imgui/backend
    libs/glew/include
    libs/nativefiledialog
    libs/asio-1.12.2/include
    libs/websocketpp
    libs/boost/bind/include
    libs/Codecrypt/src
    libs/fftw3/api
)

target_include_directories(p_encryption_test PRIVATE
    ./
    common/
    src_client/
    libs/
    libs/imgui
    libs/glfw-3.3.5/include
    libs/imgui/backend
    libs/glew/include
    libs/nativefiledialog
    libs/asio-1.12.2/include
    libs/websocketpp
    libs/boost/bind/include
    libs/Codecrypt/src
    libs/fftw3/api
)

target_link_libraries(encryption_test PRIVATE
crypto
fftw3
gmp
)
target_compile_options(encryption_test PRIVATE
-Wall
-Wextra
-O1
)

target_link_libraries(p_encryption_test PRIVATE
crypto
fftw3
gmp
)
target_compile_options(p_encryption_test PRIVATE
-Wall
-Wextra
)
