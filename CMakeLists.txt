cmake_minimum_required(VERSION 3.0)

project(p2p LANGUAGES C)

set(CMAKE_C_STANDARD 11)

include_directories(src)

if(NOT_WASM)
    add_executable(p2p
        src/kcp/ikcp.h
        src/kcp/ikcp.c
        src/pcap.h
        src/pcap.c
        src/mt19937-64.h
        src/mt19937-64.c
        src/p2p.h
        src/p2p.c
        src/yskey.h
        test/test-p2p.c
    )
else()
    set(CMAKE_EXECUTABLE_SUFFIX ".js")
    add_executable(p2p
        src/kcp/ikcp.h
        src/kcp/ikcp.c
        src/pcap.h
        src/pcap.c
        src/mt19937-64.h
        src/mt19937-64.c
        src/p2p.h
        src/p2p.c
        src/yskey.h
    )
    set_target_properties(p2p PROPERTIES LINK_FLAGS "\
        --no-entry\
        --closure 1\
        -O3\
        -s EXPORT_ES6=1\
        -s MODULARIZE=1\
        -s ALLOW_MEMORY_GROWTH=1\
        -s EXPORTED_FUNCTIONS=\"[\
            '_malloc',\
            '_free',\
            '_p2p_open',\
            '_p2p_close',\
            '_p2p_set_key_seed',\
            '_p2p_decrypt_packet'\
        ]\"\
        -s EXPORTED_RUNTIME_METHODS=cwrap\
    ")
endif()
