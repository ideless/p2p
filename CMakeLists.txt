cmake_minimum_required(VERSION 3.0)

project(p2p LANGUAGES C)

set(CMAKE_C_STANDARD 11)
include_directories(src)

set(CSOURCES
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

if(NOT_WASM)
    add_executable(p2p
        ${CSOURCES}
        test/test-p2p.c
    )
else()
    set(CMAKE_EXECUTABLE_SUFFIX ".js")
    if(NOT DEFINED VITE)
        set(VITE 0)
    endif()
    message("VITE ${VITE}")
    add_executable(p2p
        ${CSOURCES}
    )
    set_target_properties(p2p PROPERTIES LINK_FLAGS "\
        --no-entry\
        -O3\
        --minify 0\
        -s MODULARIZE=1\
        -s EXPORT_ES6=1\
        -s USE_ES6_IMPORT_META=${VITE}\
        -s ALLOW_MEMORY_GROWTH=1\
        -s EXPORTED_FUNCTIONS=\"[\
            '_malloc',\
            '_free',\
            '_stdout',\
            '_p2p_open',\
            '_p2p_close',\
            '_p2p_set_key_seed',\
            '_p2p_decrypt_packet',\
            '_p2p_set_logger'\
        ]\"\
        --pre-js ../js/p2p.pre.js\
    ")
endif()
