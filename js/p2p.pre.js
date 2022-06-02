/// <reference types="emscripten" />
/** Above will import declarations from @types/emscripten, including Module etc. */
/** It is not .ts file but declaring reference will pass TypeScript Check. */

Module['Parser'] = function () {
    /* private */
    let data_ptr = 0
    let pb_ptr = 0
    let pid_ptr = 0
    let ctx_ptr = 0
    function xmalloc(size) {
        let ptr = _malloc(size)
        if (ptr == 0) {
            throw new Error(`Failed allocation of ${size} bytes`)
        }
        return ptr
    }
    /* public */
    this.open = function (data, verbose = -1) {
        /* make sure heap is clear */
        this.close()
        /* malloc */
        data_ptr = xmalloc(data.length)
        pb_ptr = xmalloc(data.length)
        pid_ptr = xmalloc(2)
        /* open */
        HEAPU8.set(data, data_ptr)
        ctx_ptr = _p2p_open(data_ptr, data.length)
        if (ctx_ptr == 0) {
            throw new Error('fail to open pcap file')
        }
        /* verbose */
        _p2p_set_logger(ctx_ptr, _stdout, verbose)
    }
    this.close = function () {
        _free(data_ptr)
        _free(pb_ptr)
        _free(pid_ptr)
        if (ctx_ptr) {
            _p2p_close(ctx_ptr)
        }
        /* avoid close twice bug */
        data_ptr = 0
        pb_ptr = 0
        pid_ptr = 0
        ctx_ptr = 0
    }
    this.setKeySeed = function (seed) {
        let seed_ptr = allocateUTF8(seed)
        _p2p_set_key_seed(ctx_ptr, seed_ptr)
        _free(seed_ptr)
    }
    this.decryptPacket = function () {
        let pb_size = _p2p_decrypt_packet(ctx_ptr, pb_ptr, pid_ptr)
        if (pb_size >= 0) {
            return {
                id: (new Uint16Array(HEAPU8.buffer, pid_ptr, 1))[0],
                protobuf: new Uint8Array(HEAPU8.buffer, pb_ptr, pb_size),
            }
        }
    }
    this.parse = function (data, callback, verbose = -1) {
        this.open(data, verbose)
        let packet
        while ((packet = this.decryptPacket())) {
            callback(packet, this)
        }
        this.close()
    }
}