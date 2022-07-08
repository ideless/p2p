/// <reference types="emscripten" />
/** Above will import declarations from @types/emscripten, including Module etc. */
/** It is not .ts file but declaring reference will pass TypeScript Check. */

Module['printErr'] = function (err) {
    console.error(err)
    printCharBuffers[2].length = 0 /* flush error buffer */
    throw new Error(err) /* expose error message to JS */
}

Module['Parser'] = function () {
    /* private */
    let data_ptr = 0
    let pb_ptr = 0
    let pid_ptr = 0
    let ctx_ptr = 0
    let seeds = []
    let verbose = -1
    function xmalloc(size) {
        let ptr = _malloc(size)
        if (ptr == 0) {
            throw new Error(`failed allocation of ${size} bytes`)
        }
        return ptr
    }
    /* public */
    this.open = function (data) {
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
        _p2p_set_logger(ctx_ptr, 0, verbose)
        /* set dispatch key seeds */
        let count = seeds.length,
            arr_ptr = xmalloc(count * 4),
            seed_ptrs = seeds.map(seed => allocateUTF8(seed));
        seed_ptrs.forEach((seed_ptr, i) => {
            setValue(arr_ptr + i * 4, seed_ptr, 'i32')
        })
        _p2p_set_init_seeds(ctx_ptr, arr_ptr, count)
        seed_ptrs.forEach(seed_ptr => _free(seed_ptr))
        _free(arr_ptr)
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
    this.setInitSeeds = function (_seeds) {
        seeds = _seeds
    }
    this.decryptPacket = function () {
        let pb_size = _p2p_decrypt_packet(ctx_ptr, pb_ptr, pid_ptr)
        if (pb_size >= 0) {
            return {
                id: (new Uint16Array(HEAPU8.buffer, pid_ptr, 1))[0],
                protobuf: new Uint8Array(HEAPU8.buffer, pb_ptr, pb_size),
            }
        } else if (pb_size < -1) {
            throw new Error('fail to parse pcap file')
        }
    }
    this.setLogLevel = function (_verbose) {
        verbose = _verbose
    }
    this.parse = function (data, callback) {
        this.open(data)
        let packet
        while ((packet = this.decryptPacket())) {
            if (callback(packet, this))
                break
        }
        this.close()
    }
}