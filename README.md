# P2P

Yuanshen **P**cap **T**o **P**rotobuf wasm parser.

# Build

Make sure you have [emsdk](https://emscripten.org/docs/getting_started/downloads.html) and [cmake](https://cmake.org/download/) installed.

Create a build folder, for example `./build`.

```sh
cd build
emcmake cmake ..
emmake make
```

# Usage

> If you use Vite and compile p2p with flag `-O2` or `-O3`, it seems that you
have to manually "beautify" the compiled p2p.js (for example on
https://beautifier.io/), otherwise p2p wouldn't work as expected when you build
your Vite project. I assume it is a bug of Vite.

```ts
/* say you have compiled p2p.js & p2p.wasm */
import Module from "./p2p"

/* use protobufjs to decode protobuf on JS side */
import protobuf from "protobufjs"
import Long from "long"
protobuf.util.Long = Long
protobuf.configure()

Module().then((p2p: any) => {
    /* register the C methods you need into JS */
    const p2p_open = p2p.cwrap(
        'p2p_open',
        'number',
        ['number', 'number']
    )
    const p2p_close = p2p.cwrap(
        'p2p_close',
        null,
        ['number']
    )
    const p2p_set_key_seed = p2p.cwrap(
        'p2p_set_key_seed',
        null,
        ['number', 'string']
    )
    const p2p_decrypt_packet = p2p.cwrap(
        'p2p_decrypt_packet',
        'number',
        ['number', 'number', 'number']
    )

    /* example: parse player store from pcap to JS object */
    const data = new Uint8Array(/* pcap file data */)
    const data_len = data.length

    p2p.HEAPU8.set(data, data_ptr)
    let p2p_ctx_ptr = p2p_open(data_ptr, data_len) /* check NULL */

    const data_ptr = p2p._malloc(data_len)
    const protobuf_ptr = p2p._malloc(data_len)
    const packetid_ptr = p2p._malloc(2)
    while (true) {
        let protobuf_size = p2p_decrypt_packet(p2p_ctx_ptr,
            protobuf_ptr, packetid_ptr) /* check size, -1: end, -2: err */
        let packetid = (new Uint16Array(p2p.HEAPU8.buffer, packetid_ptr, 2))[0]
        if (packetid == 133) {
            let root = await protobuf.load('./proto/GetPlayerTokenRsp.proto')
            let GetPlayerTokenRsp = root.lookup('GetPlayerTokenRsp') as any
            let msg = GetPlayerTokenRsp.decode(new Uint8Array(p2p.HEAPU8.buffer, protobuf_ptr, protobuf_size))
            p2p_set_key_seed(p2p_ctx_ptr, msg.secretKeySeed.toString())
        } else if (packetid == 660) {
            let root = await protobuf.load('./proto/PlayerStoreNotify.proto')
            let PlayerStoreNotify = root.lookup('PlayerStoreNotify') as any
            let msg = PlayerStoreNotify.decode(new Uint8Array(p2p.HEAPU8.buffer, protobuf_ptr, protobuf_size))
            msg = PlayerStoreNotify.toObject(msg, {
                longs: String,
                enums: String,
                bytes: String,
            })
            console.log(msg) /* This is the data we want */
            break;
        }
    }
    p2p._free(data_ptr)
    p2p._free(protobuf_ptr)
    p2p._free(packetid_ptr)

    p2p_close(p2p_ctx_ptr)
})
```

# Credit

* Iridium