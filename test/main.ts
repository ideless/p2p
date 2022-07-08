import Module from './p2p'
import protobuf from 'protobufjs'
import fs from 'node:fs'
import cmdIds from './cmdIds'

async function loadProto(name: string) {
    let root = await protobuf.load(`./proto/${name}.proto`)
    return root.lookupType(name)
}

Module().then(async (p2p) => {
    let parser = new p2p.Parser()

    parser.setLogLevel(1)
    parser.setInitSeeds(['5030560303351918544'])

    let GetPlayerTokenRsp = await loadProto('GetPlayerTokenRsp')
    let PlayerStoreNotify = await loadProto('PlayerStoreNotify')
    let AvatarDataNotify = await loadProto('AvatarDataNotify')

    let d: any = {}
    Object.entries(cmdIds).forEach(([key, val]) => d[val as any] = key)

    let data = fs.readFileSync('./example.pcap')
    let ids: number[] = []

    parser.parse(data, (pkt, ctx) => {
        if (d[pkt.id] == 'GetPlayerTokenRsp') {
            let msg = GetPlayerTokenRsp.decode(pkt.protobuf) as any
            let seed = msg.secretKeySeed.toString()
            parser.setKeySeed(seed)
            fs.writeFileSync('./dumps/GetPlayerTokenRsp.json', JSON.stringify(msg))
        } else if (d[pkt.id] == 'PlayerStoreNotify') {
            let msg = PlayerStoreNotify.decode(pkt.protobuf) as any
            fs.writeFileSync('./dumps/PlayerStoreNotify.json', JSON.stringify(msg))
        } else if (d[pkt.id] == 'AvatarDataNotify') {
            let msg = AvatarDataNotify.decode(pkt.protobuf)
            fs.writeFileSync('./dumps/AvatarDataNotify.json', JSON.stringify(msg))
        }
        ids.push(pkt.id)
    })

    fs.writeFileSync('./dumps/packets.txt', ids.map(id => id.toString().padEnd(5, ' ') + ' ' + d[id]).join('\n'))
})
