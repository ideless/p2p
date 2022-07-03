import Avatar from './GenshinData/ExcelBinOutput/AvatarExcelConfigData.json'
import TextMap from './GenshinData/TextMap/TextMapEN.json'
import { toKey } from './utils'
import fs from 'node:fs'

let A: any = {}

Avatar.forEach((a: any) => {
    A[a.id] = toKey((TextMap as any)[a.nameTextMapHash])
})

fs.writeFileSync('./dumps/Avatar.json', JSON.stringify(A))