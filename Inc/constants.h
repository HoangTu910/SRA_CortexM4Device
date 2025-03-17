#ifndef CONSTANTS_H_
#define CONSTANTS_H_

#include <stdint.h>

#define ASCON_80PQ_VARIANT 0
#define ASCON_AEAD_VARIANT 1
#define ASCON_HASH_VARIANT 2
#define ASCON_XOF_VARIANT 3
#define ASCON_CXOF_VARIANT 4
#define ASCON_MAC_VARIANT 5
#define ASCON_PRF_VARIANT 6
#define ASCON_PRFS_VARIANT 7

#define ASCON_ASSOCIATED_DATA "DeslabAIoT0x910"

#define ASCON_TAG_SIZE 16
#define ASCON_HASH_SIZE 32
#define ASCON_NONCE_SIZE 16
#define ASCON_KEY_SIZE 16

#define ASCON_128_RATE 8
#define ASCON_128A_RATE 16
#define ASCON_HASH_RATE 8
#define ASCON_PRF_IN_RATE 32
#define ASCON_PRFA_IN_RATE 40
#define ASCON_PRF_OUT_RATE 16

#define ASCON_PA_ROUNDS 12
#define ASCON_128_PB_ROUNDS 6
#define ASCON_128A_PB_ROUNDS 8
#define ASCON_HASH_PB_ROUNDS 12
#define ASCON_HASHA_PB_ROUNDS 8
#define ASCON_PRF_PB_ROUNDS 12
#define ASCON_PRFA_PB_ROUNDS 8

#define ASCON_128_IV 0x00000800806c0001ull
#define ASCON_128A_IV 0x00001000808c0001ull
#define ASCON_80PQ_IV 0x00000000806c0800ull

#define ASCON_HASH_IV 0x0000080100cc0002ull
#define ASCON_HASHA_IV 0x00000801008c0002ull
#define ASCON_XOF_IV 0x0000080000cc0003ull
#define ASCON_XOFA_IV 0x00000800008c0003ull
#define ASCON_CXOF_IV 0x0000080000cc0004ull
#define ASCON_CXOFA_IV 0x00000800008c0004ull

#define ASCON_MAC_IV 0x0010200080cc0005ull
#define ASCON_MACA_IV 0x00102800808c0005ull
#define ASCON_PRF_IV 0x0010200000cc0006ull
#define ASCON_PRFA_IV 0x00102800008c0006ull
#define ASCON_PRFS_IV 0x00000000800c0007ull

#define ASCON_HASH_IV0 0x9b1e5494e934d681ull
#define ASCON_HASH_IV1 0x4bc3a01e333751d2ull
#define ASCON_HASH_IV2 0xae65396c6b34b81aull
#define ASCON_HASH_IV3 0x3c7fd4a4d56a4db3ull
#define ASCON_HASH_IV4 0x1a5c464906c5976dull

#define ASCON_HASHA_IV0 0xe2ffb4d17ffcadc5ull
#define ASCON_HASHA_IV1 0xdd364b655fa88cebull
#define ASCON_HASHA_IV2 0xdcaabe85a70319d2ull
#define ASCON_HASHA_IV3 0xd98f049404be3214ull
#define ASCON_HASHA_IV4 0xca8c9d516e8a2221ull

#define ASCON_XOF_IV0 0xda82ce768d9447ebull
#define ASCON_XOF_IV1 0xcc7ce6c75f1ef969ull
#define ASCON_XOF_IV2 0xe7508fd780085631ull
#define ASCON_XOF_IV3 0x0ee0ea53416b58ccull
#define ASCON_XOF_IV4 0xe0547524db6f0bdeull

#define ASCON_XOFA_IV0 0xf3040e5017d92943ull
#define ASCON_XOFA_IV1 0xc474f6e3ae01892eull
#define ASCON_XOFA_IV2 0xbf5cb3ca954805e0ull
#define ASCON_XOFA_IV3 0xd9c28702ccf962efull
#define ASCON_XOFA_IV4 0x5923fa01f4b0e72full

#define RC0 0xf0
#define RC1 0xe1
#define RC2 0xd2
#define RC3 0xc3
#define RC4 0xb4
#define RC5 0xa5
#define RC6 0x96
#define RC7 0x87
#define RC8 0x78
#define RC9 0x69
#define RCa 0x5a
#define RCb 0x4b

#define RC(i) (i)

#define START(n) ((3 + (n)) << 4 | (12 - (n)))
#define INC -0x0f
#define END 0x3c

enum AsconMagicNumber
{
    ASCON_ASSOCIATED_DATALENGTH = 16,
};

#endif /* CONSTANTS_H_ */
