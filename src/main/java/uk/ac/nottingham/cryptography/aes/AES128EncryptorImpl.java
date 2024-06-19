package uk.ac.nottingham.cryptography.aes;

/**
 * Implementation of AES encryption.
 * <p>
 * This class provides an optimised implementation of
 * AES. This can be used within the AESGCM class as a
 * base cipher, knowledge of this class is not necessary
 * for the coursework
 * <p>
 * Do not edit this class.
 */
public class AES128EncryptorImpl implements AES128Encryptor {
    private static final byte[] S = {
            (byte)0x63, (byte)0x7C, (byte)0x77, (byte)0x7B, (byte)0xF2, (byte)0x6B, (byte)0x6F, (byte)0xC5,
            (byte)0x30, (byte)0x01, (byte)0x67, (byte)0x2B, (byte)0xFE, (byte)0xD7, (byte)0xAB, (byte)0x76,
            (byte)0xCA, (byte)0x82, (byte)0xC9, (byte)0x7D, (byte)0xFA, (byte)0x59, (byte)0x47, (byte)0xF0,
            (byte)0xAD, (byte)0xD4, (byte)0xA2, (byte)0xAF, (byte)0x9C, (byte)0xA4, (byte)0x72, (byte)0xC0,
            (byte)0xB7, (byte)0xFD, (byte)0x93, (byte)0x26, (byte)0x36, (byte)0x3F, (byte)0xF7, (byte)0xCC,
            (byte)0x34, (byte)0xA5, (byte)0xE5, (byte)0xF1, (byte)0x71, (byte)0xD8, (byte)0x31, (byte)0x15,
            (byte)0x04, (byte)0xC7, (byte)0x23, (byte)0xC3, (byte)0x18, (byte)0x96, (byte)0x05, (byte)0x9A,
            (byte)0x07, (byte)0x12, (byte)0x80, (byte)0xE2, (byte)0xEB, (byte)0x27, (byte)0xB2, (byte)0x75,
            (byte)0x09, (byte)0x83, (byte)0x2C, (byte)0x1A, (byte)0x1B, (byte)0x6E, (byte)0x5A, (byte)0xA0,
            (byte)0x52, (byte)0x3B, (byte)0xD6, (byte)0xB3, (byte)0x29, (byte)0xE3, (byte)0x2F, (byte)0x84,
            (byte)0x53, (byte)0xD1, (byte)0x00, (byte)0xED, (byte)0x20, (byte)0xFC, (byte)0xB1, (byte)0x5B,
            (byte)0x6A, (byte)0xCB, (byte)0xBE, (byte)0x39, (byte)0x4A, (byte)0x4C, (byte)0x58, (byte)0xCF,
            (byte)0xD0, (byte)0xEF, (byte)0xAA, (byte)0xFB, (byte)0x43, (byte)0x4D, (byte)0x33, (byte)0x85,
            (byte)0x45, (byte)0xF9, (byte)0x02, (byte)0x7F, (byte)0x50, (byte)0x3C, (byte)0x9F, (byte)0xA8,
            (byte)0x51, (byte)0xA3, (byte)0x40, (byte)0x8F, (byte)0x92, (byte)0x9D, (byte)0x38, (byte)0xF5,
            (byte)0xBC, (byte)0xB6, (byte)0xDA, (byte)0x21, (byte)0x10, (byte)0xFF, (byte)0xF3, (byte)0xD2,
            (byte)0xCD, (byte)0x0C, (byte)0x13, (byte)0xEC, (byte)0x5F, (byte)0x97, (byte)0x44, (byte)0x17,
            (byte)0xC4, (byte)0xA7, (byte)0x7E, (byte)0x3D, (byte)0x64, (byte)0x5D, (byte)0x19, (byte)0x73,
            (byte)0x60, (byte)0x81, (byte)0x4F, (byte)0xDC, (byte)0x22, (byte)0x2A, (byte)0x90, (byte)0x88,
            (byte)0x46, (byte)0xEE, (byte)0xB8, (byte)0x14, (byte)0xDE, (byte)0x5E, (byte)0x0B, (byte)0xDB,
            (byte)0xE0, (byte)0x32, (byte)0x3A, (byte)0x0A, (byte)0x49, (byte)0x06, (byte)0x24, (byte)0x5C,
            (byte)0xC2, (byte)0xD3, (byte)0xAC, (byte)0x62, (byte)0x91, (byte)0x95, (byte)0xE4, (byte)0x79,
            (byte)0xE7, (byte)0xC8, (byte)0x37, (byte)0x6D, (byte)0x8D, (byte)0xD5, (byte)0x4E, (byte)0xA9,
            (byte)0x6C, (byte)0x56, (byte)0xF4, (byte)0xEA, (byte)0x65, (byte)0x7A, (byte)0xAE, (byte)0x08,
            (byte)0xBA, (byte)0x78, (byte)0x25, (byte)0x2E, (byte)0x1C, (byte)0xA6, (byte)0xB4, (byte)0xC6,
            (byte)0xE8, (byte)0xDD, (byte)0x74, (byte)0x1F, (byte)0x4B, (byte)0xBD, (byte)0x8B, (byte)0x8A,
            (byte)0x70, (byte)0x3E, (byte)0xB5, (byte)0x66, (byte)0x48, (byte)0x03, (byte)0xF6, (byte)0x0E,
            (byte)0x61, (byte)0x35, (byte)0x57, (byte)0xB9, (byte)0x86, (byte)0xC1, (byte)0x1D, (byte)0x9E,
            (byte)0xE1, (byte)0xF8, (byte)0x98, (byte)0x11, (byte)0x69, (byte)0xD9, (byte)0x8E, (byte)0x94,
            (byte)0x9B, (byte)0x1E, (byte)0x87, (byte)0xE9, (byte)0xCE, (byte)0x55, (byte)0x28, (byte)0xDF,
            (byte)0x8C, (byte)0xA1, (byte)0x89, (byte)0x0D, (byte)0xBF, (byte)0xE6, (byte)0x42, (byte)0x68,
            (byte)0x41, (byte)0x99, (byte)0x2D, (byte)0x0F, (byte)0xB0, (byte)0x54, (byte)0xBB, (byte)0x16,
    };

    private static final int[] rcon = {
            0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,
            0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f };

    // Precomputed table T0
    private static final int[] T0 =
            {
                    0xa56363c6, 0x847c7cf8, 0x997777ee, 0x8d7b7bf6, 0x0df2f2ff,
                    0xbd6b6bd6, 0xb16f6fde, 0x54c5c591, 0x50303060, 0x03010102,
                    0xa96767ce, 0x7d2b2b56, 0x19fefee7, 0x62d7d7b5, 0xe6abab4d,
                    0x9a7676ec, 0x45caca8f, 0x9d82821f, 0x40c9c989, 0x877d7dfa,
                    0x15fafaef, 0xeb5959b2, 0xc947478e, 0x0bf0f0fb, 0xecadad41,
                    0x67d4d4b3, 0xfda2a25f, 0xeaafaf45, 0xbf9c9c23, 0xf7a4a453,
                    0x967272e4, 0x5bc0c09b, 0xc2b7b775, 0x1cfdfde1, 0xae93933d,
                    0x6a26264c, 0x5a36366c, 0x413f3f7e, 0x02f7f7f5, 0x4fcccc83,
                    0x5c343468, 0xf4a5a551, 0x34e5e5d1, 0x08f1f1f9, 0x937171e2,
                    0x73d8d8ab, 0x53313162, 0x3f15152a, 0x0c040408, 0x52c7c795,
                    0x65232346, 0x5ec3c39d, 0x28181830, 0xa1969637, 0x0f05050a,
                    0xb59a9a2f, 0x0907070e, 0x36121224, 0x9b80801b, 0x3de2e2df,
                    0x26ebebcd, 0x6927274e, 0xcdb2b27f, 0x9f7575ea, 0x1b090912,
                    0x9e83831d, 0x742c2c58, 0x2e1a1a34, 0x2d1b1b36, 0xb26e6edc,
                    0xee5a5ab4, 0xfba0a05b, 0xf65252a4, 0x4d3b3b76, 0x61d6d6b7,
                    0xceb3b37d, 0x7b292952, 0x3ee3e3dd, 0x712f2f5e, 0x97848413,
                    0xf55353a6, 0x68d1d1b9, 0x00000000, 0x2cededc1, 0x60202040,
                    0x1ffcfce3, 0xc8b1b179, 0xed5b5bb6, 0xbe6a6ad4, 0x46cbcb8d,
                    0xd9bebe67, 0x4b393972, 0xde4a4a94, 0xd44c4c98, 0xe85858b0,
                    0x4acfcf85, 0x6bd0d0bb, 0x2aefefc5, 0xe5aaaa4f, 0x16fbfbed,
                    0xc5434386, 0xd74d4d9a, 0x55333366, 0x94858511, 0xcf45458a,
                    0x10f9f9e9, 0x06020204, 0x817f7ffe, 0xf05050a0, 0x443c3c78,
                    0xba9f9f25, 0xe3a8a84b, 0xf35151a2, 0xfea3a35d, 0xc0404080,
                    0x8a8f8f05, 0xad92923f, 0xbc9d9d21, 0x48383870, 0x04f5f5f1,
                    0xdfbcbc63, 0xc1b6b677, 0x75dadaaf, 0x63212142, 0x30101020,
                    0x1affffe5, 0x0ef3f3fd, 0x6dd2d2bf, 0x4ccdcd81, 0x140c0c18,
                    0x35131326, 0x2fececc3, 0xe15f5fbe, 0xa2979735, 0xcc444488,
                    0x3917172e, 0x57c4c493, 0xf2a7a755, 0x827e7efc, 0x473d3d7a,
                    0xac6464c8, 0xe75d5dba, 0x2b191932, 0x957373e6, 0xa06060c0,
                    0x98818119, 0xd14f4f9e, 0x7fdcdca3, 0x66222244, 0x7e2a2a54,
                    0xab90903b, 0x8388880b, 0xca46468c, 0x29eeeec7, 0xd3b8b86b,
                    0x3c141428, 0x79dedea7, 0xe25e5ebc, 0x1d0b0b16, 0x76dbdbad,
                    0x3be0e0db, 0x56323264, 0x4e3a3a74, 0x1e0a0a14, 0xdb494992,
                    0x0a06060c, 0x6c242448, 0xe45c5cb8, 0x5dc2c29f, 0x6ed3d3bd,
                    0xefacac43, 0xa66262c4, 0xa8919139, 0xa4959531, 0x37e4e4d3,
                    0x8b7979f2, 0x32e7e7d5, 0x43c8c88b, 0x5937376e, 0xb76d6dda,
                    0x8c8d8d01, 0x64d5d5b1, 0xd24e4e9c, 0xe0a9a949, 0xb46c6cd8,
                    0xfa5656ac, 0x07f4f4f3, 0x25eaeacf, 0xaf6565ca, 0x8e7a7af4,
                    0xe9aeae47, 0x18080810, 0xd5baba6f, 0x887878f0, 0x6f25254a,
                    0x722e2e5c, 0x241c1c38, 0xf1a6a657, 0xc7b4b473, 0x51c6c697,
                    0x23e8e8cb, 0x7cdddda1, 0x9c7474e8, 0x211f1f3e, 0xdd4b4b96,
                    0xdcbdbd61, 0x868b8b0d, 0x858a8a0f, 0x907070e0, 0x423e3e7c,
                    0xc4b5b571, 0xaa6666cc, 0xd8484890, 0x05030306, 0x01f6f6f7,
                    0x120e0e1c, 0xa36161c2, 0x5f35356a, 0xf95757ae, 0xd0b9b969,
                    0x91868617, 0x58c1c199, 0x271d1d3a, 0xb99e9e27, 0x38e1e1d9,
                    0x13f8f8eb, 0xb398982b, 0x33111122, 0xbb6969d2, 0x70d9d9a9,
                    0x898e8e07, 0xa7949433, 0xb69b9b2d, 0x221e1e3c, 0x92878715,
                    0x20e9e9c9, 0x49cece87, 0xff5555aa, 0x78282850, 0x7adfdfa5,
                    0x8f8c8c03, 0xf8a1a159, 0x80898909, 0x170d0d1a, 0xdabfbf65,
                    0x31e6e6d7, 0xc6424284, 0xb86868d0, 0xc3414182, 0xb0999929,
                    0x772d2d5a, 0x110f0f1e, 0xcbb0b07b, 0xfc5454a8, 0xd6bbbb6d,
                    0x3a16162c};

    private static int rotateR(int x, int shift) {
        return (x >>> shift) | (x << 32 - shift);
    }

    private static int subWord(int x) {
        return (S[x & 255] & 255 | ((S[(x >> 8) & 255] & 255) << 8) | ((S[(x >> 16) & 255] & 255) << 16) | S[(x >> 24) & 255] << 24);
    }

    public static int bytesToInt(byte[] bs, int off)
    {
        int n = bs[off] & 0xff;
        n |= (bs[++off] & 0xff) << 8;
        n |= (bs[++off] & 0xff) << 16;
        n |= bs[++off] << 24;
        return n;
    }

    private int[][] generateRoundKeys(byte[] key) {
        int[][] keys = new int[ROUNDS + 1][4];

        int col0 = bytesToInt(key, 0);
        keys[0][0] = col0;
        int col1 = bytesToInt(key, 4);
        keys[0][1] = col1;
        int col2 = bytesToInt(key, 8);
        keys[0][2] = col2;
        int col3 = bytesToInt(key, 12);
        keys[0][3] = col3;

        for (int i = 1; i <= 10; ++i) {
            int colx = subWord(rotateR(col3, 8)) ^ rcon[i - 1];
            col0 ^= colx;
            keys[i][0] = col0;
            col1 ^= col0;
            keys[i][1] = col1;
            col2 ^= col1;
            keys[i][2] = col2;
            col3 ^= col2;
            keys[i][3] = col3;
        }

        return keys;
    }

    private final int ROUNDS = 10;
    private int[][] roundKeys = null;

    @Override
    public void init(byte[] key) {
        roundKeys = generateRoundKeys(key);
    }

    public static void intToBytes(int n, byte[] bs, int off)
    {
        bs[off] = (byte)n;
        bs[++off] = (byte)(n >>>  8);
        bs[++off] = (byte)(n >>> 16);
        bs[++off] = (byte)(n >>> 24);
    }

    @Override
    public void encryptBlock(byte[] in, byte[] out)
    {
        int t0 = bytesToInt(in, 0) ^ roundKeys[0][0];
        int t1 = bytesToInt(in, 4) ^ roundKeys[0][1];
        int t2 = bytesToInt(in, 8) ^ roundKeys[0][2];

        int r = 1, r0, r1, r2, r3 = bytesToInt(in, 12) ^ roundKeys[0][3];
        while (r < ROUNDS - 1)
        {
            r0 = T0[t0&255] ^ rotateR(T0[(t1>>8)&255], 24) ^ rotateR(T0[(t2>>16)&255], 16) ^ rotateR(T0[(r3>>24)&255], 8) ^ roundKeys[r][0];
            r1 = T0[t1&255] ^ rotateR(T0[(t2>>8)&255], 24) ^ rotateR(T0[(r3>>16)&255], 16) ^ rotateR(T0[(t0>>24)&255], 8) ^ roundKeys[r][1];
            r2 = T0[t2&255] ^ rotateR(T0[(r3>>8)&255], 24) ^ rotateR(T0[(t0>>16)&255], 16) ^ rotateR(T0[(t1>>24)&255], 8) ^ roundKeys[r][2];
            r3 = T0[r3&255] ^ rotateR(T0[(t0>>8)&255], 24) ^ rotateR(T0[(t1>>16)&255], 16) ^ rotateR(T0[(t2>>24)&255], 8) ^ roundKeys[r++][3];
            t0 = T0[r0&255] ^ rotateR(T0[(r1>>8)&255], 24) ^ rotateR(T0[(r2>>16)&255], 16) ^ rotateR(T0[(r3>>24)&255], 8) ^ roundKeys[r][0];
            t1 = T0[r1&255] ^ rotateR(T0[(r2>>8)&255], 24) ^ rotateR(T0[(r3>>16)&255], 16) ^ rotateR(T0[(r0>>24)&255], 8) ^ roundKeys[r][1];
            t2 = T0[r2&255] ^ rotateR(T0[(r3>>8)&255], 24) ^ rotateR(T0[(r0>>16)&255], 16) ^ rotateR(T0[(r1>>24)&255], 8) ^ roundKeys[r][2];
            r3 = T0[r3&255] ^ rotateR(T0[(r0>>8)&255], 24) ^ rotateR(T0[(r1>>16)&255], 16) ^ rotateR(T0[(r2>>24)&255], 8) ^ roundKeys[r++][3];
        }

        r0 = T0[t0&255] ^ rotateR(T0[(t1>>8)&255], 24) ^ rotateR(T0[(t2>>16)&255], 16) ^ rotateR(T0[(r3>>24)&255], 8) ^ roundKeys[r][0];
        r1 = T0[t1&255] ^ rotateR(T0[(t2>>8)&255], 24) ^ rotateR(T0[(r3>>16)&255], 16) ^ rotateR(T0[(t0>>24)&255], 8) ^ roundKeys[r][1];
        r2 = T0[t2&255] ^ rotateR(T0[(r3>>8)&255], 24) ^ rotateR(T0[(t0>>16)&255], 16) ^ rotateR(T0[(t1>>24)&255], 8) ^ roundKeys[r][2];
        r3 = T0[r3&255] ^ rotateR(T0[(t0>>8)&255], 24) ^ rotateR(T0[(t1>>16)&255], 16) ^ rotateR(T0[(t2>>24)&255], 8) ^ roundKeys[r++][3];

        int C0 = (S[r0&255]&255) ^ ((S[(r1>>8)&255]&255)<<8) ^ ((S[(r2>>16)&255]&255)<<16) ^ (S[(r3>>24)&255]<<24) ^ roundKeys[r][0];
        int C1 = (S[r1&255]&255) ^ ((S[(r2>>8)&255]&255)<<8) ^ ((S[(r3>>16)&255]&255)<<16) ^ (S[(r0>>24)&255]<<24) ^ roundKeys[r][1];
        int C2 = (S[r2&255]&255) ^ ((S[(r3>>8)&255]&255)<<8) ^ ((S[(r0>>16)&255]&255)<<16) ^ (S[(r1>>24)&255]<<24) ^ roundKeys[r][2];
        int C3 = (S[r3&255]&255) ^ ((S[(r0>>8)&255]&255)<<8) ^ ((S[(r1>>16)&255]&255)<<16) ^ (S[(r2>>24)&255]<<24) ^ roundKeys[r][3];

        intToBytes(C0, out, 0);
        intToBytes(C1, out, 4);
        intToBytes(C2, out, 8);
        intToBytes(C3, out, 12);
    }

}
