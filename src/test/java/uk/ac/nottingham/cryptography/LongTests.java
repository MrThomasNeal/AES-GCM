package uk.ac.nottingham.cryptography;

import org.junit.jupiter.api.*;

import java.util.ServiceLoader;

import static org.junit.jupiter.api.Assertions.assertEquals;

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class LongTests {

    private final AEADCipher cipher = ServiceLoader.load(AEADCipher.class).findFirst().orElseThrow();

    @BeforeAll
    void BurnIn() {
        String key = "edb58228747d04cac313aac2f6c79bf6";
        String iv = "e78bef52e1bec517c59e575d";
        String aad = "10161fc44781ff120b1fc2f1c4e46bd2";

        byte[] block = new byte[16];

        cipher.init(new AEADParams(HexUtils.hexToBytes(key), HexUtils.hexToBytes(iv), CipherMode.ENCRYPT));
        cipher.updateAAD(HexUtils.hexToBytes(aad));

        for (int i = 0; i < 64; i++) {
            cipher.processBlock(block);
        }
    }

    @Test
    @Order(1)
    void Encrypt10KBTest() {
        String key = "71ef2a8d0da6a5bbaf7bb2ed4ea81f44";
        String iv = "9cd49e8e6b525c6964e3e959";
        String aad = "0525d3a74e23aa9a02c9f0c901b263b8";
        String ct = "7b8aa03d91b7c6435f71cb2f4ce7303a";
        String tag = "c484aca9f3808743cc586c77f89e8dbe";

        byte[] tagbytes = new byte[16];
        byte[] block = new byte[16];

        cipher.init(new AEADParams(HexUtils.hexToBytes(key), HexUtils.hexToBytes(iv), CipherMode.ENCRYPT));
        cipher.updateAAD(HexUtils.hexToBytes(aad));

        for (int i = 0; i < 640; i++) {
            cipher.processBlock(block);
        }

        cipher.finalise(tagbytes);

        assertEquals(ct, HexUtils.bytesToHex(block));
        assertEquals(tag, HexUtils.bytesToHex(tagbytes));
    }

    @Test
    @Order(2)
    void Encrypt100KBTest() {
        String key = "6d953457b660ea50ea7bfe9f24bb4b3a";
        String iv = "52069c72f9acef27f3da19dd";
        String aad = "764646e27aa29c29bf69e6ae09902674";
        String ct = "9e5c31877e8b0f08fcc889da923544df";
        String tag = "7bbe88f130604892f7dba0b9adb66982";

        byte[] tagbytes = new byte[16];
        byte[] block = new byte[16];

        cipher.init(new AEADParams(HexUtils.hexToBytes(key), HexUtils.hexToBytes(iv), CipherMode.ENCRYPT));
        cipher.updateAAD(HexUtils.hexToBytes(aad));

        for (int i = 0; i < 6400; i++) {
            cipher.processBlock(block);
        }

        cipher.finalise(tagbytes);

        assertEquals(ct, HexUtils.bytesToHex(block));
        assertEquals(tag, HexUtils.bytesToHex(tagbytes));
    }

    @Test
    @Order(3)
    void Encrypt1MBTest() {
        String key = "0a90afd214fa6b6cf59606e7f566138a";
        String iv = "bca4b4df1d16571c576070a2";
        String aad = "a1cc17dfbda5a748459d8969a94fe274";
        String ct = "57ee0236107f93caedcde8f6c1e30259";
        String tag = "a5782c6a7602636a442d1f46aa9491cd";

        byte[] tagbytes = new byte[16];
        byte[] block = new byte[16];

        cipher.init(new AEADParams(HexUtils.hexToBytes(key), HexUtils.hexToBytes(iv), CipherMode.ENCRYPT));
        cipher.updateAAD(HexUtils.hexToBytes(aad));

        for (int i = 0; i < 64000; i++) {
            cipher.processBlock(block);
        }

        cipher.finalise(tagbytes);

        assertEquals(ct, HexUtils.bytesToHex(block));
        assertEquals(tag, HexUtils.bytesToHex(tagbytes));
    }
}

