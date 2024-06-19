package uk.ac.nottingham.cryptography;

import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestMethodOrder;

import java.util.ServiceLoader;

import static org.junit.jupiter.api.Assertions.assertEquals;

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class AADTests {
    private final AEADCipher cipher = ServiceLoader.load(AEADCipher.class).findFirst().orElseThrow();

    @Test
    void SingleBlockAADTestOne() {
        String key = "5b9604fe14eadba931b0ccf34843dab9";
        String iv = "921d2507fa8007b7bd067d34";
        String aad = "00112233445566778899aabbccddeeff";
        String tag = "493f52b4beec7506a3054287613b86e8";

        byte[] tagbytes = new byte[16];

        cipher.init(new AEADParams(HexUtils.hexToBytes(key), HexUtils.hexToBytes(iv), CipherMode.ENCRYPT));
        cipher.updateAAD(HexUtils.hexToBytes(aad));
        cipher.finalise(tagbytes);
        assertEquals(tag, HexUtils.bytesToHex(tagbytes));
    }

    @Test
    void SingleBlockAADTestTwo() {
        String key = "fe89772254c5da4b02aea6bfbe92ecc0";
        String iv = "711406731205a0194affd574";
        String aad = "0480f0265a3744012ab5f2fe1ba00486";
        String tag = "0a4e9e85b175422967344508a7e59486";
        byte[] tagbytes = new byte[16];

        cipher.init(new AEADParams(HexUtils.hexToBytes(key), HexUtils.hexToBytes(iv), CipherMode.ENCRYPT));
        cipher.updateAAD(HexUtils.hexToBytes(aad));
        cipher.finalise(tagbytes);
        assertEquals(tag, HexUtils.bytesToHex(tagbytes));
    }

    @Test
    void PartialBlockAADTestOne() {
        String key = "4623c64ba434359535c90961ae404b9c";
        String iv = "4eacc1688cd5c06b77f52d03";
        String aad = "1cbe8303e54384440d9cf1";
        String tag = "e311e8553f1be424231c492588633ef9";
        byte[] tagbytes = new byte[16];

        cipher.init(new AEADParams(HexUtils.hexToBytes(key), HexUtils.hexToBytes(iv), CipherMode.ENCRYPT));
        cipher.updateAAD(HexUtils.hexToBytes(aad));
        cipher.finalise(tagbytes);
        assertEquals(tag, HexUtils.bytesToHex(tagbytes));
    }

    @Test
    void PartialBlockAADTestTwo() {
        String key = "ed9f3e0e25dfe2376a8c5a09667d54bc";
        String iv = "9a6a3166a53ec66b7d323d3a";
        String aad = "e0003153";
        String tag = "952850e9cf1271cacc44ef0cbfa0a330";

        byte[] tagbytes = new byte[16];

        cipher.init(new AEADParams(HexUtils.hexToBytes(key), HexUtils.hexToBytes(iv), CipherMode.ENCRYPT));
        cipher.updateAAD(HexUtils.hexToBytes(aad));
        cipher.finalise(tagbytes);
        assertEquals(tag, HexUtils.bytesToHex(tagbytes));
    }

    @Test
    void MultiBlockAADTestOne() {
        String key = "91f6c11f6881690d1e24039914c5e215";
        String iv = "16bffb0582eae81de537424a";
        String aad = "22b0e7a9910d08b76fac3d0402790197216a10c6d9aae0c9b51acbed108dbc9e";
        String tag = "fe66683f69f4f784c3b113b8b037d081";
        byte[] tagbytes = new byte[16];

        cipher.init(new AEADParams(HexUtils.hexToBytes(key), HexUtils.hexToBytes(iv), CipherMode.ENCRYPT));
        cipher.updateAAD(HexUtils.hexToBytes(aad.substring(0,32)));
        cipher.updateAAD(HexUtils.hexToBytes(aad.substring(32,64)));
        cipher.finalise(tagbytes);
        assertEquals(tag, HexUtils.bytesToHex(tagbytes));
    }

    @Test
    void MultiBlockAADTestTwo() {
        String key = "6c0ad7e38cb6f3a64b173ce65997329f";
        String iv = "d8ba277ae0594c8b941c852a";
        String aad = "a9556e501df4e46b18662feded87f767379c148674f41c93f64bb2a791ab81e6aa7980480f09b907143e4e1e16cd2bcdfc1f6a9f2be0e35ec40e35807d671201";
        String tag = "f14eff559fdc411630dd5cf7423914e3";
        byte[] tagbytes = new byte[16];

        cipher.init(new AEADParams(HexUtils.hexToBytes(key), HexUtils.hexToBytes(iv), CipherMode.ENCRYPT));
        cipher.updateAAD(HexUtils.hexToBytes(aad.substring(0,32)));
        cipher.updateAAD(HexUtils.hexToBytes(aad.substring(32,64)));
        cipher.updateAAD(HexUtils.hexToBytes(aad.substring(64,96)));
        cipher.updateAAD(HexUtils.hexToBytes(aad.substring(96,128)));
        cipher.finalise(tagbytes);

        assertEquals(tag, HexUtils.bytesToHex(tagbytes));
    }

    @Test
    void MultiThenPartialBlockAADTest() {
        String key = "74272ba114d0b7a6beb17490d54b14ae";
        String iv = "f8cfe8c94ea8e25fcf07c8cb";
        String aad = "7391ce86f4e2eb8fe89f99999ace2d7e4e30ec0f33ff468b34cf220f30ee09cc87c8d57b6dc731d53fd0a8e255070fc2f8501070c7";
        String tag = "0310aff98da81175d81f0ffeb4707ced";
        byte[] tagbytes = new byte[16];

        cipher.init(new AEADParams(HexUtils.hexToBytes(key), HexUtils.hexToBytes(iv), CipherMode.ENCRYPT));
        cipher.updateAAD(HexUtils.hexToBytes(aad.substring(0,32)));
        cipher.updateAAD(HexUtils.hexToBytes(aad.substring(32,64)));
        cipher.updateAAD(HexUtils.hexToBytes(aad.substring(64,96)));
        cipher.updateAAD(HexUtils.hexToBytes(aad.substring(96)));
        cipher.finalise(tagbytes);

        assertEquals(tag, HexUtils.bytesToHex(tagbytes));
    }

}

