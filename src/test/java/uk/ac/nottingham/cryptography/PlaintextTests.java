package uk.ac.nottingham.cryptography;

import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestMethodOrder;

import java.util.ServiceLoader;

import static org.junit.jupiter.api.Assertions.assertEquals;

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class PlaintextTests {

    private final AEADCipher cipher = ServiceLoader.load(AEADCipher.class).findFirst().orElseThrow();

    @Test
    void SingleBlockPTTest() {
        String key = "f420c2e113b07d4d634d4b6ec4ce0e91";
        String iv = "155309c8d203744f631d2c87";
        String pt = "f4ab1eb9ccf0ee6b9b71fa433b7ceba0";
        String ct = "9f11bb1bb24e8cb52617173f7ec2dea3";
        String tag = "955fb9198fdbe1fb37b7aafca48286ca";

        byte[] tagbytes = new byte[16];

        cipher.init(new AEADParams(HexUtils.hexToBytes(key), HexUtils.hexToBytes(iv), CipherMode.ENCRYPT));

        byte[] block = HexUtils.hexToBytes(pt);

        cipher.processBlock(block);
        assertEquals(ct, HexUtils.bytesToHex(block));

        cipher.finalise(tagbytes);
        assertEquals(tag, HexUtils.bytesToHex(tagbytes));
    }

    @Test
    void PartialBlockPTTest() {
        String key = "207efd41bedf47c49edaad59b55aa6f3";
        String iv = "cf347195b458bfc7f36d0f8e";
        String pt = "8da9cca789a4d7fe4b1b4f9a94";
        String ct = "218c528b807e7ee52af17b7e2c";
        String tag = "0928d322b20d7decc82c21cd2d09db21";

        byte[] tagbytes = new byte[16];

        cipher.init(new AEADParams(HexUtils.hexToBytes(key), HexUtils.hexToBytes(iv), CipherMode.ENCRYPT));

        byte[] block = HexUtils.hexToBytes(pt);

        cipher.processBlock(block);
        assertEquals(ct, HexUtils.bytesToHex(block));

        cipher.finalise(tagbytes);
        assertEquals(tag, HexUtils.bytesToHex(tagbytes));

    }

    @Test
    void MultiBlockPTTest() {
        String key = "3a43c4ea22d8cd8a27320498ae30a49f";
        String iv = "b0c11ec7512b760799fd3d0e";
        String pt = "663d1e6b7b9d83bf20fab131407d269dafea8128a8b4aa04b973b141735c22ff";
        String ct = "a23bfe9498e776cbe32f11b8e9d8de1739429a75051f20752ddcd1795edb4458";
        String tag = "ee2deb9bff46c488b2a9343aa2b2ab0d";


        byte[] tagbytes = new byte[16];

        cipher.init(new AEADParams(HexUtils.hexToBytes(key), HexUtils.hexToBytes(iv), CipherMode.ENCRYPT));

        byte[] block = HexUtils.hexToBytes(pt.substring(0,32));
        cipher.processBlock(block);
        assertEquals(ct.substring(0,32), HexUtils.bytesToHex(block));

        block = HexUtils.hexToBytes(pt.substring(32,64));
        cipher.processBlock(block);
        assertEquals(ct.substring(32,64), HexUtils.bytesToHex(block));

        cipher.finalise(tagbytes);
        assertEquals(tag, HexUtils.bytesToHex(tagbytes));
    }

    @Test
    void MultiThenPartialBlockPTTest() {
        String key = "49685bc39ff85814f6bc41ae084c56b4";
        String iv = "a03bbd26b9c8da9d653d61a8";
        String pt = "c3e60d8b274e656c4abc548f1b2986e4e53f";
        String ct = "9fad5d1271131381d727442625a4f07d3e40";
        String tag = "95ada59098e4c7a96dcb0d050a77b6e6";

        byte[] tagbytes = new byte[16];

        cipher.init(new AEADParams(HexUtils.hexToBytes(key), HexUtils.hexToBytes(iv), CipherMode.ENCRYPT));

        byte[] block = HexUtils.hexToBytes(pt.substring(0,32));
        cipher.processBlock(block);
        assertEquals(ct.substring(0,32), HexUtils.bytesToHex(block));

        block = HexUtils.hexToBytes(pt.substring(32));
        cipher.processBlock(block);
        assertEquals(ct.substring(32), HexUtils.bytesToHex(block));

        cipher.finalise(tagbytes);
        assertEquals(tag, HexUtils.bytesToHex(tagbytes));
    }
}

