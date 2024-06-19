package uk.ac.nottingham.cryptography;

import org.junit.jupiter.api.*;

import java.util.ServiceLoader;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class LateAADTests {

    private final AEADCipher cipher = ServiceLoader.load(AEADCipher.class).findFirst().orElseThrow();

    private final boolean testsEnabled = false;

    @BeforeAll
    void checkEnabled() {
        assumeTrue(testsEnabled);
    }

    @Test
    void LateAADMultiBlockTestOne() {
        String key = "0ba4ecf2e2910158e13427a8fbce7219";
        String iv = "48035bea98944f5d3db78022";
        String aad = "5e67642c50ea42c526e08ac854756c9c48add4d1682658ab4f5c8f35c4ef710f";
        String pt = "afdf0416a290596af3a45729a4feec4f261da3bf9e4bbb3beb5ad64080b2bfc0";
        String ct = "d4f5f40791db9f670d0c8a6ade083b96329e6f6b2217eab054553cec1721a6b9";
        String tag = "7d336070175d1a69e12699b00ec65ac1";

        byte[] tagbytes = new byte[16];

        cipher.init(new AEADParams(HexUtils.hexToBytes(key), HexUtils.hexToBytes(iv), CipherMode.ENCRYPT));

        cipher.updateAAD(HexUtils.hexToBytes(aad.substring(0, 32)));

        byte[] block = HexUtils.hexToBytes(pt.substring(0,32));
        cipher.processBlock(block);
        assertEquals(ct.substring(0,32), HexUtils.bytesToHex(block));

        cipher.updateAAD(HexUtils.hexToBytes(aad.substring(32,64)));

        block = HexUtils.hexToBytes(pt.substring(32,64));
        cipher.processBlock(block);
        assertEquals(ct.substring(32,64), HexUtils.bytesToHex(block));

        cipher.finalise(tagbytes);
        assertEquals(tag, HexUtils.bytesToHex(tagbytes));
    }

    @Test
    void LateAADMultiBlockTestTwo() {
        String key = "4776ece9dc2355144a546f60422242a3";
        String iv = "12cbd3320ad50a2e28e91056";
        String aad = "d1c74ad4080576adfaefc21449ff6b60cb9dd293d1466240e8b692e829966eee0edd2fc043a523b93d67892a8269893b";
        String pt = "99bce7d0abbb42d1f2c8b6f901d3c87266026d6539c2df362f231cf13d1b54d30fdf180c4a51be4f652c091fa54c546e4977d6660d97403149d891e1457e60b3";
        String ct = "c64e3dd96a4c5cf764e12ba2aeaba55348484c0347e245475466b249487ee7a4beb838407602e87d66c74925224c74730a1448603a24db8ef4e9637da9b892a2";
        String tag = "7f4ebb32583d134b6604ac61007f9768";

        byte[] tagbytes = new byte[16];

        cipher.init(new AEADParams(HexUtils.hexToBytes(key), HexUtils.hexToBytes(iv), CipherMode.ENCRYPT));

        cipher.updateAAD(HexUtils.hexToBytes(aad.substring(0, 32)));
        cipher.updateAAD(HexUtils.hexToBytes(aad.substring(32,64)));

        byte[] block = HexUtils.hexToBytes(pt.substring(0,32));
        cipher.processBlock(block);
        assertEquals(ct.substring(0,32), HexUtils.bytesToHex(block));

        block = HexUtils.hexToBytes(pt.substring(32,64));
        cipher.processBlock(block);
        assertEquals(ct.substring(32,64), HexUtils.bytesToHex(block));

        block = HexUtils.hexToBytes(pt.substring(64,96));
        cipher.processBlock(block);
        assertEquals(ct.substring(64,96), HexUtils.bytesToHex(block));

        cipher.updateAAD(HexUtils.hexToBytes(aad.substring(64,96)));

        block = HexUtils.hexToBytes(pt.substring(96,128));
        cipher.processBlock(block);
        assertEquals(ct.substring(96,128), HexUtils.bytesToHex(block));

        cipher.finalise(tagbytes);
        assertEquals(tag, HexUtils.bytesToHex(tagbytes));
    }

    @Test
    void LateAADMultiBlockTestThree() {
        String key = "f4a0bd273579c892118764546b002907";
        String iv = "049c23aae0056224d7904fca";
        String aad = "a62efb993a1f1b658fa9b03a3cb3b574a76e371d730483adb914f77ba1c8b7a1ed34d7303b1f84d8601fe9b26c954eb0";
        String pt = "1ef3eba6b705c5e9a45d89e4cbfc1b7e326ef79fcfabee76353738acb2caf0b5255385d137ffbbeb2e06c957305f01bf05922eb6c4e5ff7e3fe5120689f7b077";
        String ct = "002eeb4d393d7647ecada12f9b25a36091f841d573cdbe25c04ebb22f205e08395d5def5694ef8a5433b2846d1e3ffbef1c8f60ff200d934a528712f87c22a01";
        String tag = "2df207ad317a1264767a3530dfb0a14c";

        byte[] tagbytes = new byte[16];

        cipher.init(new AEADParams(HexUtils.hexToBytes(key), HexUtils.hexToBytes(iv), CipherMode.ENCRYPT));

        cipher.updateAAD(HexUtils.hexToBytes(aad.substring(0, 32)));

        byte[] block = HexUtils.hexToBytes(pt.substring(0,32));
        cipher.processBlock(block);
        assertEquals(ct.substring(0,32), HexUtils.bytesToHex(block));

        cipher.updateAAD(HexUtils.hexToBytes(aad.substring(32,64)));

        block = HexUtils.hexToBytes(pt.substring(32,64));
        cipher.processBlock(block);
        assertEquals(ct.substring(32,64), HexUtils.bytesToHex(block));

        block = HexUtils.hexToBytes(pt.substring(64,96));
        cipher.processBlock(block);
        assertEquals(ct.substring(64,96), HexUtils.bytesToHex(block));

        cipher.updateAAD(HexUtils.hexToBytes(aad.substring(64,96)));

        block = HexUtils.hexToBytes(pt.substring(96,128));
        cipher.processBlock(block);
        assertEquals(ct.substring(96,128), HexUtils.bytesToHex(block));

        cipher.finalise(tagbytes);
        assertEquals(tag, HexUtils.bytesToHex(tagbytes));
    }

    @Test
    void LateAADPartialBlockTest() {
        String key = "5f02c604cd1a8c1a206f66a27eebce05";
        String iv = "a37fce43e44e37856e205333";
        String aad = "81533d20662eae5218300081134a4566e657ad6365f0d1dacfaa32a1";
        String pt = "c44751237047242ba26050849f4973b37df91f46cf45d34ecfe9d0674b10ccb339364f2b45b9fdbf9fc089da9a";
        String ct = "629dbd314a209f62e6d520834efa1ca612a819a39741b7b469e52e9d2e58f3689eb9952ece617bbd6aef52d227";
        String tag = "fe7351d59a0996179641026ec812b32d";

        byte[] tagbytes = new byte[16];

        cipher.init(new AEADParams(HexUtils.hexToBytes(key), HexUtils.hexToBytes(iv), CipherMode.ENCRYPT));

        cipher.updateAAD(HexUtils.hexToBytes(aad.substring(0, 32)));
        cipher.updateAAD(HexUtils.hexToBytes(aad.substring(32)));

        byte[] block = HexUtils.hexToBytes(pt.substring(0,32));
        cipher.processBlock(block);
        assertEquals(ct.substring(0,32), HexUtils.bytesToHex(block));

        block = HexUtils.hexToBytes(pt.substring(32,64));
        cipher.processBlock(block);
        assertEquals(ct.substring(32,64), HexUtils.bytesToHex(block));

        block = HexUtils.hexToBytes(pt.substring(64));
        cipher.processBlock(block);
        assertEquals(ct.substring(64), HexUtils.bytesToHex(block));

        cipher.finalise(tagbytes);
        assertEquals(tag, HexUtils.bytesToHex(tagbytes));
    }

    @Test
    @Order(4)
    void LateAAD10MBTest() {
        String key = "a39fb789809590b8ac7b093eb150c265";
        String iv = "483115528828908719395b51";
        String aad = "a62efb993a1f1b658fa9b03a3cb3b574a76e371d730483adb914f77ba1c8b7a1ed34d7303b1f84d8601fe9b26c954eb0";
        String ct = "b0c4e82854d625151daa97c861dee7c0";
        String tag = "6d7d550c7d335358a7eb60af8485a17d";

        byte[] tagbytes = new byte[16];
        byte[] block = new byte[16];

        cipher.init(new AEADParams(HexUtils.hexToBytes(key), HexUtils.hexToBytes(iv), CipherMode.ENCRYPT));

        cipher.updateAAD(HexUtils.hexToBytes(aad.substring(0, 32)));
        cipher.updateAAD(HexUtils.hexToBytes(aad.substring(32,64)));

        for (int i = 0; i < 640000; i++) {
            cipher.processBlock(block);
        }

        cipher.updateAAD(HexUtils.hexToBytes(aad.substring(32,64)));

        cipher.finalise(tagbytes);

        assertEquals(ct, HexUtils.bytesToHex(block));
        assertEquals(tag, HexUtils.bytesToHex(tagbytes));
    }

}

