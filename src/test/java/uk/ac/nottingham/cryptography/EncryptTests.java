package uk.ac.nottingham.cryptography;

import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestMethodOrder;

import java.util.ServiceLoader;

import static org.junit.jupiter.api.Assertions.assertEquals;

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class EncryptTests {

    private final AEADCipher cipher = ServiceLoader.load(AEADCipher.class).findFirst().orElseThrow();


    @Test
    void EncryptSingleBlocksTest() {
        String key = "edb58228747d04cac313aac2f6c79bf6";
        String iv = "e78bef52e1bec517c59e575d";
        String aad = "10161fc44781ff120b1fc2f1c4e46bd2";
        String pt = "5d54086f99b150265323dd76171d94de";
        String ct = "3ac27d3d8f6d7a078291c7347ac81eba";
        String tag = "d949145131580e1d0768c57dbb0f535f";

        byte[] tagbytes = new byte[16];

        cipher.init(new AEADParams(HexUtils.hexToBytes(key), HexUtils.hexToBytes(iv), CipherMode.ENCRYPT));

        cipher.updateAAD(HexUtils.hexToBytes(aad));

        byte[] block = HexUtils.hexToBytes(pt);

        cipher.processBlock(block);
        assertEquals(ct, HexUtils.bytesToHex(block));

        cipher.finalise(tagbytes);
        assertEquals(tag, HexUtils.bytesToHex(tagbytes));
    }

    @Test
    void EncryptMultiBlockTest() {
        String key = "0ba4ecf2e2910158e13427a8fbce7219";
        String iv = "48035bea98944f5d3db78022";
        String aad = "5e67642c50ea42c526e08ac854756c9c48add4d1682658ab4f5c8f35c4ef710f";
        String pt = "afdf0416a290596af3a45729a4feec4f261da3bf9e4bbb3beb5ad64080b2bfc0";
        String ct = "d4f5f40791db9f670d0c8a6ade083b96329e6f6b2217eab054553cec1721a6b9";
        String tag = "7d336070175d1a69e12699b00ec65ac1";

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

        cipher.finalise(tagbytes);
        assertEquals(tag, HexUtils.bytesToHex(tagbytes));
    }

    @Test
    void EncryptMultiPTPartialAADBlockTest() {
        String key = "97e3b1044a2a49856f1bfe73edbed5f5";
        String iv = "027721168c79086ea3b80100";
        String aad = "d370ff9735";
        String pt = "89a5095eaf5f85d676a2bc4d4fce4cc24788521a5be5f7ffdc45c03ef2efffc4";
        String ct = "772c75d77e23c9056e9f82666d15ddfab597d8a4e65ac8bdd17b8d6811da17be";
        String tag = "3c94575eeaeb5ccfd7cdfe8c832b9afa";

        byte[] tagbytes = new byte[16];

        cipher.init(new AEADParams(HexUtils.hexToBytes(key), HexUtils.hexToBytes(iv), CipherMode.ENCRYPT));

        for (int i = 0; i < aad.length(); i+=32) {
            cipher.updateAAD(HexUtils.hexToBytes(aad.substring(i, Math.min(i + 32, aad.length()))));
        }

        for (int i = 0; i < pt.length(); i+=32) {
            int endIndex = Math.min(i + 32, pt.length());
            byte[] block = HexUtils.hexToBytes(pt.substring(i, endIndex));
            cipher.processBlock(block);
            assertEquals(ct.substring(i, endIndex), HexUtils.bytesToHex(block));
        }

        cipher.finalise(tagbytes);
        assertEquals(tag, HexUtils.bytesToHex(tagbytes));
    }

    @Test
    void EncryptMultiThenPartialBlockTest() {
        String key = "151b207dbef2b0679e372d9ae3dd2ddc";
        String iv = "d3cf0e575c0999eae8fbaf36";
        String aad = "bfa7e8c1547ace2fbc6f12ed863bffa51797cae9e49231e733da859e9bade066ea656f6e0fb18d20";
        String pt = "87789365ae7f1688a7d867b0a1d34e9b7bdfc2";
        String ct = "d4d51e5bfa557c3c90b619ac61825f07aa2b03";
        String tag = "99a1d6c9b8400cabecbab8a0c10c1d40";

        byte[] tagbytes = new byte[16];

        cipher.init(new AEADParams(HexUtils.hexToBytes(key), HexUtils.hexToBytes(iv), CipherMode.ENCRYPT));

        for (int i = 0; i < aad.length(); i+=32) {
            cipher.updateAAD(HexUtils.hexToBytes(aad.substring(i, Math.min(i + 32, aad.length()))));
        }

        for (int i = 0; i < pt.length(); i+=32) {
            int endIndex = Math.min(i + 32, pt.length());
            byte[] block = HexUtils.hexToBytes(pt.substring(i, endIndex));
            cipher.processBlock(block);
            assertEquals(ct.substring(i, endIndex), HexUtils.bytesToHex(block));
        }

        cipher.finalise(tagbytes);
        assertEquals(tag, HexUtils.bytesToHex(tagbytes));
    }
}

