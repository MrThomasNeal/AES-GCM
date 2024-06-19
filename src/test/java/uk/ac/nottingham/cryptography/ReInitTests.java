package uk.ac.nottingham.cryptography;

import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestMethodOrder;

import java.util.Arrays;
import java.util.ServiceLoader;

import static org.junit.jupiter.api.Assertions.assertEquals;

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class ReInitTests {

    private final AEADCipher cipher = ServiceLoader.load(AEADCipher.class).findFirst().orElseThrow();

    @Test
    void ReInitTest() {
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

        key = "eeefba270bd16e5d40cab5221cb7f4c3";
        iv = "daf86912bbe55dc5ce8e6f22";
        aad = "e09bc8049a7f984ea6dab298965edfbc";
        pt = "4735958c6e135ad3a7941b7519167a29";
        ct = "5112baba11a4d2128eb90a12fb3113c9";
        tag = "7f521c3ed77ff2c066155a42716285ac";

        Arrays.fill(tagbytes, (byte)0);

        cipher.init(new AEADParams(HexUtils.hexToBytes(key), HexUtils.hexToBytes(iv), CipherMode.ENCRYPT));

        cipher.updateAAD(HexUtils.hexToBytes(aad));

        block = HexUtils.hexToBytes(pt);

        cipher.processBlock(block);
        assertEquals(ct, HexUtils.bytesToHex(block));

        cipher.finalise(tagbytes);
        assertEquals(tag, HexUtils.bytesToHex(tagbytes));
    }

    @Test
    void ComplexReInitTest() {
        String key = "97e3b1044a2a49856f1bfe73edbed5f5";
        String iv = "027721168c79086ea3b80100";
        String aad = "d370ff9735";
        String pt = "89a5095eaf5f85d676a2bc4d4fce4cc24788521a5be5f7ffdc45c03ef2efffc4";
        String ct = "772c75d77e23c9056e9f82666d15ddfab597d8a4e65ac8bdd17b8d6811da17be";
        String tag = "3c94575eeaeb5ccfd7cdfe8c832b9afa";

        byte[] tagbytes = new byte[16];

        cipher.init(new AEADParams(HexUtils.hexToBytes(key), HexUtils.hexToBytes(iv), CipherMode.ENCRYPT));

        for (int i = 0; i < aad.length(); i += 32) {
            cipher.updateAAD(HexUtils.hexToBytes(aad.substring(i, Math.min(i + 32, aad.length()))));
        }

        for (int i = 0; i < pt.length(); i += 32) {
            int endIndex = Math.min(i + 32, pt.length());
            byte[] block = HexUtils.hexToBytes(pt.substring(i, endIndex));
            cipher.processBlock(block);
            assertEquals(ct.substring(i, endIndex), HexUtils.bytesToHex(block));
        }

        cipher.finalise(tagbytes);
        assertEquals(tag, HexUtils.bytesToHex(tagbytes));

        key = "d5f4b70208a308b8efa99b0b13004950";
        iv = "afbdf094e478d92ad258cbf1";
        aad = "68f9369edffd27a05a76a516ae99307b3ae5a024c7a82919cd5031069b33ae5ec05ffd7ce85d9194e1e96f03c8216addc632";
        pt = "74cde2cf0a77636cf25ad2495f577ed9d577d4b39c595fb09cc4cc6b864eb1dbc17c975da1325d2e263f4fc20c97090c085818497120145eeba5dc7711bbd7596ce89d2853fdce503d06952e6aeafbfa4bf092a0f1ae85871dc130d55666ddec9e217925";
        ct = "23adf3d418a7b06955c04823034665e0f395b1a3b40fcedd4990b5369bb6d665830134fc94a3b65179bbd55bd4de5633e9fe510ab78f88196147a5d3461a7462344e0d1e7475345b856dad562871e6d22bc31587c309e852e63f250ba0eef705548bf561";
        tag = "0c1491d74d7e59d7ba1f95a1a3dfe117";

        Arrays.fill(tagbytes, (byte)0);

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

