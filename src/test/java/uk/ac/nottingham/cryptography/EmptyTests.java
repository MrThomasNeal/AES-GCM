package uk.ac.nottingham.cryptography;

import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestMethodOrder;

import java.util.ServiceLoader;

import static org.junit.jupiter.api.Assertions.assertEquals;

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class EmptyTests {

    private final AEADCipher cipher = ServiceLoader.load(AEADCipher.class).findFirst().orElseThrow();

    @Test
    void emptyTestOne() {
        String key = "bedcfb5a011ebc84600fcb296c15af0d";
        String iv = "438a547a94ea88dce46c6c85";
        String tag = "960247ba5cde02e41a313c4c0136edc3";

        byte[] tagbytes = new byte[16];

        cipher.init(new AEADParams(HexUtils.hexToBytes(key), HexUtils.hexToBytes(iv), CipherMode.ENCRYPT));
        cipher.finalise(tagbytes);
        assertEquals(tag, HexUtils.bytesToHex(tagbytes));
    }

    @Test
    void emptyTestTwo() {
        String key = "f5c16336e2a1a2414ec335ba6255818c";
        String iv = "06608aa9d09765913b8c4a11";
        String tag = "18c3d59fabfa17fd4d9a10c8d2195046";

        byte[] tagbytes = new byte[16];

        cipher.init(new AEADParams(HexUtils.hexToBytes(key), HexUtils.hexToBytes(iv), CipherMode.ENCRYPT));
        cipher.finalise(tagbytes);
        assertEquals(tag, HexUtils.bytesToHex(tagbytes));
    }

}

