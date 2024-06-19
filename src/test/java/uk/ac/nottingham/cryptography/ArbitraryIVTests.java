package uk.ac.nottingham.cryptography;

import org.junit.jupiter.api.*;

import java.util.ServiceLoader;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class ArbitraryIVTests {

    private final AEADCipher cipher = ServiceLoader.load(AEADCipher.class).findFirst().orElseThrow();

    private final boolean testsEnabled = false;

    @BeforeAll
    void checkEnabled() {
        assumeTrue(testsEnabled);
    }

    @Test
    void ShortIVTestOne() {
        String key = "d880b5768e2fdcffdaa68bb0e185b233";
        String iv = "a3125b05fbd89176";
        String aad = "2a1548fb11f9400c54ed02b10ae5b41d";
        String pt = "221044b06e67c0fee219602ead7f040b";
        String ct = "0cc1553f12ba4e96a65f15574c530c93";
        String tag = "5f58faaeb45c6d236f593ab56104964d";

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
    void ShortIVTestTwo() {
        String key = "9a25e140236be71b54261e40b48e00ef";
        String iv = "7cc8e187f4b4a6522eb8";
        String aad = "be908cbba7943b805947079ba6fdfcd0ad9bbbe7b4597d9d3da907d0f91cd13374967e81c03908cbfdc0082ae663e7c5";
        String pt = "dedab37bbfcdc2fe94934570509ee9156c1c1951adf20cc47c7d724a98a73dad";
        String ct = "91f7d5b4590e527e21c1e155ded1ee71af4f0b8c93a83103e001458567b12be7";
        String tag = "d19e0b0b4bbcca73f0239d4aca9645d0";

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
    void LongIVTestOne() {
        String key = "556d8b8648163583f53c68f0b379eae9";
        String iv = "8190e1d01a27c12dcd445ee31508ac4f39d55dfd7d395371957c194d7d6fac62";
        String aad = "987b8b2a1c4d6223061ca1b0ec19f641";
        String pt = "bacadbe5528276b72118c929b291a9e1";
        String ct = "130b592b6343d59352eeeed4a02ca080";
        String tag = "2a74393d9a4f1e73c2a03421334e576b";

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
    void LongIVTestTwo() {
        String key = "eb684a9f8fe808787f6290fe281ed068";
        String iv = "c95b38a2f94d9e80989f2c638c9ddc2326852e21bbb1257a25f6e18adaa261e807273b7f3c32ecf6a2d016bb17fd01f8da0adc6b0a3fd95c971328ff448e04fc";
        String aad = "1f819e2756ff5bc39acb4308729f7ec8";
        String pt = "7991a2656ffb545631e2b9a9515935a1";
        String ct = "bcdd1bb38a55783ea2f3968a13b28849";
        String tag = "d58d62c18a7bd1bd18a36339a7cab411";

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
    void LongIVTestThree() {
        String key = "5bb79b9b6d61d899fab6b95f1fea3489";
        String iv = "96d82dee72a73a63c3c286f98a706b3fa09ad6d33a4c7066c29499fbb5909680b856252875e8d833c4737a8b0434d6e55391706639bfaaba79dcd35d82bb69131bd8867d1e1961b144a6057b41342f066ef701f0c2fecb5d299e8ef100418f54";
        String aad = "b4f934c6ce9fd95d6dd2d717801fa9fd";
        String pt = "5b3fed9c03297b232e9960cd8b19d4749ce4ee48721f581519cb0172bb713805";
        String ct = "8d3263796b6e05cabda1f98ea9f996ace35eb62ecc23aefd8307ff78e2310848";
        String tag = "85749fd679fe8de1081e88a897e1d7aa";

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
    void LongPartialIVTestOne() {
        String key = "a1509bd8befa0e3ef2d0b20da65d7580";
        String iv = "cfec766668a587aa64be2f95471e3e01afba0c8870e96f9c51";
        String aad = "34f08e48ba370bc9455ee861cfe41e89";
        String pt = "b2281d5ddee7711e91db41ee09bbc6dccce942158be49640dfba9fdf07cc27fb";
        String ct = "d4bdd675f1747e5a42f11d9067d2ab213f9ae1d0c3bc7901d22d1cd9beaaacad";
        String tag = "c9c6a0f97af0e0959ce78a65915144f7";

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
    void LongPartialIVTestTwo() {
        String key = "3a288a37a52d182b09fac23482026a8e";
        String iv = "56a7b289e9ad932274f4854a35ad9c6e8d06e8a1781934959bc6487cfbf0fd461cb702b0ed1d5baed45048bfecb5534163";
        String aad = "63d9ad55e3f9efd016be50ffcf58ea68";
        String pt = "79250af09b44b78e41896be9b2a7742e172e669b8824772c2cc7587a8d8d7f40";
        String ct = "f0dcb95825fc4d6ab41da9344b32f754f2f889ab75aa8039a2ee5c3a0c843ee3";
        String tag = "84ab8b7df47232c162d922de6e44005c";

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

