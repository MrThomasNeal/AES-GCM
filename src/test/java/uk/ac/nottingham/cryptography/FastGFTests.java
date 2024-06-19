package uk.ac.nottingham.cryptography;

import org.junit.jupiter.api.*;
import uk.ac.nottingham.cryptography.galois.GF128FastImpl;
import uk.ac.nottingham.cryptography.galois.GF128Multiplier;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class FastGFTests {
    private final GF128Multiplier GF = new GF128FastImpl();
    private final boolean testsEnabled = false;

    @BeforeAll
    void checkEnabled() {
        assumeTrue(testsEnabled);
    }

    @Test
    void gfGetHTest() {
        byte[] H = new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
        GF.init(Arrays.copyOf(H, 16));
        assertArrayEquals(H, GF.getH());
    }

    @Test
    void gfMultiplyByHTest() {
        String[] Hs = new String[] {
                "b572d36e1fefd0d57522fb6ade3b69c4",
                "a5f904137b0f00246b0b31224cd622e8",
                "0eb742738ca367ff80114c4c1f484425"
        };

        String[] As = new String[] {
                "5feadf16d64d4d5683dc00d067fed0fc",
                "6f32466153cd738b84d469af40554d3c",
                "f86d5683dc008d4d48f7dec5d72f4eb4"
        };

        String[][] AHs = new String[][] {
                {
                        "c12fd26ccb0ea3083be0d85cc502e66e",
                        "484e8fa3aba9ce70a9f10bdbcd08ccfd",
                        "accb9ddfe1b8d566655cd426ae76f31c"
                },
                {
                        "40e79be8db8a150315e9608d6d0d7445",
                        "a401c34ec682d292c2fc9cbfc64174b8",
                        "1cb049d71b45a1fde88a418fdc72ace2"
                },
                {
                        "099fc460deedef730f0c0987b8332056",
                        "53fad13605761719a20c7e2f334f3c52",
                        "c0711d9b652056d34de3fc2cbec75524"
                },
        };

        String[][] AH10s = new String[][] {
                {
                        "109985504510ba5609cf5059fd3a4ae3",
                        "4e9021fbba97861e4644b05575587e03",
                        "b2b4ce9c9afec6681af93dfa15b218d7"
                },
                {
                        "10895911750047c8d1a7dc5280c62de8",
                        "7114ab1171d6c76fb654e127d6ace66c",
                        "656714b4bd9519ffb814b358373b3e70"
                },
                {
                        "310ef18f3822f87103987526cbe82a03",
                        "246e636a259ac37110e72790580de9a2",
                        "62831358592f717b7e418d53edbd0137"
                },
        };

        for (int hi = 0; hi < 3; hi++) {
            GF.init(HexUtils.hexToBytes(Hs[hi]));
            for (int ai = 0; ai < 3; ai++) {
                byte[] A = HexUtils.hexToBytes(As[ai]);
                GF.multiplyByH(A);
                assertArrayEquals(HexUtils.hexToBytes(AHs[hi][ai]), A);

                for (int i = 0; i < 9; i++) {
                    GF.multiplyByH(A);
                }
                assertArrayEquals(HexUtils.hexToBytes(AH10s[hi][ai]), A);
            }
        }

    }

    @Test
    void gfMultiplyTest() {
        String[] As = new String[] {
                "b572d36e1fefd0d57522fb6ade3b69c4",
                "a5f904137b0f00246b0b31224cd622e8",
                "0eb742738ca367ff80114c4c1f484425"
        };

        String[] Bs = new String[] {
                "5feadf16d64d4d5683dc00d067fed0fc",
                "6f32466153cd738b84d469af40554d3c",
                "f86d5683dc008d4d48f7dec5d72f4eb4"
        };

        String[][] ABs = new String[][] {
                {
                        "c12fd26ccb0ea3083be0d85cc502e66e",
                        "72b6d56aa195157f3c38e317833f6598",
                        "e1cc12e61be925baa297c0154f8088a8"
                },
                {
                        "40e79be8db8a150315e9608d6d0d7445",
                        "9e663af62c29cf6b594215147756cb02",
                        "5326db3da772e51117f0aa8327b0ead8"
                },
                {
                        "099fc460deedef730f0c0987b8332056",
                        "f22883745eb3f63963b6aae08a00a155",
                        "894c8680178d77a12299df835c2eda3a"
                },
        };

        for (int ai = 0; ai < 3; ai++) {
            byte[] A = HexUtils.hexToBytes(As[ai]);
            for (int bi = 0; bi < 3; bi++) {
                byte[] B = HexUtils.hexToBytes(Bs[bi]);
                GF.multiply(A,B);
                assertArrayEquals(HexUtils.hexToBytes(ABs[ai][bi]), A);
            }
        }
    }

    @Test
    void gfLongTest() {
        String Hs = "b572d36e1fefd0d57522fb6ade3b69c4";
        String As = "5326db3da772e51117f0aa8327b0ead8";
        String AH1M = "a55dc7f555d958837468241711763bd1";

        GF.init(HexUtils.hexToBytes(Hs));
        byte[] A = HexUtils.hexToBytes(As);

        for (int i = 0; i < 1000000; i++) {
            GF.multiplyByH(A);
        }
        assertEquals(AH1M, HexUtils.bytesToHex(A));
    }

}

