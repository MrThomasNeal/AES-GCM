package uk.ac.nottingham.cryptography;

import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestMethodOrder;

import java.util.ServiceLoader;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class VerificationTests {

    private final AEADCipher cipher = ServiceLoader.load(AEADCipher.class).findFirst().orElseThrow();

    @Test
    void ValidTests() {
        String[] keys = {
                "38449890234eb8afab0bbf82e2385454",
                "e12260fcd355a51a0d01bb1f6fa538c2",
                "c4b03435b91fc52e09eff27e4dc3fb42",
                "74272ba114d0b7a6beb17490d54b14ae",
                "46afc43af2b819334563dc568ef7aa7f"
        };

        String[] ivs = {
                "33e90658416e7c1a7c005f11",
                "5dfc37366f5688275147d3f9",
                "5046e7e08f0747e1efccb09e",
                "f8cfe8c94ea8e25fcf07c8cb",
                "52b5dbb5793bd12d0c7dabc4"
        };

        String[] aads = {
                "4020855c66ac4595058395f367201c4c",
                "",
                "75fc9078b488e9503dcb568c882c9eec24d80b04f0958c82aac8484f025c90434148db8e9bfe29c7e071b797457cb1695a5e5a6317b83690ba0538fb11e325ca",
                "7391ce86f4e2eb8fe89f99999ace2d7e4e30ec0f33ff468b34cf220f30ee09cc87c8d57b6dc731d53fd0a8e255070fc2f8501070c7",
                "168f1f14987fdce87f072b13eb03ad8f9798a030b6b376c80836508abd8b3bcb"
        };

        String[] cts = {
                "a6f2ef3c7ef74a126dd2d5f6673964e27d5b34b6",
                "d33bf6722fc29384fad75f990248b9528e0959aa67ec66869dc3996c67a2d559e7d77ce5955f8cad2a4df5fdc3acccafa7bc0def53d848111256903e5add0420",
                "b6786812574a254eb43b1cb1d1753564c6b520e9",
                "",
                "c0fb350e91db44674b52cfdf40dac2dffae91cc5b5b6deb1667b3de7be09b38b0c470a546b9ff661e1a77da2047b480cc5424873ea35c7c5a5aeb3a419bb798c"
        };

        String[] tags = {
                "b8bbdc4f5014bc752c8b4e9b87f650a3",
                "8bc833de510863b4b432c3cbf45aa7cc",
                "ad8c09610d508f3d0f03cc523c0d5fcc",
                "0310aff98da81175d81f0ffeb4707ced",
                "ef5f2d7e4dc96816919d4ceb048915ae"
        };

        for (int t = 0; t < keys.length; t++) {
            cipher.init(new AEADParams(HexUtils.hexToBytes(keys[t]), HexUtils.hexToBytes(ivs[t]), CipherMode.DECRYPT));

            for (int i = 0; i < aads[t].length(); i += 32) {
                cipher.updateAAD(HexUtils.hexToBytes(aads[t].substring(i, Math.min(i + 32, aads[t].length()))));
            }

            for (int i = 0; i < cts[t].length(); i += 32) {
                int endIndex = Math.min(i + 32, cts[t].length());
                byte[] block = HexUtils.hexToBytes(cts[t].substring(i, endIndex));
                cipher.processBlock(block);
            }

            final byte[] outputTag = HexUtils.hexToBytes(tags[t]);
            assertDoesNotThrow(() -> cipher.verify(outputTag));
        }
    }

    @Test
    void InvalidTests() {
        /*
        1) Invalid Key
        2) Invalid IV
        3) Invalid AAD
        4) Invalid Tag
        5) Invalid CT
         */

        String[] keys = {
                "38449890234eb8bfab0bbf82e2385454",
                "e12260fcd355a51a0d01bb1f6fa538c2",
                "c4b03435b91fc52e09eff27e4dc3fb42",
                "74272ba114d0b7a6beb17490d54b14ae",
                "46afc43af2b819334563dc568ef7aa7f"
        };

        String[] ivs = {
                "33e90658416e7c1a7c005f11",
                "5dfc37366f5678275147d3f9",
                "5046e7e08f0747e1efccb09e",
                "f8cfe8c94ea8e25fcf07c8cb",
                "52b5dbb5793bd12d0c7dabc4"
        };

        String[] aads = {
                "4020855c66ac4595058395f367201c4c",
                "",
                "75fc9078b488e9503dcb568c882c9eec24d80b04f0958c82aac8484f025c90434148db8e9bfe29c7e071b797457cb0695a5e5a6317b83690ba0538fb11e325ca",
                "7391ce86f4e2eb8fe89f99999ace2d7e4e30ec0f33ff468b34cf220f30ee09cc87c8d57b6dc731d53fd0a8e255070fc2f8501070c7",
                "168f1f14987fdce87f072b13eb03ad8f9798a030b6b376c80836508abd8b3bcb"
        };

        String[] cts = {
                "a6f2ef3c7ef74a126dd2d5f6673964e27d5b34b6",
                "d33bf6722fc29384fad75f990248b9528e0959aa67ec66869dc3996c67a2d559e7d77ce5955f8cad2a4df5fdc3acccafa7bc0def53d848111256903e5add0420",
                "b6786812574a254eb43b1cb1d1753564c6b520e9",
                "",
                "c0fb350e91db44674b52cfdf40dac2dffae91cc5b5b6deb1667b3de7be09b38b0c470a546b9ff661e1a77da3047b480cc5424873ea35c7c5a5aeb3a419bb798c"
        };

        String[] tags = {
                "b8bbdc4f5014bc752c8b4e9b87f650a3",
                "8bc833de510863b4b432c3cbf45aa7cc",
                "ad8c09610d508f3d0f03cc523c0d5fcc",
                "0317aff98da81175d81f0ffeb4707ced",
                "ef5f2d7e4dc96816919d4ceb048915ae"
        };

        for (int t = 0; t < keys.length; t++) {
            cipher.init(new AEADParams(HexUtils.hexToBytes(keys[t]), HexUtils.hexToBytes(ivs[t]), CipherMode.DECRYPT));

            for (int i = 0; i < aads[t].length(); i += 32) {
                cipher.updateAAD(HexUtils.hexToBytes(aads[t].substring(i, Math.min(i + 32, aads[t].length()))));
            }

            for (int i = 0; i < cts[t].length(); i += 32) {
                int endIndex = Math.min(i + 32, cts[t].length());
                byte[] block = HexUtils.hexToBytes(cts[t].substring(i, endIndex));
                cipher.processBlock(block);
            }

            final byte[] outputTag = HexUtils.hexToBytes(tags[t]);
            assertThrows(InvalidTagException.class, () -> cipher.verify(outputTag));
        }
    }

}

