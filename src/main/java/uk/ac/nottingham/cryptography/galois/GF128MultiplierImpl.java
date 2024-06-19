package uk.ac.nottingham.cryptography.galois;

import java.util.Arrays;

/**
 * Implementation of a multiplier in GF(2^128).
 * <p>
 * Provides a basic implementation of multiplication in the
 * Galois Field 2^128, modulo x^127 + x^7 + x^2 + x + 1.
 * <p>
 * This implementation can be used by the AESGCM implementation
 * to perform the calculations needed to compute the tag T.
 * <p>
 * Do not edit this class.
 */
public class GF128MultiplierImpl implements GF128Multiplier {
    private static final byte[] F = new byte[] { (byte)0xE1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    private byte[] H = null;
    private final byte[] V = new byte[16];

    @Override
    public void init(byte[] H) {
        this.H = Arrays.copyOf(H, 16);
    }

    @Override
    public void multiplyByH(byte[] X) {
        if (H != null) {
            multiply(X, H);
        }
    }

    @Override
    public void multiply(byte[] X, byte[] Y) {
        System.arraycopy(X, 0, V, 0, 16);

        if (X == Y) {
            Y = Arrays.copyOf(Y, 16);
        }

        Arrays.fill(X, (byte) 0);

        for (int i = 0; i < 128; i++) {
            if (getBit(Y, 127 - i) == 1) {
                xor(X, V);
            }
            xtimes(V);
        }
    }

    @Override
    public byte[] getH() {
        return this.H;
    }

    private void rightShift(byte[] a) {
        for (int i = 15; i > 0; i--) {
            a[i] = (byte)(((a[i] & 0xFF) >>> 1) | ((a[i-1] & 1) << 7));
        }
        a[0] = (byte)((a[0] & 0xFF) >>> 1);
    }

    private void xor(byte[] a, byte[] b) {
        for(int i = 0; i < 16; i++) {
            a[i] = (byte)(a[i] & 0xFF ^ b[i] & 0xFF);
        }
    }

    private int getBit(byte[] a, int i) {
        return (a[15 - i / 8] >> (i % 8)) & 1;
    }

    private void xtimes(byte[] a) {
        if ((a[15] & 1) == 0) {
            this.rightShift(a);
        } else {
            this.rightShift(a);
            this.xor(a, F);
        }
    }

}
