package uk.ac.nottingham.cryptography.galois;

/**
 * Unfinished implementation of a multiplier in GF(2^128).
 * <p>
 * This class could be used to implement a more efficient
 * multiplier in GF(2^128). Coding in this class is not
 * necessary unless you wish to tackle this challenge.
 * <p>
 * This class is used by the FastGFTests class within
 * the test suite, which is disabled by default.
 */
public class GF128FastImpl implements GF128Multiplier {
    @Override
    public void init(byte[] H) {
        // Add your code here
    }

    @Override
    public void multiplyByH(byte[] X) {
        // Add your code here
    }

    @Override
    public void multiply(byte[] X, byte[] Y) {
        // Add your code here
    }

    @Override
    public byte[] getH() {
        // Add your code here
        return new byte[16];
    }
}
