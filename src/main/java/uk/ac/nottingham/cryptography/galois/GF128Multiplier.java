package uk.ac.nottingham.cryptography.galois;

/**
 * Interface representing a class that implements multiplication
 * in GF(2^128).
 * <p>
 * Provides a generic multiply function, as well as specific
 * functions to initialise and multiply by a constant H
 * <p>
 * Do not edit this class.
 */
public interface GF128Multiplier {
    void init(byte[] H);
    void multiplyByH(byte[] X);
    void multiply(byte[] X, byte[] Y);
    byte[] getH();
}
