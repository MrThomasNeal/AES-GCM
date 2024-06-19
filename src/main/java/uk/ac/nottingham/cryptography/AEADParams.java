package uk.ac.nottingham.cryptography;

/**
 * Parameters used to initialise an AEAD cipher.
 * <p>
 * Each set of parameters is an immutable group of a 128 bit key,
 * (usually) 96 bit IV, and a CipherMode detailing whether encryption
 * or decryption is required.
 * <p>
 * Do not edit this class.
 */
public class AEADParams {
    private final byte[] key;
    private final byte[] iv;
    private final CipherMode mode;

    public AEADParams(byte[] key, byte[] iv, CipherMode mode) {
        this.key = key;
        this.iv = iv;
        this.mode = mode;
    }

    public byte[] getKey() {
        return key;
    }

    public byte[] getIv() {
        return iv;
    }

    public CipherMode getMode() {
        return mode;
    }

}
