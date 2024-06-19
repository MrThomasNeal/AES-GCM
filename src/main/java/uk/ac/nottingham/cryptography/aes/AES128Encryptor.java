package uk.ac.nottingham.cryptography.aes;

/**
 * Interface representing an implementation of AES
 * encryption.
 * <p>
 * Provides a function to initialise AES using a secret
 * key, and a single encryptBlock function that will
 * encrypt a single block of data, writing the result
 * into the output parameter. No decryption function
 * is provided, as this is not necessary.
 * <p>
 * Do not edit this class.
 */
public interface AES128Encryptor {
    void init(byte[] key);
    void encryptBlock(byte[] input, byte[] output);
}
