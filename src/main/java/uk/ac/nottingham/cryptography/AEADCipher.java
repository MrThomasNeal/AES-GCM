package uk.ac.nottingham.cryptography;

/**
 * Interface that defines an AEAD cipher. This interface is used
 * extensively for the test suite.
 * <p>
 * Do not edit this interface.
 */
public interface AEADCipher {
    // Init the cipher
    void init(AEADParams params);

    // Add some additional data
    void updateAAD(byte[] data);

    // Processes one block of data, either by encrypting or decrypting
    void processBlock(byte[] data);

    // Finish, return a completed tag
    void finalise(byte[] out);

    // Calculates whether the given tag matches the data seen so far
    void verify(byte[] tag) throws InvalidTagException;
}

