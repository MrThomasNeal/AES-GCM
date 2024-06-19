package uk.ac.nottingham.cryptography;

import uk.ac.nottingham.cryptography.aes.AES128Encryptor;
import uk.ac.nottingham.cryptography.aes.AES128EncryptorImpl;
import uk.ac.nottingham.cryptography.galois.GF128Multiplier;
import uk.ac.nottingham.cryptography.galois.GF128MultiplierImpl;

import java.nio.ByteBuffer;
import java.util.Arrays;

/**
 * Implementation of AEADCipher that encrypts using AES and calculates
 * a tag using GCM.
 * <p>
 * This class is the primary code file in which you can complete your
 * solution to the coursework.
 */
public class AESGCM implements AEADCipher {

    private final GF128Multiplier GF; // Galois Field (size 128) Multiplier
    private final AES128Encryptor encryptor; // AES cipher for encryption and decryption
    private byte[] tag; // Authentication tag used in the AES-GCM cipher
    private byte[] counter; // Counter block used for AES-GCM
    private byte[] additionalMask; // Addition block used in final step of AES-GCM
    private int ciphertextLength; // Length of the total provided ciphertext
    private int AADLength; // Length of the total provided AAD
    CipherMode mode; // Mode of operation for AES-GCM cipher (encryption/decryption)

    public AESGCM() {
        // Initialise AES and GF128 multiplier objects
        GF = new GF128MultiplierImpl();
        encryptor = new AES128EncryptorImpl();
    }

    @Override
    public void init(AEADParams params) {

        // Extract the key, IV, and mode from the parameter
        byte[] key = params.getKey();
        byte[] iv = params.getIv();
        mode = params.getMode();

        // Initialise AADLength and Ciphertext to 0
        AADLength = 0;
        ciphertextLength = 0;

        // IV concatenated to a 16 byte array (128 bits)
        counter = new byte[16];
        System.arraycopy(iv, 0, counter, 0, iv.length);

        // Increment the array by 1 to start it at 1
        incrementCounter();

        // Initialise the encryptor with a key
        encryptor.init(key);

        // Additional mask applied to final tag
        additionalMask = new byte[16];
        encryptor.encryptBlock(counter, additionalMask);

        // All zero block encrypted to produce hash key H
        byte[] H = new byte[16];
        encryptor.encryptBlock(H, H);
        GF.init(H);

        // Set the initial tag (all zeros)
        tag = new byte[16];

    }

    @Override
    public void updateAAD(byte[] data) {

        // XOR the AAD with the tag and multiply the tag by H
        xorWithTagAndMultiplyByH(data);

        // Update the current length of the AAD
        AADLength += (data.length * 8);
    }

    @Override
    public void processBlock(byte[] data) {

        if (mode == CipherMode.ENCRYPT) {

            // Counter is incremented
            incrementCounter();

            // Encrypt the counter and XOR it with the plaintext to produce ciphertext
            encryptCounterAndXORWithText(data);

            // Track the bit length of the ciphertext for concatenation
            ciphertextLength += data.length * 8;

            // XOR ciphertext with tag and multiply by H
            xorWithTagAndMultiplyByH(data);

        } else if (mode == CipherMode.DECRYPT) {

            // XOR the ciphertext with the tag and multiply by H
            xorWithTagAndMultiplyByH(data);

            // counter is incremented
            incrementCounter();

            // Encrypt the counter and XOR it with the ciphertext to produce plaintext
            encryptCounterAndXORWithText(data);

            // Track the bit length of the ciphertext for concatenation
            ciphertextLength += data.length * 8;

        }
    }

    @Override
    public void finalise(byte[] out) {

        // Convert AADLength into a 64-bit byte array
        ByteBuffer buffer1 = ByteBuffer.allocate(Long.BYTES);
        buffer1.putLong(AADLength);
        byte[] byteArray1 = buffer1.array();

        // Convert ciphertext into a 64-bit byte array
        ByteBuffer buffer2 = ByteBuffer.allocate(Long.BYTES);
        buffer2.putLong(ciphertextLength);
        byte[] byteArray2 = buffer2.array();

        // Concatenate the two byte arrays into a single 128-bit byte array
        byte[] concatenatedArray = new byte[byteArray1.length + byteArray2.length];
        System.arraycopy(byteArray1, 0, concatenatedArray, 0, byteArray1.length);
        System.arraycopy(byteArray2, 0, concatenatedArray, byteArray1.length, byteArray2.length);

        // Concatenated data XOR with tag and then multiplied by H
        xorWithTagAndMultiplyByH(concatenatedArray);

        // XOR Tag with initial mask to produce final tag, T
        byte[] T = additionalMask;
        for (int i = 0; i < tag.length; i++) {
            T[i] ^= tag[i];
        }

        // Copy the final tag (T) into the passed in parameter
        System.arraycopy(T, 0, out, 0, T.length);

    }

    @Override
    public void verify(byte[] tag) throws InvalidTagException {

        // Calculate final tag and hold it in temporary array
        byte[] holdArray = new byte[16];
        finalise(holdArray);

        // Compare expected tag with produced tag from cipher
        if (!Arrays.equals(holdArray, tag)) {
            // Throw exception if tags do not match
            throw new InvalidTagException("Tags do not match!");
        }
    }

    private void incrementCounter() {

        // Extract the 4-byte position of the counter byte array starting from
        // index 12 and convert it to integer
        int value = ByteBuffer.wrap(counter, 12, 4).getInt();

        // Increment the integer
        value++;

        // Turn the integer back into the same 4-byte portion of the counter
        ByteBuffer.wrap(counter, 12, 4).putInt(value);
    }

    private void xorWithTagAndMultiplyByH(byte[] data) {

        // Determine the minimum length between data and tag
        int length = Math.min(data.length, tag.length);

        // XOR the tag with the passed in data
        for (int i = 0; i < tag.length; i++) {
            if (i < length) {
                tag[i] ^= data[i]; // XOR data if within the length of data
            } else {
                tag[i] ^= 0; // XOR with 0 if beyond the length of data
            }
        }

        // Multiply the tag by H
        GF.multiplyByH(tag);
    }

    private void encryptCounterAndXORWithText(byte[] data) {

        // Counter is encrypted and locally stored
        byte[] temp = new byte[16];
        encryptor.encryptBlock(counter, temp);

        // XOR counter with data parameter in-place
        for (int i = 0; i < data.length; i++) {
            data[i] ^= temp[i];
        }
    }
}
