package uk.ac.nottingham.cryptography;

public class Main {

    /**
     * Entry point when this program is run directly. Not used within
     * the coursework, but is available for those who would like to
     * test or debug themselves. Nothing in this file will be marked.
     *
     * @param args Command line arguments - not used in this coursework
     */
    public static void main(String[] args) {
        // Create cipher
        AEADCipher cipher = new AESGCM();

        // Initialise with zero key and simple iv for encryption
        byte[] iv = new byte[12];
        for (int i = 0; i < iv.length; i++) {
            iv[i] = (byte)i;
        }

        cipher.init(new AEADParams(new byte[16], iv, CipherMode.ENCRYPT));

        // Submit one block of AAD and encrypt one block
        cipher.updateAAD(new byte[16]);
        cipher.processBlock(new byte[16]);

        // Finalise and obtain example tag
        byte[] tag = new byte[16];
        cipher.finalise(tag);

    }

}
