package uk.ac.nottingham.cryptography;

/**
 * Exception representing an incorrect tag following decryption.
 * <p>
 * After an AEAD cipher has performed decryption, verification
 * can be performed to check whether the calculated tag matches
 * the original one. This exception can be raised to signal that
 * there is an error with the tag
 * <p>
 * Do not edit this class.
 */
public class InvalidTagException extends Exception {

    public InvalidTagException() { }

    public InvalidTagException(String message)
    {
        super(message);
    }
}
