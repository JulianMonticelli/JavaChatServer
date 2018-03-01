/*
 * This program, if distributed by its author to the public as source code,
 * can be used if credit is given to its author and any project or program
 * released with the source code is released under the same stipulations.
 */

package chatserver;


import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import javax.crypto.BadPaddingException;

import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;


public class EncryptionHandler {
    
    public static final int ASYM_KEY_SIZE = 2048;
    
    public static final int SYM_BLOCK_SIZE = 128;
    
    public static final String ASYM_ENC_ALG = "RSA";
    public static final String SYM_ENC_ALG = "AES";
    
    
    public static final String PUBLIC_KEY_PREFIX = "!!PUBK:";
    
    // Asymmetric Ciphers
    private Cipher encryptionCipher;
    private Cipher decryptionCipher;
    
    // Asymmetric Keypairs
    KeyPair keyPair;
    
    // Asymmetric Public & Private Keys
    PrivateKey nativePrivateKey;
    PublicKey nativePublicKey;
    
    // Foreign Public Key
    PublicKey foreignPublicKey;
    
    
    /***************************************************************************
     * Constructs the encryption handler and generates a native keypair. It is
     * necessary to further initialize the EncryptionHandler manually and prov-
     * ide the public key of a foreign party, so that this EncryptionHandler
     * can be used to communicate with a foreign party.
     */
    public EncryptionHandler() {
        keyPair = generateNewKeyPair();
        nativePrivateKey = keyPair.getPrivate();
        nativePublicKey = keyPair.getPublic();        
        
        
        // The following commented out code allows for performing simple tests
        // inside the class without the need of a client-to-server connection
        /*
        try {
            initEncryptionHandler(nativePublicKey);
        } catch (Exception e) {
            e.printStackTrace();
        }
        */
    }
    
    
    /***************************************************************************
     * Initializes the encryption handler after it has been constructed. This
     * method is necessary, because upon construction of the object, it is not
     * always the case that the foreign party's public key will be available.
     * 
     * Thus, it is necessary to call this method after initially creating the
     * EncryptionHandler argument.
     * @param nativeKey The PublicKey representation of the native key
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws InvalidKeySpecException 
     */
    public void initEncryptionHandler(PublicKey nativeKey) throws NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException, InvalidKeySpecException {
        // Asymmetric setup
        setPublicKey(nativeKey);
        
        encryptionCipher = Cipher.getInstance(ASYM_ENC_ALG);
        encryptionCipher.init(Cipher.ENCRYPT_MODE, foreignPublicKey);

        decryptionCipher = Cipher.getInstance(ASYM_ENC_ALG);
        decryptionCipher.init(Cipher.DECRYPT_MODE, nativePrivateKey);
    }
    
    
    /**************************************************************************/
    //
    // RSA-related methods are below, AES-related methods begin around line 280
    //
    /**************************************************************************/
    
    
    
    /***************************************************************************
     * Initializes the encryption handler after it has been constructed. This
     * method is necessary, because upon construction of the object, it is not
     * always the case that the foreign party's public key will be available.
     * 
     * Thus, it is necessary to call this method after initially creating the
     * EncryptionHandler argument.
     * @param nativeKey The String representation of the native key
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws InvalidKeySpecException 
     */
    public void initEncryptionHandler(String nativeKey) throws NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException, InvalidKeySpecException {
        setPublicKey(nativeKey);
        initEncryptionHandler(foreignPublicKey);
    }
    
    /***************************************************************************
     * Sets the foreign public key of the EncryptionHandler so that data can be
     * sent to the foreign party encrypted via RSA
     * @param publicKey A public key as a PublicKey object
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException 
     */
    private void setPublicKey(PublicKey publicKey) throws NoSuchAlgorithmException,
            InvalidKeySpecException
    {
        foreignPublicKey = publicKey;
    }
    
    /***************************************************************************
     * Sets the foreign public key of the EncryptionHandler so that data can be
     * sent to the foreign party encrypted via RSA
     * @param publicKey A public key in String format
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException 
     */
    private void setPublicKey(String publicKey) throws NoSuchAlgorithmException,
            InvalidKeySpecException
    {
        foreignPublicKey = getPublicKey(Base64.getDecoder().decode(publicKey));
    }
    
    /***************************************************************************
     * Returns a PublicKey object from a byte array which contains the RSA key
     * @param binaryKey The public key in a byte array
     * @return PublicKey object representation of the public key
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException 
     */
    private PublicKey getPublicKey(byte[] binaryKey) throws NoSuchAlgorithmException,
            InvalidKeySpecException
    {
        KeyFactory factory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec encodedKeySpec = new X509EncodedKeySpec(binaryKey);
        return factory.generatePublic(encodedKeySpec);
    }
    
    
    /***************************************************************************
     * Generates a textual representation of the public key, prefixed by a 
     * String that is defined statically in the EncryptionHandler.
     * @return a String representation of the key prepended with a pre-defined
     * prefix
     */
    public String generatePublicKeyMessage() {
        return PUBLIC_KEY_PREFIX + 
                new String(Base64.getEncoder().encode(nativePublicKey.getEncoded()));
    }
    
    
    /***************************************************************************
     * Generates a new key pair and returns it
     * @return The KeyPair that was randomly generated
     */
    public KeyPair generateNewKeyPair() {
        KeyPairGenerator keyPairGenerator = null;
        try {
            keyPairGenerator = KeyPairGenerator.getInstance(ASYM_ENC_ALG);
        } catch (NoSuchAlgorithmException ex) {
            ex.printStackTrace();
            System.exit(-1);
        }
        keyPairGenerator.initialize(ASYM_KEY_SIZE);
        return keyPairGenerator.genKeyPair();
    }
    
    /***************************************************************************
     * Encrypts a byte array with RSA and returns the bytes. It should be noted
     * that this can only encrypt a limited amount of data, somewhat smaller
     * than the bit-amount of the RSA algorithm you are using divided by 8. 
     * @param data A byte array to encrypt
     * @return The encrypted byte array
     */
    public byte[] encryptRSA(byte[] data) {
        try {
            return encryptionCipher.doFinal(data);
        } catch (IllegalBlockSizeException ex) {
            ex.printStackTrace();
        } catch (BadPaddingException ex) {
            ex.printStackTrace();
        }
        return null;
    }
    
    /***************************************************************************
     * Encrypts a String with RSA and returns the bytes. It should be noted
     * that this can only encrypt a limited amount of data, somewhat smaller
     * than the bit-amount of the RSA algorithm you are using divided by 8. 
     * @param message A String message to encrypt
     * @return The encrypted byte array
     */
    public byte[] encryptRSA(String message) {
        try {
            return encryptionCipher.doFinal(message.getBytes());
        } catch (IllegalBlockSizeException ex) {
            ex.printStackTrace();
        } catch (BadPaddingException ex) {
            ex.printStackTrace();
        }
        return null;
    }
    
    
    /***************************************************************************
     * Use RSA encryption to encrypt a byte array and return a Base64 String
     * of the encrypted data.
     * @param rawBytes a byte array
     * @return a Base-64 string representation of the encrypted byte array
     */
    public String encryptRSAToB64String(byte[] rawBytes) {
        return new String(Base64.getEncoder().encode(encryptRSA(rawBytes)));
    }
    
    /***************************************************************************
     * Encrypts a String with RSA and returns a new String. It should be noted
     * that this can only encrypt a limited amount of data, somewhat smaller
     * than the bit-amount of the RSA algorithm you are using divided by 8. 
     * @param message A String message to encrypt
     * @return A string containing the encrypted message
     */
    public String encryptMessageRSA(String message) {
        byte[] encryptedData = encryptRSA(message);
        return new String(Base64.getEncoder().encode(encryptedData));
    }
    
    /***************************************************************************
     * Decrypts a byte array with RSA and returns the decrypted byte array.
     * It should be noted that this can only decrypt a limited amount of data,
     * somewhat smaller than the bit-amount of the RSA algorithm you are using
     * divided by 8. 
     * @param encrypted A byte array to decrypt
     * @return The decrypted byte array
     */
    public byte[] decryptRSA(byte[] encrypted) {
        try {
            return decryptionCipher.doFinal(encrypted);
        } catch (IllegalBlockSizeException ex) {
            ex.printStackTrace();
        } catch (BadPaddingException ex) {
            ex.printStackTrace();
        }
        return null;
    }
    
    
    /***************************************************************************
     * Decrypts a String with RSA and returns the decrypted byte array.
     * It should be noted that this can only decrypt a limited amount of data,
     * somewhat smaller than the bit-amount of the RSA algorithm you are using
     * divided by 8. 
     * @param message A String to decrypt
     * @return The decrypted byte array
     */
    @Deprecated
    public byte[] decryptRSA(String message) {
        return decryptRSA(Base64.getDecoder().decode(message));
    }
    
    /***************************************************************************
     * Decrypts a String with RSA and returns the decrypted String.
     * It should be noted that this can only decrypt a limited amount of data,
     * somewhat smaller than the bit-amount of the RSA algorithm you are using
     * divided by 8. 
     * @param message A String to decrypt
     * @return The decrypted String
     */
    public String decryptMessageRSA(String encrypted) {
        byte[] decryptedData = decryptRSA(Base64.getDecoder().decode(encrypted));
        if (decryptedData != null) {
            return new String(decryptedData);
        }
        return null;
    }
    
    
    
    /**************************************************************************/
    //
    // AES-related methods are below
    //
    /**************************************************************************/
    
    
    
    /***************************************************************************
     * Get a new random symmetric key as a byte array
     * @return 
     */
    public static byte[] getNewAESKey() {
        KeyGenerator keyGen = null;
        try {
            keyGen = KeyGenerator.getInstance(SYM_ENC_ALG);
        } catch (NoSuchAlgorithmException ex) {
            ex.printStackTrace();
            System.exit(-1);
        }
        keyGen.init(SYM_BLOCK_SIZE);
        SecretKey secretKey = keyGen.generateKey();
        return Base64.getEncoder().encode(secretKey.getEncoded());
    }
    
    /***************************************************************************
     * Provided a symmetric key byte array, return a SecretKey object of the
     * byte array of the key
     * @param encodedKey an AES key as a byte array
     * @return an AES SecretKey object
     */
    public SecretKey getSecretKeyAES(byte[] encodedKey) {
        byte[] key = Base64.getDecoder().decode(encodedKey);
        return new SecretKeySpec(key, 0, key.length, SYM_ENC_ALG);
    }
    
    /***************************************************************************
     * Provided a byte array key and data in the form of a byte array, encrypt
     * the data using the selected symmetric algorithm. Returns a Base64 byte
     * array.
     * @param key the symmetric key as a byte array
     * @param data the data to be encrypted as a byte array
     * @return a byte array of the encrypted data in Base64
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException 
     */
    public byte[] encryptAES(byte[] key, byte[] data) throws 
            NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException {
        Cipher symmetricEncrypt = Cipher.getInstance(SYM_ENC_ALG);
        symmetricEncrypt.init(Cipher.ENCRYPT_MODE, getSecretKeyAES(key));
        byte[] encrypted = symmetricEncrypt.doFinal(data);
        return Base64.getEncoder().encode(encrypted);
    }
    
    /***************************************************************************
     * Provided a byte array key and data in the form of a byte array, encrypt
     * the data using the selected symmetric algorithm. Returns a Base64 String.
     * @param key the symmetric key as a byte array
     * @param data the data to be encrypted as a byte array
     * @return a Base64 String of the encrypted data
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException 
     */
    public String encryptMessageAES(byte[] key, byte[] data) throws 
            NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException {
        return new String(encryptAES(key, data));
    }
    
    /***************************************************************************
     * Provided a byte array key and data in the form of a byte array, decrypt
     * the data using the selected symmetric algorithm. Returns a byte array
     * of the decrypted data.
     * @param key the symmetric key as a byte array
     * @param data the data to be decrypted as a byte array
     * @return a byte array of the decrypted data
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException 
     */
    public byte[] decryptAES(byte[] key, byte[] data) throws 
            NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException {
        Cipher symmetricEncrypt = Cipher.getInstance(SYM_ENC_ALG);
        symmetricEncrypt.init(Cipher.DECRYPT_MODE, getSecretKeyAES(key));
        byte[] decrypted = symmetricEncrypt.doFinal(Base64.getDecoder().decode(data));
        return decrypted;
    }
    
    
    /***************************************************************************
     * Provided a byte array key and data in the form of a byte array, decrypt
     * the data using the selected symmetric algorithm. Returns a String.
     * @param key the symmetric key as a byte array
     * @param data the data to be decrypted as a byte array
     * @return a String of the decrypted data
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException 
     */
    public String decryptMessageAES(byte[] key, byte[] data) throws 
            NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException {
        return new String(decryptAES(key, data));
    }
    
    
    /***************************************************************************
     * Encodes a message such that it provides an 
     * @param key
     * @param message
     * @return
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException 
     */
    public String encodeMessage(byte[] key, String message)  throws 
            NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException {
        StringBuilder sb = new StringBuilder();
        String keyString = encryptRSAToB64String(key);
        char keySize = (char)keyString.length();
        sb.append(keySize);
        sb.append(keyString);
        sb.append(encryptMessageAES(key, message.getBytes()));
        return sb.toString();
    }
    
    /***************************************************************************
     * Takes a message which is expected to be in the format of an asymmetric-
     * ally encrypted symmetric key followed immediately by a symmetrically
     * encrypted message.
     * @param message
     * @return 
     */
    public String decipherMessage(String message) throws 
            NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException {
        
        int keyLength = ((int)message.charAt(0));
        
        String encryptedKey = message.substring(1, keyLength + 1);
        String encryptedMessage = message.substring(keyLength + 1);
        
        byte[] key = decryptRSA(encryptedKey);
        return decryptMessageAES(key, encryptedMessage.getBytes());
    }
     
    
    /***************************************************************************
     * A simple test of the hybrid encryption scheme
     * @param args Nothing
     */
    /*
    public static void main(String[] args) {
        String message = "This is a test message";
        
        // assumes that initEncryptionHandler() is called in constructor
        // with native public key - for testing only
        EncryptionHandler encHandler = new EncryptionHandler();
        
        String encoded = null;
        
        String decoded = null;
        
        try {
            encoded = encHandler.encodeMessage(EncryptionHandler.getNewAESKey(), message);
            decoded = encHandler.decipherMessage(encoded);
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        System.out.println(decoded);
    }
    */
}
