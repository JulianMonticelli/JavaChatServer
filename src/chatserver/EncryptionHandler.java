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
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;

import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;


public class EncryptionHandler {
    
    public static final int KEY_SIZE = 2048;
    public static final String ENC_ALG = "RSA";

    Cipher encryptionCipher;
    Cipher decryptionCipher;
    
    KeyPair keyPair;
    
    PrivateKey serverPrivateKey;
    PublicKey serverPublicKey;
    
    PublicKey clientPublicKey;
    
    public EncryptionHandler() {
        keyPair = generateNewKeyPair();
        
        serverPrivateKey = keyPair.getPrivate();
        serverPublicKey = keyPair.getPublic();
    }
    
    private void setPublicKey(String publicKey) throws NoSuchAlgorithmException,
            InvalidKeySpecException
    {
        clientPublicKey = getPublicKey(Base64.getDecoder().decode(publicKey));
    }
    
    private PublicKey getPublicKey(byte[] encodedKey) throws NoSuchAlgorithmException, InvalidKeySpecException
    {
        KeyFactory factory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec encodedKeySpec = new X509EncodedKeySpec(encodedKey);
        return factory.generatePublic(encodedKeySpec);
    }
    
    public void initEncryptionHandler(String clientKey) throws NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException, InvalidKeySpecException {
        setPublicKey(clientKey);
        
        encryptionCipher = Cipher.getInstance(ENC_ALG);
        encryptionCipher.init(Cipher.ENCRYPT_MODE, clientPublicKey);

        decryptionCipher = Cipher.getInstance(ENC_ALG);
        decryptionCipher.init(Cipher.DECRYPT_MODE, serverPrivateKey);
        
    }
    
    public String generatePublicKeyMessage() {
        return "!!PUBK:" + new String(Base64.getEncoder().encode(serverPublicKey.getEncoded()));
    }
    
    public KeyPair generateNewKeyPair() {
        KeyPairGenerator keyPairGenerator = null;
        try {
            keyPairGenerator = KeyPairGenerator.getInstance(ENC_ALG);
        } catch (NoSuchAlgorithmException ex) {
            ex.printStackTrace();
            System.exit(-1);
        }
        keyPairGenerator.initialize(KEY_SIZE);
        return keyPairGenerator.genKeyPair();
    }
    
    public byte[] encrypt(String message) {
        try {
            return encryptionCipher.doFinal(message.getBytes());
        } catch (IllegalBlockSizeException ex) {
            ex.printStackTrace();
        } catch (BadPaddingException ex) {
            ex.printStackTrace();
        }
        return null;
    }
    
    public String encryptMessage(String message) {
        byte[] encryptedData = encrypt(message);
        return new String(Base64.getEncoder().encode(encryptedData));
    }
    
    public byte[] decrypt(byte[] encrypted) {
        try {
            return decryptionCipher.doFinal(encrypted);
        } catch (IllegalBlockSizeException ex) {
            ex.printStackTrace();
        } catch (BadPaddingException ex) {
            ex.printStackTrace();
        }
        return null;
    }
    
    public String decryptMessage(String encrypted) {
        byte[] decryptedData = decrypt(Base64.getDecoder().decode(encrypted));
        if (decryptedData != null) {
            return new String(decryptedData);
        }
        return null;
    }
    
}
