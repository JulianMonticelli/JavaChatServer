/*
 * This program, if distributed by its author to the public as source code,
 * can be used if credit is given to its author and any project or program
 * released with the source code is released under the same stipulations.
 */

package chatserver;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;


/**
 * @author Julian
 */
public class ClientHandler implements Runnable {
    
    private Socket sock;
    private PrintWriter out;
    private BufferedReader in;
    
    EncryptionHandler encHandler;
    
    private ChatServer serverReference;
    
    public ClientHandler(Socket sock, ChatServer server) {
        this.sock = sock;
        this.serverReference = server;
        
        encHandler = new EncryptionHandler();
        
        try {
            out = new PrintWriter(sock.getOutputStream(), true);
            in = new BufferedReader(new InputStreamReader(sock.getInputStream()));
        } catch (IOException ex) {
            ex.printStackTrace(); // lazily output exceptions
        }
    }
    
    /***************************************************************************
     * Sends a client a message with an RSA-secured symmetric key.
     * @param string A String message to encrypt and send to the client.
     */
    public void send(byte[] key, String string) {
        try {
            out.println(encHandler.encodeMessage(key, string));
        } catch (Exception e) {
            e.printStackTrace();
            closeConnection();
        }
    }
    
    /***************************************************************************
     * A convenience function for encrypting a message to send to the client,
     * and then sending it - this should only be used for SINGLE messages to
     * SINGLE clients. Client broadcast messages should include a key to save
     * the extra overhead of generating n AES keys.
     * @param string A String message to encrypt and send to the client.
     */
    public void send(String string) {
        byte[] key = EncryptionHandler.getNewAESKey();
        try {
            out.println(encHandler.encodeMessage(key, string));
        } catch (Exception e) {
            e.printStackTrace();
            closeConnection();
        }
    }
    
    /***************************************************************************
     * The main bulk of code for the program thread. Will first exchange public
     * keys with the client, and then begin looping for input from the client.
     */
    @Override
    public void run() {
        String buffer;
        
        try {
            while ((buffer = in.readLine()) != null) {
                if (!buffer.startsWith("!!PUBK:")) {
                    closeConnection();
                    return;
                } else {
                    String pubKey = buffer.substring(7);
                    try {
                        encHandler.initEncryptionHandler(pubKey);
                    } catch (Exception e) {
                        e.printStackTrace();
                        closeConnection();
                        return;
                    }
                }
                out.println(encHandler.generatePublicKeyMessage());
                serverReference.addClient(this);
                break;
            }
        } catch (IOException ex) {
            ex.printStackTrace();
            closeConnection();
            return;
        }
        
        try {
            while ((buffer = in.readLine()) != null) {
                try {
                    serverReference.registerMessage(this,
                            encHandler.decipherMessage(buffer));
                } catch (Exception e) {
                    e.printStackTrace();
                    closeConnection();
                }
            }
        } catch (IOException e) {
            System.out.println("An IOException occurred while handling client "
                + getClientName());
        } finally {
            closeConnection();
        }
    }
    
    /***************************************************************************
     * Close the connection of the client who belongs to this thread.
     */
    public void closeConnection() {
        serverReference.removeClient(this);
        out.close();
        try {
            in.close();
        } catch (IOException ex) {
            System.out.println("Some error occurred trying to close a"
                    + " ClientHandler BufferedReader.");
        }
    }
    
    /***************************************************************************
     * Get the String name of the client
     * @return name of the client as a String
     */
    public String getClientName() {
        return sock.getInetAddress().getHostAddress(); // Lazy
    }
    

}
