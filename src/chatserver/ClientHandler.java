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
     * Initiates a connection with a client, first exchanging public keys and
     * then adds the client to the server list.
     * @return whether or not the connection was successful
     */
    private boolean initiateClientConnection() {
        String buffer;
        
        try {
            while ((buffer = in.readLine()) != null) {
                
                // Verify that the first message at least appears to be a valid
                // public key according to how the 
                if (!buffer.startsWith(EncryptionHandler.PUBLIC_KEY_PREFIX)) {
                    closeConnection();
                    return false;
                } else {
                    String pubKey = buffer.substring(
                            EncryptionHandler.PUBLIC_KEY_PREFIX.length());
                    try {
                        encHandler.initEncryptionHandler(pubKey);
                    } catch (Exception e) {
                        e.printStackTrace();
                        closeConnection();
                        return false;
                    }
                }
                out.println(encHandler.generatePublicKeyMessage());
                serverReference.addClient(this);
                break;
            }
        } catch (IOException ex) {
            ex.printStackTrace();
            closeConnection();
            return false;
        }
        return true;
    }
    
    
    /***************************************************************************
     * Run the client listener, looping for messages from the client. If the
     * client disconnects gracefully or in a non-graceful manner, the client
     * is removed from the server client list.
     */
    private void runClientListener() {
        
        String buffer;
        
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
     * The main bulk of code for the program thread. Will first exchange public
     * keys with the client, and then begin looping for input from the client.
     */
    @Override
    public void run() {
        
        // Handle dealing with connecting a client
        boolean connectionSuccessful = initiateClientConnection();
        
        if (connectionSuccessful) {
            runClientListener();
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
