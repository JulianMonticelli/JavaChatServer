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
    
    public void send(String string) {
        out.println(encHandler.encryptMessage(string));
    }
    
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
                serverReference.registerMessage(this, encHandler.decryptMessage(buffer));
            }
        } catch (IOException e) {
            System.out.println("An IOException occurred while handling client "
                + getClientName());
        } finally {
            closeConnection();
        }
    }
    
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
    
    public String getClientName() {
        return sock.getInetAddress().getHostAddress(); // Lazy
    }
    

}
