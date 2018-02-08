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
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * @author Julian
 */
public class ClientHandler implements Runnable {

    private boolean connected;
    
    private Socket sock;
    private PrintWriter out;
    private BufferedReader in;
    
    private ChatServer serverReference;
    
    public ClientHandler(Socket sock, ChatServer server) {
        this.sock = sock;
        this.serverReference = server;
        
        try {
            out = new PrintWriter(sock.getOutputStream(), true);
            in = new BufferedReader(new InputStreamReader(sock.getInputStream()));
        } catch (IOException ex) {
            ex.printStackTrace(); // lazily output exceptions
        }
        connected = true;
    }
    
    public void send(String string) {
        // Might need some code here to fix this
        out.println(string);
    }
    
    public void run() {
        String buffer;
        try {
            while ((buffer = in.readLine()) != null) {
                serverReference.registerMessage(this, buffer);
            }
            connected = false;
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            serverReference.removeClient(this);
        }
    }
    
    public String getClientName() {
        return sock.getInetAddress().getHostAddress();// Lazy
    }
    
    public boolean isToBeRemoved() {
        return !connected;
    }

}
