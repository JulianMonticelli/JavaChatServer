/*
 * This program, if distributed by its author to the public as source code,
 * can be used if credit is given to its author and any project or program
 * released with the source code is released under the same stipulations.
 */
package chatserver;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Random;

/**
 *
 * @author Julian
 */
public class ChatServer {

    
    private static InetAddress HOST;
    private static final int PORT = 6161;
    
    
    private boolean running = false;
    
    private Random rand = new Random(); // For RNG chat commands
    
    private final List<ClientHandler> clientList;
    
    public ChatServer() {
        try {
            HOST = InetAddress.getLocalHost();
        } catch (UnknownHostException ex) {
            System.err.println("Failed to get local host");
            System.exit(-1);
        }
        
        clientList  = Collections.synchronizedList(new ArrayList<>());
        
        running = true;        
    }
    
    public void run() {
        try (
            ServerSocket sock = new ServerSocket(PORT);
            )
        {
            while (running) {
                Socket newClient = sock.accept();
                ClientHandler client = new ClientHandler(newClient, this);
                addClient(client);
                new Thread(client).start();
            }
        } catch (IOException ex) {
            ex.printStackTrace();
            System.exit(-1);
        }
    }
    
    /***************************************************************************
     * Add a client to the client list
     * @param clientHandler A reference to the ClientHandler we are adding
     */
    private void addClient(ClientHandler clientHandler) {
        
        synchronized(clientList) {
            clientList.add(clientHandler);
        }
        String joinMessage = clientHandler.getClientName() + " has joined"
                    + " the server.";
        
        broadcastMessage(joinMessage);
    }

    /***************************************************************************
     * Remove a client from the client list
     * @param clientHandler A reference to the ClientHandler we are removing
     */
    public void removeClient(ClientHandler clientHandler) {
        synchronized(clientList) {
            clientList.remove(clientHandler);
        }
        String message = clientHandler.getClientName() + " has left the server.";
        broadcastMessage(message);
    }
    
    public void registerMessage(ClientHandler clientHandler, String message) {
        if (message.startsWith("/")) {
            handleClientCommand(clientHandler, message);
        } else {
            broadcastMessageFromClient(clientHandler, message);
        }
    }
    
    /***************************************************************************
     * Handle a client-issued command 
     * @param clientHandler A reference to the ClientHandler issuing the command
     * @param message The entirety of the message that is to be parsed as a 
     * command
     */
    private void handleClientCommand(ClientHandler clientHandler, String message) {
        // Split command into command arguments, where command[0] is the command
        String[] commandArgs = message.substring(1).split("\\s+");
        
        String command = commandArgs[0]; // For easy reading
        
        if (command.equalsIgnoreCase("who")){
            // TODO: Add chat filtering
            StringBuilder sb = new StringBuilder();
            synchronized (clientList) {
                System.out.println(clientHandler.getClientName() + " performed a /who command");
                sb.append("\nOnline users:\n---------------\n\n");
                for (ClientHandler client : clientList) {
                    sb.append(client.getClientName() + "\n");
                }
            }
            clientHandler.send(sb.toString());
        }
        
        else if (command.equalsIgnoreCase("roll")) {
            int minRoll = 1;
            int maxRoll = 100;
            try {
                if (commandArgs.length == 2) {
                    maxRoll = Integer.parseInt(commandArgs[1]);
                } else if (commandArgs.length > 2) {
                    minRoll = Integer.parseInt(commandArgs[1]);
                    maxRoll = Integer.parseInt(commandArgs[2]);
                }
            } catch (NumberFormatException e) {
                clientHandler.send("Roll requires either no arguments, or valid"
                        + " numerical values to operate.");
                return;
            }
            if (minRoll < 0 || maxRoll < 0) {
                clientHandler.send("Roll cannot accept negative integers.");
                return;
            }
            if (minRoll == maxRoll) {
                clientHandler.send("The minimum roll value cannot be the "
                        + "maximum roll value.");
                return;
            }
            // Fix minRoll and maxRoll if necessary
            if (minRoll > maxRoll) {
                int temp = minRoll;
                minRoll = maxRoll;
                maxRoll = temp;
            }
            
            int roll = rand.nextInt(maxRoll) + minRoll;
            
            broadcastMessage(clientHandler.getClientName() + " has rolled a "
                    + roll + " (" + minRoll + "-" + maxRoll + ")");
        }
        
        else if (command.equalsIgnoreCase("flip")) {
            String res = rand.nextBoolean() ? "heads" : "tails";
            broadcastMessage(clientHandler.getClientName() + " has flipped a "
            + res + ".");
        }
        else if (command.equalsIgnoreCase("disconnect")) {
            clientHandler.send("goodbye:)");
        }
    }
    
    /***************************************************************************
     * Broadcast a message to the client list
     * @param message A message to broadcast
     */
    private void broadcastMessage(String message) {
        synchronized (clientList) {
            System.out.println(message);
                clientList.forEach((client) -> {
                client.send(message);
            });
        }
    }
    
    private void broadcastMessageFromClient(ClientHandler clientHandler, 
            String message) {
        String newMessage = clientHandler.getClientName() + ": " + message;
        broadcastMessage(newMessage);
    }
    
    
    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        ChatServer server = new ChatServer();
        server.run();
    }
    
    
    
}
