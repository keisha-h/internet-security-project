package com.keishaheeralal.networking.asymmetric;

/*
 * HOW TO RUN CODE: Right Click class then select Run File or Shift+F6.
 * 
 * Server class sends his public key to the Client when it is requested. It also 
 * requests the Client's public key when....
 * 
 */

import java.io.*;
import java.net.*;

import com.keishaheeralal.cryptography.Cryptography;
import java.util.Arrays;

public class Server {

    public static final int PORT = 8080, lower = 1000, upper = 100000;

    public static void main(String[] args) throws IOException {

        try {

            String clientSentence = "", clientResponse = "", serverResponse = "", 
                    end = "END", requeststring = "Requesting your key", start = "START";
            long[][] keys = Cryptography.RSA(lower, upper);
            long[] serverPublicKey = keys[0];
            long[] serverPrivateKey = keys[1];
            long[] clientPublicKey = new long[2];
            
            ServerSocket serverSocket = new ServerSocket(PORT);
            System.out.println("Server started ...");

            try {

                Socket connectionSocket = serverSocket.accept();

                try {

                    System.out.println("Connection accepted: " + connectionSocket);

                    //to read the Client's request
                    BufferedReader inFromClient =
                            new BufferedReader(new InputStreamReader(connectionSocket.getInputStream()));

                    PrintWriter outToClient =
                            new PrintWriter(
                            new BufferedWriter(
                            new OutputStreamWriter(
                            connectionSocket.getOutputStream())), true);

                    clientSentence = inFromClient.readLine();
                    
                    if ((clientSentence.toLowerCase()).compareTo(requeststring.toLowerCase()) == 0) {//Client requested his key

                        outToClient.println("Sending key...");

                        //converting the key values to a string to send over the connection
                        String e = String.valueOf(serverPublicKey[0]);
                        String n = String.valueOf(serverPublicKey[1]);
                        outToClient.println(e + " " + n);//send the key

                        clientSentence = inFromClient.readLine();
                        System.out.println("CLIENT SAYS: " + clientSentence + "\n");
                        outToClient.println("Message '" + clientSentence + "' was received...");
                    }
                    
                    clientSentence = inFromClient.readLine();
                                
                    if ((clientSentence.toLowerCase()).compareTo(start.toLowerCase()) == 0) {
                        
                        System.out.println("Client wants to start communicating...\n");
                        
                        outToClient.println(requeststring);//requesting the public key from the Client after the Client received his

                        //get the key
                        clientSentence = inFromClient.readLine();
                        System.out.println("CLIENT SAYS: " + clientSentence + "\n");

                        //taking the key values and converting it to be used
                        clientSentence = inFromClient.readLine();
                        String[] ckey = clientSentence.split("\\s");
                        clientPublicKey[0] = Long.parseLong(ckey[0]);
                        clientPublicKey[1] = Long.parseLong(ckey[1]);

                        System.out.println("SERVER SAYS: Received keys...\n");
                        serverResponse = Cryptography.encryptString("Received keys. We can now start communicating securely!!!", clientPublicKey[0], clientPublicKey[1]);
                        outToClient.println(serverResponse);

                    }
                                  
                    clientSentence = inFromClient.readLine();
                    clientResponse = Cryptography.decryptString(clientSentence, serverPrivateKey[0], serverPrivateKey[1]);
                                        
                    while (clientResponse.compareTo(end) != 0) {
                        
                        System.out.println("CLIENT SAYS: " + clientResponse + "\n");
                        
                        //encrypt Server's message with Client's public key
                        String r = "Message '" + clientResponse + "' was received...";
                        serverResponse = Cryptography.encryptString(r, clientPublicKey[0], clientPublicKey[1]);
                        outToClient.println(serverResponse);
                        
                        clientSentence = inFromClient.readLine();
                        
                        //decrypt Client's message with Server's private key
                        clientResponse = Cryptography.decryptString(clientSentence, serverPrivateKey[0], serverPrivateKey[1]);

                    }

                    System.out.println("CLIENT SAYS: Good Bye...");

                    System.out.println("SERVER SAYS: Closing Server...");
                    connectionSocket.close();

                } catch (IOException e) {//catching the error when trying to read the first line 
                    System.out.println("SERVER SAYS: ERROR READING LINE..." + e.toString());
                    System.exit(1);
                }

            } catch (IOException e) {//catching any exceptions with opening connection with server
                System.out.println("SERVER SAYS: ERROR ACCEPTING CLIENT...\n" + e.toString());
                System.exit(1);
            }
            serverSocket.close();
        } catch (IOException e) {//catching any exceptions with opening connection with server
            System.out.println("SERVER SAYS: ERROR STARTING SERVER...\n" + e.toString());
            System.exit(1);
        }
    }
}
