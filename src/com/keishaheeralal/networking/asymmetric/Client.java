package com.keishaheeralal.networking.asymmetric;

/*
 * HOW TO RUN CODE: This code was written in NetBeans and should be executed in
 * NetBeans also. To pass arguments in the code, one must navigate to 'File ->
 * Project Properties -> Run (one the right hand side) -> Arguments (left hand side)
 * and enter localhost then select 'OK'. Navigate to Run (menu bar) -> Run Main Project
 * or F6.
 * 
 * OR
 * 
 * Uncomment the line InetAddress address = InetAddress.getByName("localhost"); and 
 * Right Click class then select Run File or Shift+F6.
 * 
 * Client class sends his public key to the AsymmetricServer when it is requested. It also 
 * requests the AsymmetricServer's public key when a user types "Requesting your key..."
 * The string "END" would close the Client's connection.
 * 
 */

import java.io.*;
import java.net.*;

import com.keishaheeralal.cryptography.Cryptography;
import java.util.Arrays;

public class Client {
    
    public static final int lower = 1000, upper = 100000;

    public static void main(String[] args)
            throws IOException {
        
        try {//try opening a connection with the server
            String clientRequest = "", encryptRequest = "", decryptResponse = "", serverResponse = "", 
                    keyrequest = "Requesting your key", end = "END", start = "START", keysent = "Sending keys...";
            
            long[][] keys = Cryptography.RSA(lower, upper);
            long[] clientPublicKey = keys[0];
            long[] clientPrivateKey = keys[1];
            long[] serverPublicKey = new long[2];
            
            //InetAddress address = InetAddress.getByName(args[0]);
            InetAddress address = InetAddress.getByName("localhost");

            System.out.println("Started Client with address: " + address);

            Socket clientSocket = new Socket(address, Server.PORT);
            
            BufferedReader inFromUser =
                        new BufferedReader(
                        new InputStreamReader(System.in)); //takes an input from the user
         
            try {
                
                //to write to the Server
                
                PrintWriter outToServer =
                 new PrintWriter(
                 new BufferedWriter(
                 new OutputStreamWriter(
                 clientSocket.getOutputStream())), true);
                
                //to read from the Server
                
                BufferedReader inFromServer = 
                        new BufferedReader(new
                        InputStreamReader(clientSocket.getInputStream()));
                
                //before any communication starts, the Client and Server must exchange keys
                
                outToServer.println("Requesting your key");
                
                //get the key
                serverResponse = inFromServer.readLine();
                System.out.println("SERVER SAYS: " + serverResponse + "\n");

                //reading the string sent and retrieving the key values separated by a space
                serverResponse = inFromServer.readLine();
                String[] skey = serverResponse.split("\\s");
                serverPublicKey[0] = Long.parseLong(skey[0]);
                serverPublicKey[1] = Long.parseLong(skey[1]);

                System.out.println("CLIENT SAYS: Received keys... ");
                outToServer.println("Received keys");

                serverResponse = inFromServer.readLine();//reading the Server's response to the message sent
                System.out.println("SERVER SAYS: " + serverResponse + "\n");
                
                System.out.println("Please enter 'START' to start...");
                
                clientRequest = inFromUser.readLine();
                
                while((clientRequest.toLowerCase()).compareTo(start.toLowerCase()) != 0) {
                    System.out.println("Please enter 'START' so I can send my keys to the Server...");
                    clientRequest = inFromUser.readLine();
                }
                
                outToServer.println(clientRequest);
                serverResponse = inFromServer.readLine();
                
                //sending Client's key to the Server
                if ((serverResponse.toLowerCase()).compareTo(keyrequest.toLowerCase()) == 0) {
                    
                    outToServer.println("Sending key...");

                    //converting the key values to be sent over the connection
                    String e = String.valueOf(clientPublicKey[0]);
                    String n = String.valueOf(clientPublicKey[1]);
                    outToServer.println(e + " " + n);//send the key

                    serverResponse = inFromServer.readLine();
                    decryptResponse = Cryptography.decryptString(serverResponse, clientPrivateKey[0], clientPrivateKey[1]);
                    System.out.println("\nSERVER SAYS: " + decryptResponse);
                }
                
                System.out.println("Please enter 'END' when finished...");
                
                //reading the Client's input
                clientRequest = inFromUser.readLine();
                
                if(clientRequest == null) System.out.println(clientRequest);
                
                while ((clientRequest.toUpperCase()).compareTo(end) != 0) {//keep reading the user's input until they are ready to close
                    
                    //encrypt message with Server's key before sending it
                    encryptRequest = Cryptography.encryptString(clientRequest, serverPublicKey[0], serverPublicKey[1]);
                    
                    outToServer.println(encryptRequest);//sending encrypted message from the Client to the Server
                    
                    serverResponse = inFromServer.readLine();//reading the Server's response to the message sent
                    
                    //decrypt message with Cilent's private key before printing it
                    decryptResponse = Cryptography.decryptString(serverResponse, clientPrivateKey[0], clientPrivateKey[1]);
                    System.out.println("SERVER SAYS: " + decryptResponse + "\n");
                                                                           
                    clientRequest = inFromUser.readLine();
                }
                
                encryptRequest = Cryptography.encryptString(clientRequest.toUpperCase(), serverPublicKey[0], serverPublicKey[1]);
                outToServer.println(encryptRequest);//sending input from the client to the server
                
                System.out.println("SERVER SAYS: Good Bye...\n");
                
                System.out.println("CLIENT SAYS: Closing Client... \n");//user entered 'END'
                clientSocket.close();

            } catch (IOException e) {//catching the error when trying to read the first line 
                System.out.println("CLIENT SAYS: ERROR READING LINE... \n" + e.toString());
                System.exit(1);
            }  

        } catch (IOException e) {//catching any exceptions with opening connection with server
            System.out.println("CLIENT SAYS: ERROR CONNECTING WITH SERVER...\n" + e.toString());
            System.exit(1);
        }

    }
}
