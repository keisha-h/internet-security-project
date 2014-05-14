package com.keishaheeralal.networking.symmetric;

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
 * Client class receives the keys from the Server when it connects. It then uses these keys
 * to encrypt and decrypt messages to and from the Server.
 * The string "END" would close the Client's connection.
 * 
 */

import java.awt.image.BufferedImage;
import java.io.*;
import java.net.*;
import java.io.ByteArrayInputStream;
import javax.imageio.ImageIO;

import com.keishaheeralal.cryptography.Cryptography;
import com.keishaheeralal.watermarking.LeastSignificantBit;
import java.util.Arrays;

public class Client {
    
    public static void main(String[] args)
            throws IOException {
        
        try {//try opening a connection with the server
            String clientRequest = "", encryptRequest = "", decryptResponse = "", serverResponse = "", end = "END";
                    
            InetAddress address = InetAddress.getByName("localhost");
            //InetAddress address = InetAddress.getByName(args[0]);

            System.out.println("Started Client with address: " + address);

            Socket clientSocket = new Socket(address, Server.PORT);
            
            BufferedReader inFromUser =
                        new BufferedReader(
                        new InputStreamReader(System.in)); //takes an input from the user
         
            char[] enigma = Cryptography.getSymbols();
            int m = enigma.length;
                        
            try {
                
                 //get the key from the image being sent
                BufferedImage img = ImageIO.read(clientSocket.getInputStream());
                                 
                int[] a_b = LeastSignificantBit.decodeImage(img);
                int inverse = Cryptography.multiplicativeInverse(a_b[0], m);
                            
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
                
                // read message from server that represents the end of the image and throw it away
                serverResponse = inFromServer.readLine();
                
                System.out.println("CLIENT SAYS: Received keys... Let's start!!!");
                encryptRequest = Cryptography.encryptStringAffine("Received keys", enigma, a_b[0], a_b[1], m);
                outToServer.println(encryptRequest);
                                
                serverResponse = inFromServer.readLine();//reading the Server's response to the message sent
                
                decryptResponse = Cryptography.decryptStringAffine(serverResponse, enigma, a_b[0], a_b[1], m, inverse);
                System.out.println("SERVER SAYS: " + decryptResponse + "\n");
                
                System.out.println("Please enter 'END' when finished...");
                
                //reading the Client's input
                clientRequest = inFromUser.readLine();
                
                while ((clientRequest.toUpperCase()).compareTo(end) != 0) {//keep reading the user's input until they are ready to close
                    
                    //encrypt message with Server's key before sending it
                    encryptRequest = Cryptography.encryptStringAffine(clientRequest, enigma, a_b[0], a_b[1], m);
                    
                    outToServer.println(encryptRequest);//sending encrypted message from the Client to the Server
                    
                    serverResponse = inFromServer.readLine();//reading the Server's response to the message sent
                    
                    //decrypt message with Cilent's private key before printing it
                    decryptResponse = Cryptography.decryptStringAffine(serverResponse, enigma, a_b[0], a_b[1], m, inverse);
                    System.out.println("SERVER SAYS: " + decryptResponse + "\n");
                                                                           
                    clientRequest = inFromUser.readLine();
                }
                
                encryptRequest = Cryptography.encryptStringAffine(clientRequest.toLowerCase(), enigma, a_b[0], a_b[1], m);
                outToServer.println(encryptRequest);//sending input from the client to the server
                
                System.out.println("SERVER SAYS: Good Bye...\n");
                
                System.out.println("CLIENT SAYS: Closing Client... \n");//user entered 'END'
                
                outToServer.close();
                inFromUser.close();
                inFromServer.close();
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
