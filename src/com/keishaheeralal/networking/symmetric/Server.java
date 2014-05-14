package com.keishaheeralal.networking.symmetric;

/*
 * HOW TO RUN CODE: Right Click class then select Run File or Shift+F6.
 * 
 * Server class sends his keys to the Client when it connects.
 * 
 * Uses image to pass along the keys to the Client. The is image it uses is randomly chosen
 * 
 */

import java.awt.image.*;
import java.io.*;
import java.net.*;
import javax.imageio.*;

import com.keishaheeralal.cryptography.Cryptography;
import com.keishaheeralal.watermarking.LeastSignificantBit;
import java.util.Arrays;

public class Server {

    public static final int PORT = 8080;

    public static void main(String[] args) throws IOException {

        try {

            String clientSentence = "", clientResponse = "", serverResponse = "", r = "", end = "END";
            
            ServerSocket serverSocket = new ServerSocket(PORT);
            System.out.println("Server started ...");

            try {

                Socket connectionSocket = serverSocket.accept();
                                
                try {

                    System.out.println("Connection accepted: " + connectionSocket);
                    
                    char[] enigma = Cryptography.getSymbols();
                    int m = enigma.length;
                    
                    int[] a_b = Cryptography.findA_B(enigma.length);//finds the keys a and b
                    int inverse = Cryptography.multiplicativeInverse(a_b[0], m);
                    
                    //retreiving the image
                    
                    String imgnum = LeastSignificantBit.chooseImage();
                    String imgname = "images_" + imgnum + ".png";
                    BufferedImage imageFile = LeastSignificantBit.encodeImage(imgname, a_b);
                    ImageIO.write(imageFile, "png", connectionSocket.getOutputStream());
                   
                    //to read the Client's request
                    BufferedReader inFromClient =
                            new BufferedReader(new InputStreamReader(connectionSocket.getInputStream()));

                    PrintWriter outToClient =
                            new PrintWriter(
                            new BufferedWriter(
                            new OutputStreamWriter(
                            connectionSocket.getOutputStream())), true);
                    
                    // check if anything was in the buffer before we started to use it.
                    outToClient.println();
                
                    clientSentence = inFromClient.readLine();
                    clientResponse = Cryptography.decryptStringAffine(clientSentence, enigma, a_b[0], a_b[1], m, inverse);
                    
                    while (clientResponse.compareTo(end.toLowerCase()) != 0) {
                        
                        System.out.println("CLIENT SAYS: " + clientResponse + "\n");
                        
                        //encrypt Server's message with keys a and b
                        r = "Message '" + clientResponse + "' was received...";
                        
                        serverResponse = Cryptography.encryptStringAffine(r, enigma, a_b[0], a_b[1], m);
                        outToClient.println(serverResponse);
                        
                        clientSentence = inFromClient.readLine();
                        
                        //decrypt Client's message with keys a and b
                        clientResponse = Cryptography.decryptStringAffine(clientSentence, enigma, a_b[0], a_b[1], m, inverse);
                    }

                    System.out.println("CLIENT SAYS: Good Bye...");

                    System.out.println("SERVER SAYS: Closing Server...");
                    
                    inFromClient.close();
                    outToClient.close();
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
