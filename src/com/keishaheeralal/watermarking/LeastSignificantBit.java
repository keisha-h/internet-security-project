/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.keishaheeralal.watermarking;

import com.keishaheeralal.cryptography.Cryptography;

import java.awt.Color;
import java.awt.image.*;
import java.io.*;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.imageio.*;

/**
 *
 * @author Keisha
 */

public class LeastSignificantBit {
    
    private static final String imagePath = "src/com/keishaheeralal/watermarking/images/";
      
    public static String chooseImage() {
        /* chooses either image or text as it medium for passing a and b */
        
        SecureRandom r = new SecureRandom();
        int pos = r.nextInt(6) + 1;
        
        return Integer.toString(pos);
    }
    
    private static int[] convertToBinary(int x, int n) {
        /* takes a number and converts it to its 8-bit rep 
         * with the lsb in the 1st position
         */
        
        int[] bin = new int[n]; 
        
        for(int i=0; i<n; i++) {
             if ((x & 1 << i )> 0) {
                 bin[i] = 1;
             }
             else {
                 bin[i] = 0;
             }
         }
        
        return bin;
    }
    
    private static int convertToDigit(int[] bin, int n) {
        /* converts the binary array to a digit */
        
        int sum = 0, t;
        
        for(int i=0; i<n; i++){
            if(bin[i] == 1){
                t = Cryptography.power(2, i);
            } else {
                t = 0;
            }
          
            sum += t;
        }
        
        return sum;
    }
    
    private static int[] copyBits(int[] a, int[] b){
        /* takes the bits for each number and copies them to a new array */
        
        int[] a_b = new int[(a.length + b.length)];
        int i;
                    
        for (i=0; i<a.length; i++) {
            a_b[i] = a[i];
        }
        
        for (; i<(a.length + b.length); i++) {
            a_b[i] = b[i - 8];
        }
        
        return a_b;
    }
    
    public static BufferedImage encodeImage(String filename, int[] primes) {
        /* encodes a and b in the image using a sequence.
         * We are assuming that the image would be big enough
         * to hold the 16 bits 
         */
        
        BufferedImage img, newimg = null;
        int[] a = convertToBinary(primes[0], 8);
        int[] b = convertToBinary(primes[1], 8);
        int[] a_b = copyBits(a, b);//copy all bits into one array
        
        try {
            img = ImageIO.read(new File(imagePath + filename));
            for (int i = 0; i < a_b.length; i++) {
                int p = img.getRGB(i, i);
                int[] bin = convertToBinary(p, 32);
                bin[0] = a_b[i];
                int d = convertToDigit(bin, 32);
                img.setRGB(i, i, d);
            }
            ImageIO.write(img, "png", new File(imagePath + "new_" + filename));
            newimg = ImageIO.read(new File(imagePath + "new_" + filename));
        } catch (IOException e) {
            System.out.println("ERROR WRITING IMAGE...\n" + e.toString());
            System.exit(1);
        }

        return newimg;
    }

    public static int[] decodeImage(BufferedImage img) {
        /* finds the hidden values in the text file */

        int[] a_b, a, b;
        a = new int[8];
        b = new int[8];
        a_b = new int[2];
        int i;

        for (i = 0; i < a.length; i++) {
            int p = img.getRGB(i, i);
            int[] bin = convertToBinary(p, 32);
            a[i] = bin[0];
        }

        for (; i < (a.length + b.length); i++) {
            int p = img.getRGB(i, i);
            int[] bin = convertToBinary(p, 32);
            b[i - b.length] = bin[0];
        }

        a_b[0] = convertToDigit(a, 8);
        a_b[1] = convertToDigit(b, 8);

        return a_b;
    }

    public static void main(String[] args) throws IOException{
        
    }
    
}
