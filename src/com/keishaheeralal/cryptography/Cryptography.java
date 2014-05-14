package com.keishaheeralal.cryptography;

/**
 * @(#)Cryptography.java
 *
 *
 * @Keisha
 * @version 1.00 2012/9/24
 * 
 * @Description
 * 
 * Using the RSA algorithm, the server and client should generate a pair of keys. 
 * The public keys should then be given to any machine requesting it.  You are 
 * required to modify the server and client to allow confidential communication 
 * between them using asymmetric communication.
 * 
 */

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.List;

public class Cryptography {

    /**************************** GCD Functions *******************************/

    private static int recursiveGCD(int p, int q) {
        /* determines the GCD of p and q using a recursive algorithm */

        if (q == 0) {
            return p;
        }

        return recursiveGCD(q, p % q);
    }
    
    private static long recursiveGCD(long p, long q) {
        /* determines the GCD of p and q using a recursive algorithm */

        if (q == 0) {
            return p;
        }

        return recursiveGCD(q, p % q);
    }

    /**************************************************************************/
    
    /****************************** Mod Functions *****************************/
    
    private static int[] extendedGCD(int a, int b) {
        /* determines d and k such that ad + bk = 1 */
        
        if (b == 0) {
            return new int[]{a, 1, 0};
        }

        int[] ret = extendedGCD(b, a % b);

        int d = ret[0];
        int x = ret[1];
        int y = ret[2];

        int q = a / b;

        return new int[]{d, y, x - y * q};
    }
    
    private static long[] extendedGCD(long a, long b) {
        /* determines d and k such that ad + bk = 1 */
        
        if (b == 0) {
            return new long[]{a, 1, 0};
        }

        long[] ret = extendedGCD(b, a % b);

        long d = ret[0];
        long x = ret[1];
        long y = ret[2];

        long q = a / b;

        return new long[]{d, y, x - y * q};
    }

    public static int power(int a, int b) {
        /* finds a^b */

        if (b == 0) {
            return 1;
        }

        if (b == 1) {
            return a;
        }

        if (b % 2 == 0) {
            int x = power(a, b / 2);
            return x * x;
        }

        return power(a, b - 1) * a;
    }
    
    private static long power(long a, long b, long n) {
        /* finds a^b mod n */

        if (b == 0) {
            return 1;
        }

        if (b == 1) {
            return a % n;
        }

        if (b % 2 == 0) {
            long x = power(a, b / 2, n);
            return (x * x) % n;
        }

        return (power(a, b - 1, n) * (a % n)) % n;
    }

    /**************************************************************************/
    
    /************************** Prime Functions *******************************/
    
    private static int[] findFactors(int n) {
        /* find m and k such that n-1 = m * 2^k */

        int k = 0;
        int m = n;

        while (m % 2 == 0) {
            k++;
            m = m / 2;
        }

        return new int[]{m, k};
    }

    private static boolean[] sieveOfEratosthenes(int n) {
        /* generates all the primes from 2 to n */

        boolean[] isPrime = new boolean[n + 1];

        Arrays.fill(isPrime, true);

        for (int i = 2; i * i <= n; i++) {
            if (isPrime[i]) {
                for (int j = i * 2; j <= n; j += i) {
                    isPrime[j] = false;
                }
            }
        }

        return isPrime;
    }

    private static int[] primeNumbers(int n) {
        boolean[] isPrime = sieveOfEratosthenes(n);

        List<Integer> primes = new ArrayList<>();
        for (int i = 2; i <= n; i++) {
            if (isPrime[i]) {
                primes.add(i);
            }
        }

        int[] ret = new int[primes.size()];
        for (int i = 0; i < ret.length; i++) {
            ret[i] = primes.get(i);
        }
        return ret;
    }

    private static int[] relativePrimes(int[] primes, long phiN) {
        /* finds all the primes relatively prime to phiN */

        List<Integer> rp = new ArrayList<>();

        for (int i = 0; i < primes.length && primes[i] <= phiN; i++) {
            if (recursiveGCD(phiN, primes[i]) == 1) {
                rp.add(primes[i]);
            }
        }

        int[] ret = new int[rp.size()];
        for (int i = 0; i < ret.length; i++) {
            ret[i] = rp.get(i);
        }

        return ret;
    }

    /**************************************************************************/
    
    /***************************** RSA Functions ******************************/
    
    private static int[] selectPrimes(int[] allprimes, int lower) {
        /* selects 2 primes within a specific range */

        SecureRandom r = new SecureRandom();
        int p = 0, q = 0;
        
        while(allprimes[p] < lower && allprimes[p] < lower) {
        
            p = r.nextInt(allprimes.length);
            q = r.nextInt(allprimes.length);
        }

        int[] prime = new int[2];
        prime[0] = allprimes[p];
        prime[1] = allprimes[q];
        
        return prime;
    }

    private static long findN(int p, int q) {
        /* calculates n = p x q */
        
        return p * q;
    }

    private static int phiN(int p, int q) {
        /* calculates phi(n) */

        int phi_n = (p - 1) * (q - 1);

        return phi_n;
    }

    private static int relativelyPrime(int[] relativeprimes) {
        /* returns a number that is relatively prime to n */ 

        SecureRandom r = new SecureRandom();

        int pos = r.nextInt(relativeprimes.length);
        int e = relativeprimes[pos];

        return e;
    }

    private static long findD(int a, long b) {
        /* finds d such that ed = 1 mod phi(n) */
        
        long[] coeff = extendedGCD(a, b); 
        
        long d = coeff[1];
                
        return d < 0 ? b + d : d;
    }

    private static long[] publicKey(long e, long n) {
        /* returns the public key (e, n) */
        
        long[] key = new long[2];

        key[0] = e;
        key[1] = n;

        return key;
    }

    private static long[] privateKey(long d, long n) {
        /* returns the private key (d, n) */
        
        long[] key = new long[2];

        key[0] = d;
        key[1] = n;

        return key;
    }
    
    public static long[][] RSA(int l, int u) {
        /* pulls all RSA functions together and creates both private and public key */
        
        int[] allprimes = primeNumbers(u);
        
        int[] vals = selectPrimes(allprimes, l);
        
        long n = -1;
        
        while (n < 0) {
            vals = selectPrimes(allprimes, l);
            n = findN(vals[0], vals[1]);
        }
        
        long phi = phiN(vals[0], vals[1]);
        
        int[] relativeprimes = relativePrimes(allprimes, phi);
        
        int e = relativelyPrime(relativeprimes);
        
        long d = findD(e, phi);
        
        return new long[][] {publicKey(e, n),privateKey(d, n)};
    }
    
    /**************************************************************************/
    
    /************************** Conversion Functions **************************/
    
    public static String encryptString(String word, long e, long n){
        /* takes a word, converts each character to an int, 
         * forms a string with those ints and returns a string format of it */
        
        String intword = "";
        char[] chars = word.toCharArray();
        int val;
        long eval;
        
        for(int i=0; i<chars.length; i++) {
             val = (int)chars[i];  
             eval = power(val, e, n);
             intword = intword + Long.toString(eval) + " ";
         }
        
        return intword;
    }
    
    public static String decryptString(String intword, long d, long n){
        /* takes the number rep of each char and forms a word */
        
        String word = "";   
        String[] eachletter = intword.split("\\s");
        int val;
        long eval;
        char t;
        
        for(int i=0; i<eachletter.length; i++) {
            val = Integer.valueOf(eachletter[i]);
            eval = power(val, d, n);
            t = (char)eval;
            word = word + t;
        }
        
        return word;
    }
    
    /**************************************************************************/
    
    /**************************** Affine Functions ****************************/
    
    public static int multiplicativeInverse(int a, int m) {
        int[] inverse;
        
        inverse = extendedGCD(a, m);
        
        return inverse[1] < 0 ? m + inverse[1] : inverse[1];
    }
    
    private static int[] factors(int n) {
        /* finds the factors of n */
        
        int[] f = {0, 0};
                
        for(int i=2; i*i<n; i++) {
            if(n % i == 0){
                f[0] = n / i;
                f[1] = n / f[0];
                break;
            }
        }
        
        return f;
    } 
    
    public static long EulersMultiplicativeInverse(int a, int n) {
        /* finds the multiplicative inverse using a^phi(n)-1 mod n*/
        
        long inverse = 0;
        
        int[] f = factors(n); 
        int phi_n = phiN(f[0], f[1]);
        
        inverse = power(a, phi_n - 1, n);
        
        return inverse;
    }
    
    public static int[] findA_B(int n) {
        /* finds the primes for n then all that are relatively prime to n
         * randomly chooses an a and b as the keys.
         */
        
        int[] a_b = new int[2];
        
        int[] primes = primeNumbers(n);
        int[] relativeprimes = relativePrimes(primes, n);
        a_b[0] = relativelyPrime(relativeprimes);
        a_b[1] = relativelyPrime(relativeprimes);
                
        return a_b;
    } 
    
    private static int AffineEncrypt(char[] symbols, int a, int b, int m, char x) {
        /* finds the e(x) where e(x) = ax + b mob m */
        int e, pos = 0;
        
        pos = Arrays.binarySearch(symbols, x);//finds the position that of x in the symbols array
       
        e = ((a * pos) + b) % m; //finds the encryption of x
         
        return e;
    }
    
    private static char AffineDecrypt(char[] symbols, int a, int b, int m, int e, int inverse) {
        /* decrypts the value and returns the decrypted letter */
        
        int d;
        char letter;
    
        int t = inverse * (e - b);
        
        if (t < 0){
            while(t < 0) {
                t+= m;
            }
            d = t;
        }
        else {
            d = t % m;
        }
        
        letter = symbols[d];
        
        return letter;
    }
    
    public static String encryptStringAffine(String sent, char[] symbols, int a, int b, int m) {
        /* takes a string, encrypts it and returns the string space separated */
        String esent = "";
        
        char[] eachletter = sent.toCharArray();
        
        for(int i=0; i<eachletter.length; i++){
            int e = AffineEncrypt(symbols, a, b, m, eachletter[i]);
            esent = esent + Integer.toString(e) + " ";
        }
                        
        return esent;
    }
    
    public static String decryptStringAffine(String sent, char[] symbols, int a, int b, int m, int inverse) {
        /* takes a string, decrypts it and returns the original string */
        
        String word = "";   
        String[] eachletter = sent.split("\\s");
        int e;
        char eval;
        
        for(int i=0; i<eachletter.length; i++) {
            e = Integer.valueOf(eachletter[i]);
            eval = AffineDecrypt(symbols, a, b, m, e, inverse);
            word = word + eval;
        }
        
        return word;
    }
    
    public static char[] getSymbols(){
        /* gets the enigma device */
        
        char[] alphabet = {' ', '!', '"', '#', '$', '%', '&', '\'', '(', 
            ')', '*', '+', ',', '-', '.', '/',  '0', '1', '2', '3', '4', '5', 
            '6', '7', '8', '9', ':', ';', '<', '=', '>', '?', '@', 'A', 'B', 
            'C',  'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O',
            'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '[', '\\', 
            ']', '^', '_', '`', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 
            'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 
            'w', 'x', 'y', 'z', '{', '|', '}', '~'};
        
        Arrays.sort(alphabet);
        
        return alphabet;
    }
    
    public static void main(String[] args) {

    }
}
