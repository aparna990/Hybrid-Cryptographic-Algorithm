package rsa;
import java.io.*;
import java.util.Random;
import java.math.BigInteger;

public class RSA {
	
	//Big Integer  - > Java class to perform operations on Integers of arbitrary precision
	
	BigInteger p;
	BigInteger q;
	BigInteger N;		// N 	= p*q
	BigInteger phiN;	// phiN	= (p-1)*(q-1)  - > Number smaller than N and relatively prime to N (( for Prime Numbers it is N-1 ))
	BigInteger e;
	BigInteger d;
	Random r;
	int bitlen = 1024;
	
	public RSA()
	{
		r = new Random();
		p = BigInteger.probablePrime(bitlen, r);
		q = BigInteger.probablePrime(bitlen, r);
		
		N = p.multiply(q);
		phiN = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));
		
		// To find z such that 1<z<N
		e = BigInteger.probablePrime(bitlen/2, r);
		
	while(phiN.gcd(e).equals(BigInteger.ONE)==false && e.compareTo(phiN)!=1)	// when GCD(N,e)=1 && e<N
		{
			e = BigInteger.probablePrime(bitlen, r);
		}
	
			d = e.modInverse(phiN);
			
			
		System.out.println("The E value is : "+e.toString(16));
		System.out.println("The D value is : "+d.toString(16));
		// Public Key  	- > { e, N }
		// Private Key  - > { d, N }
	}
	
	public byte[] encrypt(byte[] message)
	{
		return (new BigInteger(message).modPow(e, N).toByteArray());	 // C = M^e mod N
	}
	
	public byte[] decrypt(byte[] cipher)
	{
		return (new BigInteger(cipher).modPow(d, N).toByteArray());	// M = C^d mod N
	}
	
	private static String bytesToString(byte[] message)
	{
		String temp="";
		for(byte b : message)
			temp+= Byte.toString(b);
		
		return temp;
	}
	
	@SuppressWarnings("deprecation")
	public static void main(String[] args) throws IOException
	{
		System.out.println("8th Semester Project -> Hybrid Cryptography Algorithm : Part 3 \"RSA\"!\n");
		RSA obj = new RSA();
		String input="";
		DataInputStream in = new DataInputStream(System.in);
		
		System.out.println("\nEnter the input string : ");
		input = in.readLine();
		
		System.out.println("The Input  : "+input);
		System.out.println("The Input (In Bytes) : "+bytesToString(input.getBytes()));
		
		//Encryption
		byte[] cipherText = obj.encrypt(input.getBytes());
		System.out.println("\nThe Cipher : "+ bytesToString(cipherText));
		
		//Decryption
		byte[] decryptedText = obj.decrypt(cipherText);
		String Message = new String(decryptedText);
		System.out.println("\nThe Message (In Bytes) : "+bytesToString(decryptedText));
		System.out.println("The Message : "+Message);		
			
	}
	
	

}
