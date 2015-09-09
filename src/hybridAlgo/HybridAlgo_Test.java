package hybridAlgo;
import java.io.*;
import java.util.Random;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.*;
import java.sql.*;

import javax.crypto.KeyAgreement;

	
public class HybridAlgo_Test {

		public static MD5 obj2;
		BigInteger p,q,N,e,d,phiN;
		Random r;
		int bitlen = 1024,flag = 0;
		
		
		
		public HybridAlgo_Test() throws Exception 
		{
			r = new Random();
			p = BigInteger.probablePrime(bitlen, r);
			q = BigInteger.probablePrime(bitlen, r);
			N = p.multiply(q);
			phiN = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));
		
		do{
			try
			{
			flag=0;
			e = ECDH_KeyGen();
			d = e.modInverse(phiN);
			
			}
			catch(ArithmeticException e)
			{
				//System.out.println("Error in Mod Inverse!"+e);
				flag=1;
			}
		}while(flag==1);
		}
		

		public static BigInteger ECDH_KeyGen() throws Exception
		{
			KeyPairGenerator kpg;
			kpg = KeyPairGenerator.getInstance("EC","SunEC");
			ECGenParameterSpec ecsp;
			
			ecsp = new ECGenParameterSpec("secp192r1");
			kpg.initialize(ecsp);
			
			KeyPair kpU = kpg.generateKeyPair();
			PrivateKey privkeyU = kpU.getPrivate();
			PublicKey pubkeyU = kpU.getPublic();
			
			KeyPair kpV = kpg.generateKeyPair();
			PrivateKey privkeyV = kpV.getPrivate();
			PublicKey pubkeyV = kpV.getPublic();
			
			
			KeyAgreement ecdhU = KeyAgreement.getInstance("ECDH");
			ecdhU.init(privkeyU);
			ecdhU.doPhase(pubkeyV, true);
			
			KeyAgreement ecdhV = KeyAgreement.getInstance("ECDH");
			ecdhV.init(privkeyV);
			ecdhV.doPhase(pubkeyU, true);
			
			BigInteger xyz = new BigInteger(1,ecdhU.generateSecret());
			return xyz;
		}
		
		private static String bytesToString(byte[] message)
		{
			String temp="";
			for(byte b : message)
				temp+= Byte.toString(b);
			
			return temp;
		}
		
		public byte[] encrypt(byte[] message)
		{
			return (new BigInteger(message).modPow(e, N).toByteArray());	 // C = M^e mod N
		}
		
		public byte[] decrypt(byte[] cipher)
		{
			return (new BigInteger(cipher).modPow(d, N).toByteArray());	// M = C^d mod N
		}
		
		
		@SuppressWarnings("deprecation")
		public static void main(String[] args) throws Exception
		{
			System.out.println("8th Semester Project -> Hybrid Cryptography Algorithm : ");
			int flag=0;
			HybridAlgo_Test obj = new HybridAlgo_Test();
			String UserID="";
			String Password="";
			DataInputStream in = new DataInputStream(System.in);
			
			//LOGIN
		
			System.out.println("==CLIENT SIDE User Login Credentials==");
			System.out.println("Enter the UserName : ");
			UserID = in.readLine();
			System.out.println("Enter the Passwords : ");
			Password = in.readLine();
			
			// LOGIN DISPLAY = Client SIDE
			
			byte[] cipherText = obj.encrypt(Password.getBytes());
			System.out.println("Password : " + bytesToString(cipherText));
			String hashText = MD5.func_md5(cipherText);
			System.out.println("Password HASH : " + hashText);
			
			
			
			// LOGIN DISPLAY = Server SIDE
			System.out.println("\n***Sending data to Server Side ***\n");
			System.out.println("==SERVER SIDE : User Login Credentials==");
			System.out.println("User ID : "+UserID);		
			
			String hashTextCheck = MD5.func_md5(cipherText);
			System.out.println("Old Hash : "+hashText);
			System.out.println("Recalculated Hash : "+hashTextCheck);
			System.out.println("Authentication : "+hashText.equals(hashTextCheck));
			
			byte[] decryptedText = obj.decrypt(cipherText);
			String PasswordCheck = new String(decryptedText);
			System.out.println("Old Password : "+Password);
			System.out.println("Recalculated Password :"+PasswordCheck);
			
			String PasswordCheckHash = MD5.func_md5(PasswordCheck.getBytes());
			System.out.println("Hashed Password :"+PasswordCheckHash);
			String searchQuery = "select * from user_database where username='"+UserID+"' AND password='"+PasswordCheckHash+"'";
			
			
			try 
		    {
		         Class.forName("com.mysql.jdbc.Driver");
		    } 
		    catch (ClassNotFoundException e) 
		   {
		    	System.out.println(e.getMessage());
		   }
			
		try {
           
			Connection con = DriverManager.getConnection("jdbc:mysql://localhost:3306/myDb", "root", "");
            Statement stmt = con.createStatement();
            ResultSet rs = stmt.executeQuery(searchQuery);
         	            
           while(rs.next())
           {
            	String fname = rs.getString("firstname");
            	String lname = rs.getString("lastname");
               	System.out.println("\nWelcome : "+fname+" "+lname);
               	System.out.println("Successful Entry");
            	flag=1;
           }
           
           if(flag==0)
        		System.out.println("\nSorry.Login Failed");
           
           con.close(); 
		    }  
        catch (SQLException e) {
            System.out.println("SQLException occured: " + e.getMessage());
            e.printStackTrace();
        } 
			
		
		
		
		}
	}

