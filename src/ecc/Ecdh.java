package ecc;
import java.security.*;
import java.math.BigInteger;
import java.security.spec.*;

import javax.crypto.KeyAgreement;

public class Ecdh {
	
	public static void main(String[] args) throws Exception{
		
		System.out.println("8th Semester Project -> Hybrid Cryptography Algorithm : Part 2 \"ECDH\"!\n");
		
		KeyPairGenerator kpg;
		kpg = KeyPairGenerator.getInstance("EC","SunEC");
		ECGenParameterSpec ecsp;
		
		ecsp = new ECGenParameterSpec("secp192r1");
		kpg.initialize(ecsp);
		
		KeyPair kpU = kpg.generateKeyPair();
		PrivateKey privKeyU = kpU.getPrivate();
		PublicKey pubKeyU = kpU.getPublic();
		System.out.println("User U : "+privKeyU.toString());
		System.out.println("User U : "+pubKeyU.toString());
		
		KeyPair kpV = kpg.generateKeyPair();
		PrivateKey privKeyV = kpV.getPrivate();
		PublicKey pubKeyV = kpV.getPublic();
		System.out.println("\nUser V : "+privKeyV.toString());
		System.out.println("User V : "+pubKeyV.toString());
		
			
		KeyAgreement ecdhU = KeyAgreement.getInstance("ECDH");
		ecdhU.init(privKeyU);
		ecdhU.doPhase(pubKeyV, true);
		
		KeyAgreement ecdhV = KeyAgreement.getInstance("ECDH");
		ecdhV.init(privKeyV);
		ecdhV.doPhase(pubKeyU, true);
		
		System.out.println("\nSecret computed by U : 0x"+(new BigInteger(1,ecdhU.generateSecret()).toString(16)).toUpperCase());		
		System.out.println("Secret computed by V : 0x"+(new BigInteger(1,ecdhV.generateSecret()).toString(16)).toUpperCase());
	}

}
