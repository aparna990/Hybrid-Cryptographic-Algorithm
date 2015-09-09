package ecc;
import java.security.*;
import java.security.spec.*;

public class ECC {

	public static void main(String[] args) throws Exception{
		
		System.out.println("8th Semester Project -> Hybrid Cryptography Algorithm : Part \"ECC\"!\n");
		KeyPairGenerator kpg;
		kpg = KeyPairGenerator.getInstance("EC","SunEC");
		ECGenParameterSpec ecsp;
		ecsp = new ECGenParameterSpec("secp192r1");
		kpg.initialize(ecsp);
		
		KeyPair kp = kpg.generateKeyPair();
		PrivateKey privKey = kp.getPrivate();
		PublicKey pubKey = kp.getPublic();
		
		System.out.println(privKey.toString());
		System.out.println(pubKey.toString());
				
	}

	
}

