import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

//import de.flexiprovider.api.SecureRandom;
//import de.flexiprovider.api.Cipher;
import de.flexiprovider.api.keys.KeySpec;
import de.flexiprovider.core.FlexiCoreProvider;
import de.flexiprovider.pki.PKCS8EncodedKeySpec;
import de.flexiprovider.pki.X509EncodedKeySpec;
import de.flexiprovider.pqc.FlexiPQCProvider;
import de.flexiprovider.pqc.ecc.ECCKeyGenParameterSpec;



public class NiederreiterPKCS {

	public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
		
		String message = "hi";
		 byte[] messageBytes = message.getBytes();
		
		Security.addProvider(new FlexiPQCProvider());
	    Security.addProvider(new FlexiCoreProvider());
	    
	   
		
		
		 KeyPairGenerator kpg = KeyPairGenerator.getInstance("Niederreiter","FlexiPQC");
		 //128 bits
		 ECCKeyGenParameterSpec param = new ECCKeyGenParameterSpec(12, 41);
			
		 kpg.initialize(param,new SecureRandom());
		 KeyPair keyPair = kpg.generateKeyPair();
		 byte[] encodedPublicKey = keyPair.getPublic().getEncoded();
		 byte[] encodedPrivateKey = keyPair.getPrivate().getEncoded();
		 
		 KeySpec publicKeySpec = new X509EncodedKeySpec(encodedPublicKey);
		 
		 KeyFactory keyFactory = KeyFactory.getInstance("Niederreiter", "FlexiPQC");
		 
		 PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
		 KeySpec privateKeySpec = new PKCS8EncodedKeySpec(encodedPrivateKey);
		 PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
		 
		 SecureRandom secureRand = new SecureRandom();
		//byte[][] ciphertextBytes=new byte [encodedPublicKey.length] [100] ;
		 
		 Cipher cipher = Cipher.getInstance("NiederreiterPKCS");
		 
		 long start = System.currentTimeMillis();
		 /*
		 for (int i = 0; i < encodedPublicKey.length; i++) {
			 cipher.init(Cipher.ENCRYPT_MODE, publicKey,new SecureRandom());
			ciphertextBytes[i] = cipher.doFinal(messageBytes);
		}
		 */
		 cipher.init(Cipher.ENCRYPT_MODE, publicKey,secureRand);
		 byte[] ciphertextBytes = cipher.doFinal(messageBytes);
		 
		 long elapsed = System.currentTimeMillis() - start;
		 
		 System.out.println("cipher text size: "+ciphertextBytes.length);
		 System.out.println("Elapsed time: "+elapsed+"ms");
		 
		 //decrypt
		 
		 
         cipher.init(Cipher.DECRYPT_MODE, privateKey);
		 byte[] messageBytes2 = cipher.doFinal(ciphertextBytes);
		 String message2 = new String(messageBytes2);
		 System.out.println("plain text: "+message2);
		 //System.out.println("Raw public key: "+publicKey);
		 
		
	       
	        
	}

}
