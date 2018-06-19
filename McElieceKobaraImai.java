import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import de.flexiprovider.api.Registry;
import de.flexiprovider.api.keys.KeySpec;
import de.flexiprovider.core.FlexiCoreProvider;
import de.flexiprovider.pki.PKCS8EncodedKeySpec;
import de.flexiprovider.pki.X509EncodedKeySpec;
import de.flexiprovider.pqc.FlexiPQCProvider;
import de.flexiprovider.pqc.ecc.ECCKeyGenParameterSpec;
import de.flexiprovider.pqc.ecc.mceliece.McElieceCCA2KeyFactory;
import de.flexiprovider.pqc.ecc.mceliece.McElieceCCA2KeyPairGenerator;
import de.flexiprovider.pqc.ecc.mceliece.McElieceCCA2ParameterSpec;
import de.flexiprovider.pqc.ecc.mceliece.McElieceCCA2PrivateKey;
import de.flexiprovider.pqc.ecc.mceliece.McElieceCCA2PublicKey;
import de.flexiprovider.pqc.ecc.mceliece.McElieceKobaraImaiCipher;

public class McElieceKobaraImai {

	public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, IOException{
		String message = "hi";
		 byte[] messageBytes = message.getBytes();
		
		Security.addProvider(new FlexiPQCProvider());
	    Security.addProvider(new FlexiCoreProvider());
	    
	   
	  for (Provider provider : Security.getProviders()) {
	        for (Provider.Service service : provider.getServices()) {
	            System.out.println(provider.getName() + ": " + service.getType() + "." + service.getAlgorithm());
	            // check these values and find a best match
	        }
	    }
		
		 //KeyPairGenerator kpg = KeyPairGenerator.getInstance("McEliece","FlexiPQC");
		 //128 bits
		 //kpg.initialize(128);
		 ECCKeyGenParameterSpec param = new ECCKeyGenParameterSpec(12, 41);
		

		 McElieceCCA2KeyPairGenerator kp = new McElieceCCA2KeyPairGenerator();
		 kp.initialize(param, new SecureRandom());
		 
		 KeyPair keys = kp.generateKeyPair();
		 
				 
		 byte[] encodedPublicKey = keys.getPublic().getEncoded();
		 byte[] encodedPrivateKey = keys.getPrivate().getEncoded();
		 
		 KeySpec publicKeySpec = new X509EncodedKeySpec(encodedPublicKey);
		 KeySpec privateKeySpec = new PKCS8EncodedKeySpec(encodedPrivateKey);
		 
		 McElieceCCA2KeyFactory mkf = new McElieceCCA2KeyFactory();
		 
		 
		 
		 PublicKey publicKey = mkf.generatePublic(publicKeySpec);
		 McElieceCCA2PublicKey pp= (McElieceCCA2PublicKey)publicKey;
		 PrivateKey privateKey = mkf.generatePrivate(privateKeySpec);
		 
		/* KeyPair keys = kpg.generateKeyPair();
		 McElieceCCA2PublicKey pubK = (McElieceCCA2PublicKey) keys.getPublic();
		 McElieceCCA2PrivateKey privK = (McElieceCCA2PrivateKey) keys.getPrivate();
		 */
		 
		 FileOutputStream fos = new FileOutputStream("publicMcEliecekobara.key");
			fos.write(encodedPublicKey);
			fos.close();
			FileOutputStream fos2 = new FileOutputStream("privateMcEliecekobara.key");
			fos2.write(encodedPrivateKey);
			fos2.close();
			
			//
			McElieceKobaraImaiCipher mce= new McElieceKobaraImaiCipher();
			McElieceCCA2ParameterSpec p = new McElieceCCA2ParameterSpec();
			de.flexiprovider.api.SecureRandom sr = Registry.getSecureRandom();
			mce.initEncrypt(pp, p,sr);
			byte[] ciphertextBytes = mce.doFinal(messageBytes);
			System.out.println("cipher text size: "+ciphertextBytes.length);
			//
		 
		/* SecureRandom secureRand = new SecureRandom();
		 
		 Cipher cipher = Cipher.getInstance("McElieceKobaraImaiCipher");
		 
		 long start = System.currentTimeMillis();
		 
		 cipher.init(Cipher.ENCRYPT_MODE, publicKey);
		 byte[] ciphertextBytes = cipher.doFinal(messageBytes);
		 
		 long elapsed = System.currentTimeMillis() - start;
		 
		 System.out.println("cipher text: "+ciphertextBytes);
		 System.out.println("Elapsed time: "+elapsed+"ms");
		 
		 //decrypt
		
		 cipher.init(Cipher.DECRYPT_MODE, privateKey);
		 byte[] messageBytes2 = cipher.doFinal(ciphertextBytes);
		 String message2 = new String(messageBytes2);
		 System.out.println("plain text: "+message2);
		 
		 */

	}

}
