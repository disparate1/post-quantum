import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
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
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import de.flexiprovider.api.keys.KeySpec;
import de.flexiprovider.core.FlexiCoreProvider;
import de.flexiprovider.pki.PKCS8EncodedKeySpec;
import de.flexiprovider.pki.X509EncodedKeySpec;
import de.flexiprovider.pqc.FlexiPQCProvider;
import de.flexiprovider.pqc.ecc.ECCKeyGenParameterSpec;



public class NiederreiterCFSSignature {

	public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, SignatureException, InvalidAlgorithmParameterException, IOException {
		
		String message = "hi";
		
		Security.addProvider(new FlexiPQCProvider());
	    Security.addProvider(new FlexiCoreProvider());
	    
	   
		
		
	    KeyPairGenerator kpg = KeyPairGenerator.getInstance("Niederreiter","FlexiPQC");
        ECCKeyGenParameterSpec param = new ECCKeyGenParameterSpec(21, 10);
        kpg.initialize(param,new SecureRandom());
		 KeyPair keyPair = kpg.generateKeyPair();
		 byte[] encodedPublicKey = keyPair.getPublic().getEncoded();
         byte[] encodedPrivateKey = keyPair.getPrivate().getEncoded();

         KeySpec publicKeySpec = new X509EncodedKeySpec(encodedPublicKey);
         

         KeyFactory keyFactory = KeyFactory.getInstance("Niederreiter", "FlexiPQC");

         PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
         KeySpec privateKeySpec = new PKCS8EncodedKeySpec(encodedPrivateKey);
         PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
         
         //save keys
          
         FileOutputStream fos = new FileOutputStream("publicKeyNiederreiter.key");
          
			fos.write(encodedPublicKey);
			fos.close();
			FileOutputStream fos2 = new FileOutputStream("privateNiederreiter.key");
			fos2.write(encodedPrivateKey);
			fos2.close();
		 
		 
		 //sign
		 
		 
		 Signature cfsSig = Signature.getInstance("Niederreiter", "FlexiPQC");
		 cfsSig.initSign(privateKey);
		 
		 cfsSig.update(message.getBytes());
		 
		 long start = System.currentTimeMillis();
		 byte[] sig = cfsSig.sign();

//verify
		 cfsSig.initVerify(publicKey);
         cfsSig.update(message.getBytes());
         boolean result = cfsSig.verify(sig);
		 long elapsed = System.currentTimeMillis() - start;
		 System.out.println("elapsed time: "+elapsed+" ms\nsignature array: "+Arrays.toString(sig));
		 System.out.println("result: "+result);

	     
	}

}
