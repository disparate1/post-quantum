import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.security.Security;
import java.util.Arrays;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.crypto.ntru.NTRUEncryptionKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.ntru.NTRUEncryptionKeyPairGenerator;
import org.bouncycastle.pqc.crypto.ntru.NTRUEncryptionPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.ntru.NTRUEncryptionPublicKeyParameters;
import org.bouncycastle.pqc.crypto.ntru.NTRUEngine;

public class NTRUEncrypt2 {

	public static void main(String[] args) throws InvalidCipherTextException, IOException {

		Security.addProvider(new BouncyCastleProvider());
		NTRUEncTest();
	}

	public static void NTRUEncTest() throws InvalidCipherTextException, IOException {
		NTRUEngine ntru = new NTRUEngine();
		NTRUEncryptionKeyGenerationParameters params = NTRUEncryptionKeyGenerationParameters.APR2011_743;

//		NTRUEncryptionKeyGenerationParameters params = new NTRUEncryptionKeyGenerationParameters(239, 1024, 7, 6, 4, 70, 85, 13, 17, 19, true, new byte[]{0, 3, 9}, true, true, new SHA256Digest());
		NTRUEncryptionKeyPairGenerator ntruGen = new NTRUEncryptionKeyPairGenerator();
		ntruGen.init(params);
		AsymmetricCipherKeyPair kp = ntruGen.generateKeyPair();
		//
		
		 ByteArrayOutputStream bos1 = new ByteArrayOutputStream();
		 ByteArrayOutputStream bos2 = new ByteArrayOutputStream();
		NTRUEncryptionPrivateKeyParameters priv = (NTRUEncryptionPrivateKeyParameters) kp.getPrivate();
        NTRUEncryptionPublicKeyParameters pub = (NTRUEncryptionPublicKeyParameters) kp.getPublic();
        pub.writeTo(bos1);
        priv.writeTo(bos2);
        byte[] encodedPub = bos1.toByteArray();
        byte[] encodedPriv = bos2.toByteArray();
         

		   
		 
                    
                 

        
      /*  byte[] priv = ((NTRUEncryptionPrivateKeyParameters) kp.getPrivate())
                .getEncoded();
        byte[] pub = ((NTRUEncryptionPublicKeyParameters) kp.getPublic())
                .getEncoded();*/
		//
				
		 byte[] plainText = "hi".getBytes();
				

		 System.out.println("pub key size: "+encodedPub.length);
		 System.out.println("priv key size: "+encodedPriv.length);
		 System.out.println("text: "+new String(plainText));
		 System.out.println("text size: "+plainText.length);
	     ntru.init(true, pub);
	     byte[] encrypted = ntru.processBlock(plainText, 0, plainText.length);
	     
	     ntru.init(false, priv);
	     

	     byte[] decrypted = ntru.processBlock(encrypted, 0, encrypted.length);
	     System.out.println("enc text size: "+encrypted.length);
	     System.out.println("dec text: "+new String(decrypted));
	     
	    
	     
	     
	     try {
	    		//save to a file
	    	 
	    	  
	    	  
	    	 FileOutputStream fos3 = new FileOutputStream("plnText.txt");
	    		fos3.write(plainText);
	    		fos3.close();
	        	PrintWriter out = new PrintWriter("publicKey.txt");
	        	out.println(Arrays.toString(encodedPub));
	        	out.close();
	        	PrintWriter out2 = new PrintWriter("privateKey.txt");
	        	out2.println(Arrays.toString(encodedPriv));
	        	out2.close();
	    		FileOutputStream fos = new FileOutputStream("encText.txt");
	    		bos1.writeTo(fos);
	    		fos.close();
	    		FileOutputStream fos2 = new FileOutputStream("decText.txt");
	    		fos2.write(pub.getEncoded());
	    		fos2.close();
	    	} catch (IOException e) {}

	     
		 
 		
	}

	 
	

}
