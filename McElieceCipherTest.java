

	import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Random;

	import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
	import org.bouncycastle.crypto.Digest;
	import org.bouncycastle.crypto.InvalidCipherTextException;
	import org.bouncycastle.crypto.digests.SHA256Digest;
	import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.pqc.crypto.mceliece.McElieceCipher;
	import org.bouncycastle.pqc.crypto.mceliece.McElieceKeyGenerationParameters;
	import org.bouncycastle.pqc.crypto.mceliece.McElieceKeyPairGenerator;
	import org.bouncycastle.pqc.crypto.mceliece.McElieceParameters;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.McElieceKeyGenParameterSpec;
import org.bouncycastle.util.test.SimpleTest;

 

	public class McElieceCipherTest
	    extends SimpleTest
	{

	    SecureRandom keyRandom = new SecureRandom();

	    public String getName()
	    {
	        return "McEliecePKCS";

	    }


	    public void performTest()
	        throws InvalidCipherTextException, IOException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException
	    {
	        int numPassesKPG = 1;
	        
	        Random rand = new Random();
	        byte[] mBytes;
	        for (int j = 0; j < numPassesKPG; j++)
	        {

	            McElieceParameters params = new McElieceParameters(10, 50);
	            
	            //McElieceKeyGenParameterSpec sd= new McElieceKeyGenParameterSpec(10, 50);
	           
	           // McElieceKeyPairGenerator mcElieceKeyGen = new McElieceKeyPairGenerator();
	           // McElieceKeyGenerationParameters genParam = new McElieceKeyGenerationParameters(keyRandom, params);

	            
	            //
	            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("McEliece","BCPQC");
	            
	           // KeyFactory keyFactory = KeyFactory.getInstance("McEliece","BCPQC");
	           // PublicKey publicKey = keyFactory.generatePublic(new x);
	            
	          /*  keyGen.initialize(sd,new SecureRandom());
	            KeyPair keyPair = keyGen.generateKeyPair();
	            McElieceKeyPairGenerator kpg= new McElieceKeyPairGenerator();
	            kpg.init(genParam);
	            byte[] encodedPublicKey = keyPair.getPublic().getEncoded();
	            System.out.println("cipher text: "+encodedPublicKey);*/
	        }
	            
	            
	            //
	            /*
	            mcElieceKeyGen.init(genParam);
	            AsymmetricCipherKeyPair pair = mcElieceKeyGen.generateKeyPair();
	            //X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec();
	           // PublicKey publicKey = keyFactory.generatePublic((KeySpec) pair.getPublic());
	            //KeyPair key = keyGen.generateKeyPair();
	           // PublicKey pub = key.getPublic();
	           //byte[] encodedPublicKey =  

	           // int keySize= pair.
	            ParametersWithRandom param = new ParametersWithRandom(pair.getPublic(), keyRandom);
	            Digest msgDigest = new SHA256Digest();
	            McElieceCipher mcEliecePKCSDigestCipher = new McElieceCipher();

	           //save keys
	            //String encodedPublicKey = pair.getPublic().toString();
	            FileOutputStream fos = new FileOutputStream("pubdddKey.txt");
				//fos.write(pub.getEncoded());
				fos.close();
	            
	                System.out.println("############### test: ");
	                System.out.println("n="+params.getN()+"\tt="+params.getT()+"\tm="+params.getM()+"\tgetFieldPoly="+params.getFieldPoly());

	                // initialize for encryption
	                mcEliecePKCSDigestCipher.init(true, param);

	                // generate random message
	                int mLength = (rand.nextInt() & 0x1f) + 1;
	                mBytes = new byte[mLength];
	                rand.nextBytes(mBytes);

	                // encrypt
	                	long start = System.currentTimeMillis();
	                msgDigest.update(mBytes, 0, mBytes.length);
	                byte[] hash = new byte[msgDigest.getDigestSize()];

	                msgDigest.doFinal(hash, 0);
	                
	                
	                byte[] enc = mcEliecePKCSDigestCipher.messageEncrypt(hash);
	                
	                	long elapsed = System.currentTimeMillis() - start;	
	                	
	                // initialize for decryption
	                mcEliecePKCSDigestCipher.init(false, pair.getPrivate());
	                byte[] constructedmessage = mcEliecePKCSDigestCipher.messageDecrypt(enc);

	                boolean verified = true;
	                for (int i = 0; i < hash.length; i++)
	                {
	                    verified = verified && hash[i] == constructedmessage[i];
	                }

	                if (!verified)
	                {
	                    fail("en/decryption fails");
	                }
	                else
	                {
	                    System.out.println("test okay \nElapsed time: "+elapsed+" ms");
	                    System.out.println();
	                }

	            
	        }*/

	    }

	    public static void main(String[] args)
	    {
	    	Security.addProvider(new BouncyCastlePQCProvider());

	    	/*for (Provider provider : Security.getProviders()) {
		        for (Provider.Service service : provider.getServices()) {
		            System.out.println(provider.getName() + ": " + service.getType() + "." + service.getAlgorithm());
		            // check these values and find a best match
		        }
		    }*/
	        runTest(new McElieceCipherTest());
	    }

	}


