import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.Provider;
import java.security.Security;
import java.util.Random;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.crypto.ntru.NTRUSigner;
import org.bouncycastle.pqc.crypto.ntru.NTRUSigningKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.ntru.NTRUSigningKeyPairGenerator;
import org.bouncycastle.pqc.crypto.ntru.NTRUSigningPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.ntru.NTRUSigningPublicKeyParameters;

public class NTRUSign {

	public static void main(String[] args) throws IOException {
		Security.addProvider(new BouncyCastleProvider());
		//testSignVerify(new NTRUSigningKeyGenerationParameters(239, 1024, 7, 6, 4, 1, 1, 0.200, 350, 150, false, true, 0, new SHA256Digest())); 
		//testSignVerify(NTRUSigningKeyGenerationParameters.APR2011_439_PROD);
		testSignVerify(NTRUSigningKeyGenerationParameters.APR2011_743_PROD); 

			
	}

	
	
	private static void testSignVerify(NTRUSigningKeyGenerationParameters params)
	        throws IOException {
	    NTRUSigner ntru = new NTRUSigner(params.getSigningParameters());
	    NTRUSigningKeyPairGenerator kGen = new NTRUSigningKeyPairGenerator();

	    kGen.init(params);

	    AsymmetricCipherKeyPair kp = kGen.generateKeyPair();
	    
	    ByteArrayOutputStream bos1 = new ByteArrayOutputStream();
		ByteArrayOutputStream bos2 = new ByteArrayOutputStream();
	    
	    NTRUSigningPublicKeyParameters pk = (NTRUSigningPublicKeyParameters) kp.getPublic();
	    NTRUSigningPrivateKeyParameters sk = (NTRUSigningPrivateKeyParameters) kp.getPrivate();

	    pk.writeTo(bos1);
	    sk.writeTo(bos2);
        byte[] encodedPub = bos1.toByteArray();
        byte[] encodedPriv = bos2.toByteArray();
        
        System.out.println("pub key size: "+encodedPub.length);
		System.out.println("priv key size: "+encodedPriv.length);
	    
	    byte[] msg = "hi".getBytes();
	    
	    
	    // sign and verify
	    ntru.init(true, sk);

	    ntru.update(msg, 0, msg.length);

	    byte[] s = ntru.generateSignature();

	    ntru.init(false, pk);

	    ntru.update(msg, 0, msg.length);

	    boolean valid = ntru.verifySignature(s);
	    System.out.println("message: "+new String(msg));
	    System.out.println("signature: "+new String(s));
	    System.out.println("signature size: "+s.length);
	    System.out.println("valid: "+valid);
	}

}
