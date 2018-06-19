import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.security.SecureRandom;
import java.security.Security;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.mceliece.McElieceCipher;
import org.bouncycastle.pqc.crypto.mceliece.McElieceKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.mceliece.McElieceKeyPairGenerator;
import org.bouncycastle.pqc.crypto.mceliece.McElieceParameters;
import org.bouncycastle.pqc.crypto.mceliece.McEliecePrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mceliece.McEliecePublicKeyParameters;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.provider.mceliece.BCMcEliecePrivateKey;
import org.bouncycastle.pqc.jcajce.provider.mceliece.BCMcEliecePublicKey;

public class McEliecePKCS {

	public static void main(String[] args) {
		Security.addProvider(new BouncyCastlePQCProvider());
		testMceliece(12, 41);
	}
	
public static void testMceliece(int m, int t){


	String message = "hi";
    byte[] messageBytes = message.getBytes();
    SecureRandom keyRandom = new SecureRandom();
    McElieceParameters params = new McElieceParameters(m, t);
    
    McElieceKeyPairGenerator mcElieceKeyGen = new McElieceKeyPairGenerator();
    McElieceKeyGenerationParameters genParam = new McElieceKeyGenerationParameters(keyRandom, params);
    mcElieceKeyGen.init(genParam);
    AsymmetricCipherKeyPair pair = mcElieceKeyGen.generateKeyPair();

    McEliecePrivateKeyParameters sk = (McEliecePrivateKeyParameters) pair.getPrivate();
    McEliecePublicKeyParameters pk = (McEliecePublicKeyParameters) pair.getPublic();
    BCMcEliecePublicKey pubk = new BCMcEliecePublicKey(pk);
    BCMcEliecePrivateKey prvk = new BCMcEliecePrivateKey(sk);
    byte[] encodedPublicKey = pubk.getEncoded();
    byte[] encodedPrivateKey = prvk.getEncoded();
    
    ParametersWithRandom param = new ParametersWithRandom(pair.getPublic(), keyRandom);

    McElieceCipher mcEliecePKCSCipher = new McElieceCipher();
    //encryption
    mcEliecePKCSCipher.init(true, param);

    byte[] enc = mcEliecePKCSCipher.messageEncrypt(messageBytes);
    

    String s = String.valueOf(enc);
    System.out.println("encrypted message: "+s);
    System.out.println("public key: "+encodedPublicKey+pubk.getT());
    System.out.println("private key: "+encodedPrivateKey+prvk.getN());
    
    try {
    	PrintWriter out = new PrintWriter("filename.txt");
    	out.println(prvk.toString());
		 
		FileOutputStream fos = new FileOutputStream("publicOEliece.key");
		fos.write(encodedPublicKey);
		fos.close();
		/*FileOutputStream fos2 = new FileOutputStream("privateOMcEliece.txt");
		fos2.write(String.valueOf(prvk) );
		fos2.close();*/
	} catch (IOException e) {}
}

}
