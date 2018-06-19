import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.mceliece.McElieceCCA2KeyGenerationParameters;
import org.bouncycastle.pqc.crypto.mceliece.McElieceCCA2KeyPairGenerator;
import org.bouncycastle.pqc.crypto.mceliece.McElieceCCA2Parameters;
import org.bouncycastle.pqc.crypto.mceliece.McElieceCCA2PrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mceliece.McElieceCCA2PublicKeyParameters;
import org.bouncycastle.pqc.crypto.mceliece.McElieceKobaraImaiCipher;
import org.bouncycastle.pqc.jcajce.provider.mceliece.BCMcElieceCCA2PrivateKey;
import org.bouncycastle.pqc.jcajce.provider.mceliece.BCMcElieceCCA2PublicKey;

public class KobaraImainMcelieceTest {

	public static void main(String[] args) {
		
		testMcelieceKobara(10,50);
		//testMcelieceKobara(11,50);
		testMcelieceKobara(11,35);
		testMcelieceKobara(12,41);
	}
	
	public static void testMcelieceKobara(int m, int t){


        String message = "hi";
        byte[] messageBytes = message.getBytes();
        //get current memory consumption
       // Runtime runtime = Runtime.getRuntime();
       // long usedMemoryBefore = runtime.totalMemory() - runtime.freeMemory();
        //get current time for keygen
       // long start3 = System.currentTimeMillis();*/

        //
        SecureRandom keyRandom = new SecureRandom();
        McElieceCCA2Parameters params = new McElieceCCA2Parameters(m,t);
        McElieceCCA2KeyPairGenerator mcElieceCCA2KeyGen = new McElieceCCA2KeyPairGenerator();
        McElieceCCA2KeyGenerationParameters genParam = new McElieceCCA2KeyGenerationParameters(keyRandom, params);
        mcElieceCCA2KeyGen.init(genParam);
        AsymmetricCipherKeyPair pair = mcElieceCCA2KeyGen.generateKeyPair();
        ParametersWithRandom param = new ParametersWithRandom(pair.getPublic(), keyRandom);


        McElieceCCA2PrivateKeyParameters  sk = (McElieceCCA2PrivateKeyParameters ) pair.getPrivate();
        McElieceCCA2PublicKeyParameters  pk = (McElieceCCA2PublicKeyParameters ) pair.getPublic();
        BCMcElieceCCA2PublicKey pubk = new BCMcElieceCCA2PublicKey(pk);
        BCMcElieceCCA2PrivateKey prvk = new BCMcElieceCCA2PrivateKey(sk);
        byte[] encodedPublicKey = pubk.getEncoded();
        byte[] encodedPrivateKey = prvk.getEncoded();
        
        //System.out.println("public key: "+encodedPublicKey+pubk.toString());
        //System.out.println("private key: "+encodedPrivateKey+prvk.toString());
        
        try {
    		
        	//PrintWriter out = new PrintWriter("filename2.txt");
        	//out.println(prvk.toString());
    		FileOutputStream fos = new FileOutputStream("publicKOBARAElieceM"+m+"T"+t+".key");
    		fos.write(encodedPublicKey);
    		fos.close();
    		FileOutputStream fos2 = new FileOutputStream("privateKOBARAMcElieceM"+m+"T"+t+".key");
    		fos2.write(encodedPrivateKey);
    		fos2.close();
    	} catch (IOException e) {}

        //


        //get elapsed time for keygen
      //  long elapsed3 = System.currentTimeMillis() - start3;
       // System.out.println( "elapsed time keygen: "+elapsed3+" ms");

        McElieceKobaraImaiCipher kobaraCipher = new McElieceKobaraImaiCipher();

        //get current time
        long start = System.currentTimeMillis();

        //encryption


        kobaraCipher.init(true, param);

        byte[] enc = kobaraCipher.messageEncrypt(messageBytes);

        //get elapsed enc time
        long elapsed = System.currentTimeMillis() - start;


        String s = String.valueOf(enc);
        String s2 = String.valueOf(elapsed);

        System.out.println("encrypted message size: "+enc.length);
        //System.out.println("elapsed time: "+s2+" ms");


        //decryption

        //get current time
        long start2 = System.currentTimeMillis();

        try {
            kobaraCipher.init(false,pair.getPrivate());
            byte[] dec = kobaraCipher.messageDecrypt(enc);

            //get elapsed time
            long elapsed2 = System.currentTimeMillis() - start2;
            String decypted = new String(dec);
            String time2 = String.valueOf(elapsed2);
            System.out.println( "decrypted message: "+decypted);
            System.out.println( "elapsed time2: "+time2+" ms");


        }catch (Exception e) {
            e.printStackTrace();
        } 
        //get memory consumption
       // long usedMemoryAfter = runtime.totalMemory() - runtime.freeMemory();
        //long memoryUsage = usedMemoryAfter-usedMemoryBefore;
        //System.out.println("memory usage: "+memoryUsage+" bytes");





    }

}
