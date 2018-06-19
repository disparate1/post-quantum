


import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.DigestingMessageSigner;
import org.bouncycastle.pqc.crypto.rainbow.RainbowKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.rainbow.RainbowKeyPairGenerator;
import org.bouncycastle.pqc.crypto.rainbow.RainbowParameters;
import org.bouncycastle.pqc.crypto.rainbow.RainbowPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.rainbow.RainbowPublicKeyParameters;
import org.bouncycastle.pqc.crypto.rainbow.RainbowSigner;
import org.bouncycastle.pqc.jcajce.provider.rainbow.BCRainbowPrivateKey;
import org.bouncycastle.pqc.jcajce.provider.rainbow.BCRainbowPublicKey;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.test.SimpleTest;


public class RainbowSignerTest
extends SimpleTest
{
    public String getName()
    {
        return "Rainbow";
    }

    public void performTest()
    {
        RainbowParameters params = new RainbowParameters(new int[] {86,131,177});

        RainbowKeyPairGenerator rainbowKeyGen = new RainbowKeyPairGenerator();
        RainbowKeyGenerationParameters genParam = new RainbowKeyGenerationParameters(new SecureRandom(), params);

        rainbowKeyGen.init(genParam);

        AsymmetricCipherKeyPair pair = rainbowKeyGen.generateKeyPair();

        ParametersWithRandom param = new ParametersWithRandom(pair.getPrivate(), new SecureRandom());
        
        BCRainbowPublicKey pk = new BCRainbowPublicKey((RainbowPublicKeyParameters) pair.getPublic());
        BCRainbowPrivateKey sk = new BCRainbowPrivateKey((RainbowPrivateKeyParameters) pair.getPrivate());
        
        byte[] privateKey = sk.getEncoded();
	     byte[] publicKey = pk.getEncoded();
	     
	     System.out.println("pub key size: "+publicKey.length);
	     //System.out.println("pub key : "+Arrays.toString(publicKey));
	     System.out.println("priv key size: "+privateKey.length);
	     //System.out.println("riv key : "+Arrays.toString(privateKey));

        DigestingMessageSigner rainbowSigner = new DigestingMessageSigner(new RainbowSigner() , new SHA224Digest());

        rainbowSigner.init(true, param);

        byte[] message = BigIntegers.asUnsignedByteArray(new BigInteger("968236873715988614170569073515315707566766479517"));
        //signing
        rainbowSigner.update(message, 0, message.length);
        
        long start = System.currentTimeMillis();
        byte[] sig = rainbowSigner.generateSignature();
        long elapsed = System.currentTimeMillis() - start;
        
        System.out.println("elapsed time: "+elapsed+" ms\nsignature array: "+Arrays.toString(sig));
        System.out.println("signature size: "+sig.length);
        
        //verifying
        rainbowSigner.init(false, pair.getPublic());
        rainbowSigner.update(message, 0, message.length);

        if (!rainbowSigner.verifySignature(sig))
        {
            fail("verification fails");
        }
    }

    public static void main(
            String[]    args)
    {
        runTest(new RainbowSignerTest());
    }
}
