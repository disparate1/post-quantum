import java.security.Security;


import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.crypto.ntru.NTRUEncryptionKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.ntru.NTRUEncryptionKeyPairGenerator;
import org.bouncycastle.pqc.crypto.ntru.NTRUEngine;
import org.bouncycastle.pqc.crypto.ntru.NTRUParameters;
import org.bouncycastle.pqc.math.ntru.polynomial.IntegerPolynomial;
import org.bouncycastle.pqc.math.ntru.polynomial.Polynomial;
import org.bouncycastle.pqc.math.ntru.polynomial.TernaryPolynomial;
//import org.bouncycastle.util.Arrays;

public class NTRUEcrypt {

	public static void main(String[] args) throws InvalidCipherTextException {

		Security.addProvider(new BouncyCastleProvider());
		NTRUEcrypt ntru = new NTRUEcrypt();
		ntru.NTRUEncTest();
		
	}
	
	public void NTRUEncTest() throws InvalidCipherTextException{
		NTRUEncryptionKeyGenerationParameters params = NTRUEncryptionKeyGenerationParameters.APR2011_743.clone();
		 // set df1..df3 and dr1..dr3 so params can be used for SIMPLE as well as PRODUCT
        params.df1 = NTRUEncryptionKeyGenerationParameters.APR2011_743_FAST.df1;
        params.df2 = NTRUEncryptionKeyGenerationParameters.APR2011_743_FAST.df2;
        params.df3 = NTRUEncryptionKeyGenerationParameters.APR2011_743_FAST.df3;
        params.dr1 = NTRUEncryptionKeyGenerationParameters.APR2011_743_FAST.dr1;
        params.dr2 = NTRUEncryptionKeyGenerationParameters.APR2011_743_FAST.dr2;
        params.dr3 = NTRUEncryptionKeyGenerationParameters.APR2011_743_FAST.dr3;
        
        int[] values = new int[] { NTRUParameters.TERNARY_POLYNOMIAL_TYPE_SIMPLE, NTRUParameters.TERNARY_POLYNOMIAL_TYPE_PRODUCT };
        
        for (int i = 0; i != values.length; i++)
        {
            int polyType = values[i];

            boolean[] booleans = {true, false};
            for (int j = 0; j != booleans.length; j++)
            {
                params.polyType = polyType;
                params.fastFp = booleans[j];

                VisibleNTRUEngine ntru = new VisibleNTRUEngine();
                NTRUEncryptionKeyPairGenerator ntruGen = new NTRUEncryptionKeyPairGenerator();

                ntruGen.init(params);

                AsymmetricCipherKeyPair kp = ntruGen.generateKeyPair();

                //testPolynomial(ntru, kp, params);

                testText(ntru, kp, params);
                // sparse/dense
                //params.sparse = !params.sparse;
                //testText(ntru, kp, params);
                //params.sparse = !params.sparse;

//                testEmpty(ntru, kp, params);
//                testMaxLength(ntru, kp, params);
//                testTooLong(ntru, kp, params);
//                testInvalidEncoding(ntru, kp, params);
            }
        }
		
		
	}
	
	// encrypts and decrypts text
    private void testText(NTRUEngine ntru, AsymmetricCipherKeyPair  kp, NTRUEncryptionKeyGenerationParameters params)
        throws InvalidCipherTextException
    {
        byte[] plainText = "hi".getBytes();

        ntru.init(true, kp.getPublic());

        byte[] encrypted = ntru.processBlock(plainText, 0, plainText.length);

        ntru.init(false, kp.getPrivate());

        byte[] decrypted = ntru.processBlock(encrypted, 0, encrypted.length);
        
        System.out.println("enc text: "+encrypted.toString());
        System.out.println("dec text: "+decrypted.toString());
        System.out.println("max length: "+plainText.length);
        System.out.println("message length: "+params.maxMsgLenBytes);


       // assertTrue(Arrays.areEqual(plainText, decrypted));
    }
    
    private class VisibleNTRUEngine
    extends NTRUEngine
{
    public IntegerPolynomial encrypt(IntegerPolynomial m, TernaryPolynomial r, IntegerPolynomial pubKey)
    {
        return super.encrypt(m, r, pubKey);
    }

    public IntegerPolynomial decrypt(IntegerPolynomial e, Polynomial priv_t, IntegerPolynomial priv_fp)
    {
        return super.decrypt(e, priv_t, priv_fp);
    }
}

}
