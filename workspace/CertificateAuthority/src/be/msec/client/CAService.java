 package be.msec.client;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Random;

public class CAService {
	
	
	public static PublicKey getPublicKey() {
		try {
			return loadPublicKey("RSA");
		} catch (NoSuchAlgorithmException | InvalidKeySpecException | IOException | URISyntaxException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}
	
	public static SignedCertificate getSignedCertificate(CertificateBasic certificateBasic) {
		SignedCertificate cert = new SignedCertificate(certificateBasic);
		try {
			cert.signCertificate(loadPrivateKey("RSA"));
			//just to verify:
			Signature sig = Signature.getInstance("SHA1WithRSA");
			byte [] data = certificateBasic.getBytes();			
			sig.initVerify(loadPublicKey("RSA"));
	        sig.update(data);
//	        System.out.println("is it verified? " + sig.verify(cert.getSignatureBytes()));
	        RSAPublicKey rsapublicKey = (RSAPublicKey) loadPublicKey("RSA");
//			System.out.println("exp CA pub key: " + bytesToDec(rsapublicKey.getPublicExponent().toByteArray()));
//			System.out.println("mod CA pub key: " + bytesToDec(rsapublicKey.getModulus().toByteArray()));
			
		} catch (NoSuchAlgorithmException | InvalidKeySpecException | IOException | 
				URISyntaxException | SignatureException | InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return cert;
		
	}
	
	
	
	public static void main(String[] args) {
		//Need tis code to generate CA keys
        /*try {
        	KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            // Initialize KeyPairGenerator.
            keyGen.initialize(512);

            // Generate Key Pairs, a private key and a public key.
            KeyPair keyPair = keyGen.generateKeyPair();
            PrivateKey privateKey = keyPair.getPrivate();
            PublicKey publicKey = keyPair.getPublic();
            try {
				System.out.println("Check if load works: " + loadPublicKey("RSA"));
			} catch (InvalidKeySpecException | URISyntaxException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
            
            
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}*/
		
		//Need this method to generate certificates
		generateCommonCertificate();
    }
	
	private static void saveKeyPair(KeyPair keyPair) throws IOException {
		PrivateKey privateKey = keyPair.getPrivate();
		PublicKey publicKey = keyPair.getPublic();
		
		// Store Public Key.
		X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(
				publicKey.getEncoded());
		FileOutputStream fos = new FileOutputStream("public.key");
		fos.write(x509EncodedKeySpec.getEncoded());
		fos.close();
 
		// Store Private Key.
		PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(
				privateKey.getEncoded());
		fos = new FileOutputStream("private.key");
		fos.write(pkcs8EncodedKeySpec.getEncoded());
		fos.close();
	}

	public static PrivateKey loadPrivateKey(String algorithm)
			throws IOException, NoSuchAlgorithmException,
			InvalidKeySpecException, URISyntaxException {
		// Read Private Key.
		URL d = CAService.class.getClassLoader().getResource("./key/private.key");
		File filePrivateKey = new File(d.toURI());
		FileInputStream fis = new FileInputStream(filePrivateKey);
		byte[] encodedPrivateKey = new byte[(int) filePrivateKey.length()];
		fis.read(encodedPrivateKey);
		fis.close();

		KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
 
		PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(
				encodedPrivateKey);
		PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
		
		
		return privateKey;
	}
	
	private static void generateCommonCertificate() {
		try {
        	KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            // Initialize KeyPairGenerator.
            keyGen.initialize(512);

            // Generate Key Pairs, a private key and a public key.
            KeyPair keyPair = keyGen.generateKeyPair();
            PrivateKey privateKey = keyPair.getPrivate();
            PublicKey publicKey = keyPair.getPublic();
            
            //generating the common keys
            RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKey;
            RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) privateKey;
            System.out.println("Commoncertificate privatekey exponent: " + bytesToDec(rsaPrivateKey.getPrivateExponent().toByteArray()));
            System.out.println("Commoncertificate privatekey modulus: " + bytesToDec(rsaPrivateKey.getModulus().toByteArray()));
            System.out.println("Commoncertificate publickey exponent: " + bytesToDec(rsaPublicKey.getPublicExponent().toByteArray()));
            System.out.println("Commoncertificate publickey modulus: " + bytesToDec(rsaPublicKey.getModulus().toByteArray()));
            
            //creating a common certificate signed by the CA
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            outputStream.write(rsaPublicKey.getPublicExponent().toByteArray());
            outputStream.write(rsaPublicKey.getModulus().toByteArray());
            outputStream.write(ByteBuffer.allocate(4).putInt(new Random().nextInt()).array());
            //this bytes will be signed: pubExponent + pubModulus + randomInt
            byte[] bytesToSign = outputStream.toByteArray();
            
            //sign the bytes
            Signature sig = Signature.getInstance("SHA1WithRSA");
			sig.initSign(loadPrivateKey("RSA"));
			sig.update(bytesToSign);
			byte[] signatureBytes = sig.sign();
            
			//certificate is the information + signature from the CA
			outputStream = new ByteArrayOutputStream();
			outputStream.write(bytesToSign);
			outputStream.write(signatureBytes);
			byte[] commonCertificate = outputStream.toByteArray();
			
			//print out the certificate, the fourth byte is not useful, take care when reconstructing keys
            System.out.println(bytesToDec(commonCertificate));
			
			
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (URISyntaxException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (SignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	public static PublicKey loadPublicKey(String algorithm)
			throws IOException, NoSuchAlgorithmException,
			InvalidKeySpecException, URISyntaxException {
		// Read Public Key.
		//smartcard/workspace/CertificateAuthority/bin/key

		URL d = CAService.class.getClassLoader().getResource("./key/public.key");
		File filePublicKey = new File(d.toURI());
		FileInputStream fis = new FileInputStream(filePublicKey);
		byte[] encodedPublicKey = new byte[(int) filePublicKey.length()];
		fis.read(encodedPublicKey);
		fis.close();
 
		// Generate Key
		KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
		X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(
				encodedPublicKey);
		PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
		
		//print out once to place him on the SC
//		RSAPublicKey rsapublicKey = (RSAPublicKey) publicKey;
//		System.out.println("CA_PK_EXP: " + bytesToDec(rsapublicKey.getPublicExponent().toByteArray()));
//		System.out.println("CA_PK_MOD: " + bytesToDec(rsapublicKey.getModulus().toByteArray()));
//		System.out.println("Length of PK mod after loading: (bits)" + rsapublicKey.getModulus().bitLength());

		return publicKey;
	}
	
	public static String bytesToDec(byte[] barray) {
		String str = "";
		for (byte b : barray)
			str += (int) b + ", (byte) ";
		return str;
	}

}
