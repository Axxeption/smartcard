package be.msec.client;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class CAService {
	
	
	public static PublicKey getPublicKey() {
		try {
			return loadPublicKey("Keys", "RSA");
		} catch (NoSuchAlgorithmException | InvalidKeySpecException | IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}
	
	public static OwnCertificate getSignedCertificate(InfoStruct infoStruct) {
		OwnCertificate cert = new OwnCertificate(infoStruct);
		try {
			cert.signCertificate(loadPrivateKey("Keys", "RSA"));
		} catch (NoSuchAlgorithmException | InvalidKeySpecException | IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return cert;
		
	}
	
	
	
	public static void main(String[] args) {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            // Initialize KeyPairGenerator.
            keyGen.initialize(1024);

            // Generate Key Pairs, a private key and a public key.
            KeyPair keyPair = keyGen.generateKeyPair();
            PrivateKey privateKey = keyPair.getPrivate();
            PublicKey publicKey = keyPair.getPublic();

            Base64.Encoder encoder = Base64.getEncoder();
            System.out.println("privateKey: " + encoder.encodeToString(privateKey.getEncoded()));
            System.out.println("publicKey: " + encoder.encodeToString(publicKey.getEncoded()));
            
            saveKeyPair("Keys/", keyPair);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    }
	
	private static void saveKeyPair(String path, KeyPair keyPair) throws IOException {
		PrivateKey privateKey = keyPair.getPrivate();
		PublicKey publicKey = keyPair.getPublic();
 
		// Store Public Key.
		X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(
				publicKey.getEncoded());
		FileOutputStream fos = new FileOutputStream(path + "/public.key");
		fos.write(x509EncodedKeySpec.getEncoded());
		fos.close();
 
		// Store Private Key.
		PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(
				privateKey.getEncoded());
		fos = new FileOutputStream(path + "/private.key");
		fos.write(pkcs8EncodedKeySpec.getEncoded());
		fos.close();
	}
	
	
	
	public static PrivateKey loadPrivateKey(String path, String algorithm)
			throws IOException, NoSuchAlgorithmException,
			InvalidKeySpecException {
		// Read Private Key.
		File filePrivateKey = new File(path + "/private.key");
		FileInputStream fis = new FileInputStream(path + "/private.key");
		byte[] encodedPrivateKey = new byte[(int) filePrivateKey.length()];
		fis.read(encodedPrivateKey);
		fis.close();

		KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
 
		PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(
				encodedPrivateKey);
		PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
 
		return privateKey;
	}
	
	public static PublicKey loadPublicKey(String path, String algorithm)
			throws IOException, NoSuchAlgorithmException,
			InvalidKeySpecException {
		// Read Public Key.
		File filePublicKey = new File(path + "/public.key");
		FileInputStream fis = new FileInputStream(path + "/public.key");
		byte[] encodedPublicKey = new byte[(int) filePublicKey.length()];
		fis.read(encodedPublicKey);
		fis.close();
 
		// Generate Key
		KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
		X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(
				encodedPublicKey);
		PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
 
		return publicKey;
	}

}
