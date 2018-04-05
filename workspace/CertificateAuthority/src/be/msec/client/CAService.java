package be.msec.client;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;
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
			return loadPublicKey("RSA");
		} catch (NoSuchAlgorithmException | InvalidKeySpecException | IOException | URISyntaxException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}
	
	public static OwnCertificate getSignedCertificate(InfoStruct infoStruct) {
		OwnCertificate cert = new OwnCertificate(infoStruct);
		try {
			cert.signCertificate(loadPrivateKey("RSA"));
		} catch (NoSuchAlgorithmException | InvalidKeySpecException | IOException | URISyntaxException e) {
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
            
            try {
				System.out.println("blabla: " + loadPublicKey("RSA"));
			} catch (InvalidKeySpecException | URISyntaxException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
            
            saveKeyPair(keyPair);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
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
		URL d = CAService.class.getClassLoader().getResource("./keys/private.key");
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
	
	public static PublicKey loadPublicKey(String algorithm)
			throws IOException, NoSuchAlgorithmException,
			InvalidKeySpecException, URISyntaxException {
		// Read Public Key.
		URL d = CAService.class.getClassLoader().getResource("./keys/public.key");
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
 
		return publicKey;
	}

}
