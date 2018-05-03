
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.SSLServerSocketFactory;

import be.msec.client.TimeStruct;

import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;

public class TimestampService {

	static final int port = 8001;

	public static void main(String[] args) {
		System.setProperty("javax.net.ssl.keyStore", "sslKeyStore.store");
        System.setProperty("javax.net.ssl.keyStorePassword", "jonasaxel");
        System.setProperty("javax.net.ssl.trustStore", "sslKeyStore.store");
        System.setProperty("javax.net.ssl.trustStorePassword", "jonasaxel");
        
		SSLServerSocketFactory sslServerSocketFactory = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();

		try {
			// start serverSocket connection
			ServerSocket sslServerSocket = sslServerSocketFactory.createServerSocket(port);
			System.out.println("SSL ServerSocket started");
			System.out.println(sslServerSocket.toString());

			Socket socket = sslServerSocket.accept();
			System.out.println("ServerSocket accepted");
			// set up input and outputstream objects, so that (serialized) objects can be
			// send
			ObjectInputStream objectinputstream = null;
			ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
			System.out.println("Listening");
			objectinputstream = new ObjectInputStream(socket.getInputStream());
			Integer received = (Integer) objectinputstream.readObject();
			System.out.println("received: " + received);
			// this if is just in case you want to ask other things to the timestampserver
			if (received == 1) {
				System.out.println("Ask for the timestamp!");
				
				// government.jks: privatekey van government

				PrivateKey privateKeyGovernment = loadPrivateKeyGovernment();
	
				// Get publickey and cerificate form Government certificate file
				FileInputStream fin = new FileInputStream(System.getProperty("user.dir") +"/key/government512.cer"); // \\TimestampService\\government512.cer
				CertificateFactory f = CertificateFactory.getInstance("X.509");
				X509Certificate certificate = (X509Certificate)f.generateCertificate(fin);
				RSAPublicKey publicKeyGovernment = (RSAPublicKey) certificate.getPublicKey();
				 
				System.out.println("The found public key is: " + publicKeyGovernment);
//				System.out.println("publickey modulus: "+ publicKeyGovernment.getModulus());
//				System.out.println("publickey exponent: " + publicKeyGovernment.getPublicExponent());
				// Print public key specs, Need to be the same as on the javacard
				System.out.println("exp: " + bytesToDec(publicKeyGovernment.getPublicExponent().toByteArray()));
				System.out.println("mod: " + bytesToDec(publicKeyGovernment.getModulus().toByteArray()));
				
				// Get time 
				byte[] timeInBytes = getTimeInBytes();

				// put a signature on the timestamp
				byte[] signedDate = signData(privateKeyGovernment,timeInBytes);

				// just to check if it works
				System.out.println("Validated: " + validateSignature(publicKeyGovernment, signedDate));
				
				// bundle time and signature in struct and send back.
				TimeStruct timeinfostruct = new TimeStruct(signedDate, timeInBytes);

				out.writeObject(timeinfostruct);
			}

			// everything is ready
			System.out.println("Bye!");

		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (UnrecoverableKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (SignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}
	
	private static boolean validateSignature(PublicKey publickey, byte[] data) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
		Signature rsa = Signature.getInstance("SHA1withRSA");
		rsa.initVerify(publickey);
		rsa.update(data);
		return rsa.verify(data);
	}
	
	private static byte[] signData(PrivateKey privateKeyGovernment, byte[] data) throws InvalidKeyException, NoSuchAlgorithmException, SignatureException {
		Signature rsa = Signature.getInstance("SHA1withRSA");
		rsa.initSign(privateKeyGovernment);
		rsa.update(data);
		return rsa.sign();
	}
	
	private static byte[] getTimeInBytes() {
		Calendar cal = Calendar.getInstance();
		Long time = cal.getTimeInMillis();
		System.out.println("Time is (in milliseconds): " + time);
		return longToBytes(time);
	}

	private static PrivateKey loadPrivateKeyGovernment() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, UnrecoverableKeyException {
		// get the key from a jks file (once generated with portecle)
		KeyStore keyStore = KeyStore.getInstance("JKS");
		String fileName = System.getProperty("user.dir") + "/key/government.jks"; // \\TimestampService\\government.jks
		FileInputStream fis = new FileInputStream(fileName);
		keyStore.load(fis, "jonasaxel".toCharArray());
		fis.close();

		// government.jks: privatekey van government
		PrivateKey privateKeyGovernment = (PrivateKey) keyStore.getKey("government512", "jonasaxel".toCharArray());
		System.out.println("The found private key is: " + privateKeyGovernment);
		return privateKeyGovernment;
	}
	
	public static byte[] longToBytes(long x) {
		ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
		buffer.putLong(x);
		return buffer.array();
	}

	public static long bytesToLong(byte[] bytes) {
		ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
		buffer.put(bytes);
		buffer.flip();// need flip
		return buffer.getLong();
	}
	
	private final static char[] hexArray = "0123456789ABCDEF".toCharArray();
	public static String bytesToHex(byte[] bytes) {
		char[] hexChars = new char[bytes.length * 2];
		for (int j = 0; j < bytes.length; j++) {
			int v = bytes[j] & 0xFF;
			hexChars[j * 2] = hexArray[v >>> 4];
			hexChars[j * 2 + 1] = hexArray[v & 0x0F];
		}
		String str = "";
		for (int j = 0; j < hexChars.length; j += 2) {
			str += "0x" + hexChars[j] + hexChars[j + 1] + ", (byte) ";
		}
		return str;
	}
	
	public static String bytesToDec(byte[] barray) {
		String str = "";
		for (byte b : barray)
			str += (int) b + ", (byte) ";
		return str;
	}

}
