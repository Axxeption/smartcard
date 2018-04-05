
import java.io.BufferedReader;
import java.io.FileInputStream;
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

import be.msec.client.TimeInfoStruct;

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
				Calendar cal = Calendar.getInstance();
				SimpleDateFormat sdf = new SimpleDateFormat("HH:mm:ss");

				// get the key from a jks file (once generated with portecle)
				KeyStore keyStore = KeyStore.getInstance("JKS");
				String fileName = new java.io.File("").getAbsolutePath() + "\\government.jks"; // \\TimestampService\\government.jks
				FileInputStream fis = new FileInputStream(fileName);
				keyStore.load(fis, "jonasaxel".toCharArray());
				fis.close();

				// government.jks: privatekey van government
				PrivateKey privateKeyGovernment = (PrivateKey) keyStore.getKey("government512", "jonasaxel".toCharArray());
				System.out.println("The found private key is: " + privateKeyGovernment);

				// get the public key from the government, commented because not needed --> is
				// already placed as bytearray on the javacard
				 FileInputStream fin = new FileInputStream(System.getProperty("user.dir") +"\\government512.cer"); // \\TimestampService\\government512.cer

				 CertificateFactory f = CertificateFactory.getInstance("X.509");
				 X509Certificate certificate = (X509Certificate)f.generateCertificate(fin);
				 RSAPublicKey publicKeyGovernment = (RSAPublicKey) certificate.getPublicKey();
				 
				 System.out.println("The found public key is: " + publicKeyGovernment);
				 System.out.println("publickey modulus: "+ publicKeyGovernment.getModulus());
				 System.out.println("publickey exponent: " + publicKeyGovernment.getPublicExponent());
				 byte [] publicKeyBytes = publicKeyGovernment.getEncoded();
				 System.out.println("exp: " + bytesToDec(publicKeyGovernment.getPublicExponent().toByteArray()));
				 System.out.println("mod: " + bytesToDec(publicKeyGovernment.getModulus().toByteArray()));

				Long time = cal.getTimeInMillis();
				System.out.println("Time is (in milliseconds): " + time);

				byte[] dataToSend = longToBytes(time);

				// put a signature on the timestamp
				Signature rsa = Signature.getInstance("SHA1withRSA");
				rsa.initSign(privateKeyGovernment);
				rsa.update(dataToSend);
				byte[] signedData = rsa.sign();

				// just to check if it works
				 rsa.initVerify(publicKeyGovernment);
				 rsa.update(dataToSend);
				 System.out.println(bytesToDec(dataToSend));
				 System.out.println("Is it verified? " + rsa.verify(signedData));

				TimeInfoStruct timeinfostruct = new TimeInfoStruct(signedData, dataToSend);
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
