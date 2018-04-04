
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
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
         
         
        SSLServerSocketFactory sslServerSocketFactory = 
                (SSLServerSocketFactory)SSLServerSocketFactory.getDefault();
         
        try {
            ServerSocket sslServerSocket = 
                    sslServerSocketFactory.createServerSocket(port);
            System.out.println("SSL ServerSocket started");
            System.out.println(sslServerSocket.toString());
             
            Socket socket = sslServerSocket.accept();
            System.out.println("ServerSocket accepted");
            ObjectInputStream objectinputstream = null;
            ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
            try {
            	System.out.println("Listening");
            	objectinputstream = new ObjectInputStream(socket.getInputStream());
            	Integer received = (Integer) objectinputstream.readObject();
            	System.out.println("received: " + received);

            	if(received == 1 ) {
            		System.out.println("Ask for the timestamp!");
            		Calendar cal = Calendar.getInstance();
                    SimpleDateFormat sdf = new SimpleDateFormat("HH:mm:ss");
                    
                    //inladen van portecle tool!
                    KeyStore keyStore = KeyStore.getInstance("JKS");
                    String fileName = new java.io.File("").getAbsolutePath() + "\\TimestampService\\government.jks";
                    FileInputStream fis = new FileInputStream(fileName);
                    keyStore.load(fis,"jonasaxel".toCharArray());
                    fis.close();
                    
                    //government.jks: privatekey van government
                    PrivateKey privateKeyGovernment = (PrivateKey) keyStore.getKey("government","jonasaxel".toCharArray());
                    System.out.println("The found private key is: " + privateKeyGovernment);

                    FileInputStream fin = new FileInputStream("C:\\Users\\vulst\\Documents\\School_4elict\\Veilige_software\\smartcard\\workspace\\TimestampService\\government.cer");
                    CertificateFactory f = CertificateFactory.getInstance("X.509");
                    X509Certificate certificate = (X509Certificate)f.generateCertificate(fin);
                    PublicKey publicKeyGovernment = certificate.getPublicKey();
                    System.out.println("The found public key is: " + publicKeyGovernment);
                    byte [] publicKeyBytes = publicKeyGovernment.getEncoded();
                    System.out.println("Byte array: " + publicKeyBytes.toString());
                    
                    Date time=  cal.getTime();
                    System.out.println("Time is: " + time );
                    byte[] dataToSend = sdf.format(time).getBytes();
//                    byte[] dataToSend = ("test".getBytes());

                    Signature rsa = Signature.getInstance("SHA1withRSA");
                    rsa.initSign(privateKeyGovernment);
                    rsa.update(dataToSend);
                    byte[] signedData = rsa.sign();
                    TimeInfoStruct timeinfostruct =  new TimeInfoStruct(signedData, time);
                    out.writeObject(timeinfostruct);
                 }
            	
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
			}
             
        } catch (IOException ex) {
            System.out.println("ERROR:" + ex);
        }
    }

}
