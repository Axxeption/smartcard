
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.SSLServerSocketFactory;
import java.text.SimpleDateFormat;
import java.util.Calendar;

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
             
            PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
            try (BufferedReader bufferedReader = 
                    new BufferedReader(
                            new InputStreamReader(socket.getInputStream()))) {
            	if(bufferedReader.readLine().equals("1")) {
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
//                    byte[] dataToSend = sdf.format(cal.getTime()).getBytes();
                    byte[] dataToSend = ("test".getBytes());

                    Signature rsa = Signature.getInstance("SHA1withRSA");
                    rsa.initSign(privateKeyGovernment);
                    rsa.update(dataToSend);
                    byte[] signedData = rsa.sign();
                    out.println(signedData);
                 }
            	
//                String line;
//                while((line = bufferedReader.readLine()) != null){
//                    System.out.println(line);
//                    out.println("goed gekregen!");
//                }
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
			}
            System.out.println("Closed");
             
        } catch (IOException ex) {
            System.out.println("ERROR: " + ex);
        }
    }

}
