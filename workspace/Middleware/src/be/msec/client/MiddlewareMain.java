package be.msec.client;

import be.msec.client.connection.Connection;

import java.awt.RenderingHints.Key;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.SSLSocketFactory;
import be.msec.client.connection.IConnection;
import be.msec.client.connection.SimulatedConnection;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Group;
import javafx.scene.Scene;
import javafx.scene.layout.AnchorPane;
import javafx.scene.layout.BorderPane;
import javafx.scene.shape.Circle;
import javafx.stage.PopupWindow.AnchorLocation;
import javafx.stage.Stage;
import javax.smartcardio.*;

public class MiddlewareMain extends Application {
	
	private Stage primaryStage;
	private BorderPane rootLayout;
	
	private final static byte IDENTITY_CARD_CLA =(byte)0x80;
	private static final byte VALIDATE_PIN_INS = 0x22;
	private final static short SW_VERIFICATION_FAILED = 0x6300;
	private final static short SW_PIN_VERIFICATION_REQUIRED = 0x6301;
	private static final byte GET_SERIAL_INS = 0x26;
	private static final byte GET_NAME_INS = 0x24;
	private static final byte SIGN_RANDOM_BYTE = 0x27;
	private static final byte GET_CERTIFICATE = 0x28;
	private static final byte test = 0x01;
	static final int port = 8001;
	private Socket timestampSocket = null;
	IConnection c;
	CommandAPDU a;
	ResponseAPDU r;

	public void start(Stage stage) throws IOException {
		this.primaryStage = stage;
        this.primaryStage.setTitle("Card reader UI");
//        initRootLayout();
        try {
			//ConnectSimulator();
	//		ConnectRealDevice();
//			
//			askName();
//			connectTimestampServer();
//			checkChallenge();
			
			InfoStruct infoStruct = new ServiceProviderInfoStruct(null, "een serviceke", 24);
			OwnCertificate ownCertificate = CAService.getSignedCertificate(infoStruct);
			
			System.out.println(ownCertificate.verifySignature(CAService.getPublicKey()));
			
//			askTime();
//        	testSetup();
		} catch (Exception e) {
			e.printStackTrace();
		}
    }
	
	public void testSetup() throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException {
		//aan de CA kant
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.genKeyPair();
        
		KeyFactory fact = KeyFactory.getInstance("RSA");
        RSAPublicKeySpec publicKeyCARSA = fact.getKeySpec(kp.getPublic(),
                RSAPublicKeySpec.class);
        RSAPrivateKeySpec privateKeyCARSA = fact.getKeySpec(kp.getPrivate(),
                RSAPrivateKeySpec.class);
        
        PublicKey publicKeyCA = fact.generatePublic(publicKeyCARSA);
        PrivateKey privateKeyCA = fact.generatePrivate(privateKeyCARSA);
        
		//aan de kant van G
		//maak eerst een keypair aan
        kpg.initialize(2048);
        kp = kpg.genKeyPair();
        
		fact = KeyFactory.getInstance("RSA");
        RSAPublicKeySpec publicKeyGovernment = fact.getKeySpec(kp.getPublic(),
                RSAPublicKeySpec.class);
        RSAPrivateKeySpec privateKeyGovernment = fact.getKeySpec(kp.getPrivate(),
                RSAPrivateKeySpec.class);
        PublicKey publicKeyG = fact.generatePublic(publicKeyGovernment);
        PrivateKey privateKeyG = fact.generatePrivate(privateKeyGovernment);
        
      //digital signature met privkey van CA
        Signature rsa = Signature.getInstance("SHA1withRSA");
        rsa.initSign(privateKeyCA);
        //OwnCertificate certificateG = new OwnCertificate(publicKeyG, "government", 365);
        //rsa.update(certificateG.getBytes());
        byte [] signedCertificateG = rsa.sign();
        
        //nu kan op de smartcard gechecked worden of dat de publickey van G klopt!
        rsa.initVerify(publicKeyCA);
        //rsa.update(certificateG.getBytes());
        System.out.println("Is it verified? " + rsa.verify(signedCertificateG));

	}
	
	public void checkChallenge() throws Exception {
		//first get the certificate with the public key
		//then send challenge and check the challenge!
		
		//5. transferring large amounts of data
		//ask for the public key (certificate)
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		byte [] byteCertificate = new byte [256];
		System.out.println("Ask for the certificate");
		//eerste is offset, tweede geeft lengte aan
		a = new CommandAPDU(IDENTITY_CARD_CLA, GET_CERTIFICATE, (byte) 0x00, (byte) 0x00);
		r= c.transmit(a);
		int numberOfBytesLeft = 0;
		
		if (r.getSW()==SW_VERIFICATION_FAILED) throw new Exception("ERROR, verification failed");
		else if(r.getSW()!=0x9000) {
			 throw new Exception("ERROR, "+ r.getSW()); // print error number if not succeded
		}else {
			System.out.println(" status 9000 ! dus oke");
			System.out.println(r.toString());
			byteCertificate = Arrays.copyOfRange( r.getBytes(), 0, r.getBytes().length -2);
			System.out.println(bytesToHex(byteCertificate));

		}
//		outputStream.write( byteCertificate );
//		byte [] byteCertificate2 = Arrays.copyOfRange( r.getData(), 1, r.getData().length);
//		outputStream.write( byteCertificate2);
//		byteCertificate = outputStream.toByteArray();
//		System.out.println(byteCertificate.length);
		
		
		// change Byte array into Certificate object
		CertificateFactory certFac = CertificateFactory.getInstance("X.509");
		InputStream is = new ByteArrayInputStream(byteCertificate);
		X509Certificate certificateObj = (X509Certificate) certFac.generateCertificate(is);
		System.out.println("Succesfully created certificate on the host app.");
		
		System.out.println("Now we send something and it must be signed and validated!");
		System.out.println("Send random byte array :");
		SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
		random.setSeed(1);
		// send 10 random bytes
		byte [] randbytes = new byte[20];
		random.nextBytes(randbytes);
		System.out.println(bytesToDec(randbytes));
		a = new CommandAPDU(IDENTITY_CARD_CLA, SIGN_RANDOM_BYTE, 0x00, 0x00, randbytes);
		r = c.transmit(a);
		if (r.getSW()==SW_VERIFICATION_FAILED) throw new Exception("ERROR");
		else if(r.getSW()!=0x9000) throw new Exception("Exception on the card: " + r.getSW());
		
		System.out.println("Signed is:");
		Signature signature = Signature.getInstance("SHA1withRSA");
		signature.initVerify(certificateObj.getPublicKey());
		signature.update(randbytes);
		byte [] signedBytes = Arrays.copyOfRange( r.getData(), 1, r.getData().length); // receive signed data from card.
		// Wel nog niet helemaal duidelijk wnr je hoeveel bytes er af moet knippen. Bij het doorsturen van het certificaat werden de SW bits op het einde ook duurgestuurd.
		// Nu is dit niet het geval dus mogen de twee laatste er ook niet afgeknipt worden. Dus steeds checken met debugger!
		System.out.println(bytesToDec(signedBytes));
		boolean ok = signature.verify(signedBytes); 
		System.out.println(ok);
	}
	public void askName() {
		try {
		
		//2. Send PIN
		//die cla is altijd zelfde: gwn aangeven welke instructieset
		//ins geeft aan wat er moet gebeuren --> dit getal staat ook vast in applet
		//new byte[] geeft de pincode aan dus dit zou je normaal ingeven door de gebruiker
		a = new CommandAPDU(IDENTITY_CARD_CLA, VALIDATE_PIN_INS, 0x00, 0x00,new byte[]{0x01,0x02,0x03,0x04});
		r = c.transmit(a);
		System.out.print("Pin ok? ");
		if (r.getSW()==SW_VERIFICATION_FAILED) throw new Exception("PIN INVALID");
		else if(r.getSW()!=0x9000) throw new Exception("Exception on the card: " + r.getSW());
		System.out.println("PIN Verified");
		
		System.out.println("Asking serial number");
		a = new CommandAPDU(IDENTITY_CARD_CLA, GET_SERIAL_INS, 0x00, 0x00,new byte[]{0x01,0x02,0x03,0x04});
		r = c.transmit(a);
		if (r.getSW()==SW_VERIFICATION_FAILED) throw new Exception("ERROR");
		else if(r.getSW()!=0x9000) throw new Exception("Exception on the card: " + r.getSW());
		String str = new String(r.getData(), StandardCharsets.UTF_8);
		System.out.println("SN is: " + str);

		//3. ask name
		System.out.println("Get name");
		a = new CommandAPDU(IDENTITY_CARD_CLA, GET_NAME_INS, 0x00, 0x00,new byte[]{0x01,0x02,0x03,0x04});
		r = c.transmit(a);
		if (r.getSW()==SW_VERIFICATION_FAILED) throw new Exception("ERROR");
		else if(r.getSW()!=0x9000) throw new Exception("Exception on the card: " + r.getSW());
		str = new String(r.getData(), StandardCharsets.UTF_8);
		System.out.println("Name is: " + str);
		
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	public void initRootLayout() {
        try {
            // Load root layout from fxml file.
        	FXMLLoader loader = new FXMLLoader();
            loader.setLocation(MiddlewareMain.class.getResource("RootLayout.fxml"));
            rootLayout = (BorderPane) loader.load();

            // Show the scene containing the root layout.
            Scene scene = new Scene(rootLayout);
            primaryStage.setScene(scene);
            primaryStage.show();
            
            loader = new FXMLLoader();
        	MiddlewareController middlewareController = new MiddlewareController(this);
            loader.setLocation(MiddlewareMain.class.getResource("MiddlewareUI.fxml"));
            loader.setController(middlewareController);
            AnchorPane anchorPane = (AnchorPane) loader.load();
            rootLayout.setCenter(anchorPane);
            
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
	
	public void ConnectSimulator() throws Exception {
//		Connect
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );

		//Simulation:
		c = new SimulatedConnection();

		//Real Card:
		System.out.println("Do simulate connecting...");
		c.connect(); 
		try {
				
			//0. create applet (only for simulator!!!)
			a = new CommandAPDU(0x00, 0xa4, 0x04, 0x00,new byte[]{(byte) 0xa0, 0x00, 0x00, 0x00, 0x62, 0x03, 0x01, 0x08, 0x01}, 0x7f);
			r = c.transmit(a);
			System.out.println(r);
			if (r.getSW()!=0x9000) throw new Exception("select installer applet failed");
			
			a = new CommandAPDU(0x80, 0xB8, 0x00, 0x00,new byte[]{0xb, 0x01,0x02,0x03,0x04, 0x05, 0x06, 0x07, 0x08, 0x09,0x00, 0x00, 0x00}, 0x7f);
			r = c.transmit(a);
			System.out.println(r);
			if (r.getSW()!=0x9000) throw new Exception("Applet creation failed");
			
			//1. Select applet  (not required on a real card, applet is selected by default)
			a = new CommandAPDU(0x00, 0xa4, 0x04, 0x00,new byte[]{0x01,0x02,0x03,0x04, 0x05, 0x06, 0x07, 0x08, 0x09,0x00, 0x00}, 0x7f);
			r = c.transmit(a);
			System.out.println(r);
			if (r.getSW()!=0x9000) throw new Exception("Applet selection failed");
			
		}catch (Exception e) {
			throw e;
		}
		System.out.println("Connected");

	}
	
	public void ConnectRealDevice() throws Exception{
		//TODO hier moet de tijd geinitaliseerd worden (als de kaart er word ingestopt)
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

		c = new Connection();
		((Connection)c).setTerminal(0); //depending on which cardreader you use
		System.out.println("Do real card connecting...");
		c.connect(); 			
		System.out.println("Connected");

		try {
			//TODO moet nog weg maar is gewoon of te testen als het werkt met de real card!
			a = new CommandAPDU(IDENTITY_CARD_CLA, VALIDATE_PIN_INS, 0x00, 0x00,new byte[]{0x01,0x02,0x03,0x04});
			r = c.transmit(a);
			System.out.print("Pin ok? ");
			if (r.getSW()==SW_VERIFICATION_FAILED) throw new Exception("PIN INVALID");
			else if(r.getSW()!=0x9000) throw new Exception("Exception on the card: " + r.getSW());
			System.out.println("PIN Verified");
			
			System.out.println("Asking serial number");
			a = new CommandAPDU(IDENTITY_CARD_CLA, GET_SERIAL_INS, 0x00, 0x00,new byte[]{0x01,0x02,0x03,0x04});
			r = c.transmit(a);
			if (r.getSW()==SW_VERIFICATION_FAILED) throw new Exception("ERROR");
			else if(r.getSW()!=0x9000) throw new Exception("Exception on the card: " + r.getSW());
			String str = new String(r.getData(), StandardCharsets.UTF_8);
			System.out.println("SN is: " + str);
		}
		catch (Exception e) {
			throw e;
		}

	}
	
	public void connectTimestampServer() {
		SSLSocketFactory sslSocketFactory = 
                (SSLSocketFactory)SSLSocketFactory.getDefault();
        try {
            timestampSocket = sslSocketFactory.createSocket("localhost", port);  
        } catch (IOException ex) {
            System.out.println("ERROR WITH CONNECTION TO G: " + ex);
        }
        System.out.println("Connected to timestamp server:" + timestampSocket);
          
	}
	
	public void askTime() {
        try {
        	System.out.println(timestampSocket);
            PrintWriter out = new PrintWriter(timestampSocket.getOutputStream(), true);
            byte[] dataToTest = ("test".getBytes());

            try (BufferedReader bufferedReader = 
                    new BufferedReader(
                            new InputStreamReader(timestampSocket.getInputStream()))) {
            	out.println(1);
            	
                String received = bufferedReader.readLine();
                System.out.println("I received the signed time: " + received);
                KeyStore keyStore = KeyStore.getInstance("JKS");
                String fileName = new java.io.File("").getAbsolutePath() + "\\middleware\\middleware.jks";
                FileInputStream fis = new FileInputStream(fileName);
                System.out.println("File found!");
                keyStore.load(fis,"jonasaxel".toCharArray());
                fis.close();
                //in middleware zitten alle (public ) keys dat middleware heeft normaal 
                //is dit enkel die van de CA maar dit ziter ng niet in
                java.security.cert.Certificate certificateGovernment = keyStore.getCertificate("government");
                
                Signature rsa = Signature.getInstance("SHA1withRSA");
                rsa.initVerify(certificateGovernment.getPublicKey());
                rsa.update(dataToTest);
                System.out.println("Is it verified? " + rsa.verify(received.getBytes()));
//                Scanner scanner = new Scanner(System.in);
//                while(true){
//                    System.out.println("Enter something:");
//                    String inputLine = scanner.nextLine();
//                    if(inputLine.equals("q")){
//                        break;
//                    }
//                     
//                    out.println(inputLine);
//                }
            } catch (SignatureException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (KeyStoreException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (InvalidKeyException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (NoSuchAlgorithmException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (CertificateException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
             
        } catch (IOException ex) {
            System.out.println("ERROR WITH RECEIVING TIME: " + ex);
        }
	}
	
	public static void main(String[] args) throws Exception {
		launch(args);
	}
	
	
	private final static char[] hexArray = "0123456789ABCDEF".toCharArray();
	public static String bytesToHex(byte[] bytes) {
	    char[] hexChars = new char[bytes.length * 2];
	    for ( int j = 0; j < bytes.length; j++ ) {
	        int v = bytes[j] & 0xFF;
	        hexChars[j * 2] = hexArray[v >>> 4];
	        hexChars[j * 2 + 1] = hexArray[v & 0x0F];
	    }
	    String str= "";
	    for ( int j = 0; j < hexChars.length; j+=2 ) {
	    	str += "0x"+ hexChars[j]+ hexChars[j+1]+", ";
	    }
	    return str;
	}
	public String bytesToDec(byte[] barray)
	 {
	   String str = "";
	   for (byte b : barray)
	      	str += (int)b + ", ";
	   return str;
	 }
}
