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
			ConnectSimulator();
//			ConnectRealDevice();
//			
			askName();
			checkChallenge();
//			connectTimestampServer();
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
        OwnCertificate certificateG = new OwnCertificate(publicKeyG, "government", 365);
        rsa.update(certificateG.getBytes());
        byte [] signedCertificateG = rsa.sign();
        
        //nu kan op de smartcard gechecked worden of dat de publickey van G klopt!
        rsa.initVerify(publicKeyCA);
        rsa.update(certificateG.getBytes());
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
		
		if (r.getSW()==SW_VERIFICATION_FAILED) throw new Exception("ERROR");
		else if(r.getSW()!=0x9000) {
//			numberOfBytesLeft = r.getSW() - 24832;  
			byteCertificate = r.getBytes();
//			byteCertificate = Arrays.copyOfRange( byteCertificate, 1, byteCertificate.length -1);
//			if(numberOfBytesLeft > 0 ) {
//			System.out.println("There are " +  numberOfBytesLeft + " number of bytes left --> ask again!");
//			r= c.transmit(a);
//			System.out.println("the second time: "+ r.getSW());
//			}
		}
		for (int i = 0; i < byteCertificate.length; i++) {
				System.out.println(i + ": " + byteCertificate[i]);
		}
		final byte[] realCertificateByteArray = new byte[]{(byte)48, (byte)-126, (byte)1, (byte)-67, (byte)48, (byte)-126, (byte)1, (byte)103, (byte)-96, (byte)3, (byte)2, (byte)1, (byte)2, (byte)2, (byte)5, (byte)0, (byte)-73, (byte)-43, (byte)96, (byte)-107, (byte)48, (byte)13, (byte)6, (byte)9, (byte)42, (byte)-122, (byte)72, (byte)-122, (byte)-9, (byte)13, (byte)1, (byte)1, (byte)5, (byte)5, (byte)0, (byte)48, (byte)100, (byte)49, (byte)11, (byte)48, (byte)9, (byte)6, (byte)3, (byte)85, (byte)4, (byte)6, (byte)19, (byte)2, (byte)66, (byte)69, (byte)49, (byte)13, (byte)48, (byte)11, (byte)6, (byte)3, (byte)85, (byte)4, (byte)7, (byte)12, (byte)4, (byte)71, (byte)101, (byte)110, (byte)116, (byte)49, (byte)25, (byte)48, (byte)23, (byte)6, (byte)3, (byte)85, (byte)4, (byte)10, (byte)12, (byte)16, (byte)75, (byte)97, (byte)72, (byte)111, (byte)32, (byte)83, (byte)105, (byte)110, (byte)116, (byte)45, (byte)76, (byte)105, (byte)101, (byte)118, (byte)101, (byte)110, (byte)49, (byte)20, (byte)48, (byte)18, (byte)6, (byte)3, (byte)85, (byte)4, (byte)11, (byte)12, (byte)11, (byte)86, (byte)97, (byte)107, (byte)103, (byte)114, (byte)111, (byte)101, (byte)112, (byte)32, (byte)73, (byte)84, (byte)49, (byte)21, (byte)48, (byte)19, (byte)6, (byte)3, (byte)85, (byte)4, (byte)3, (byte)12, (byte)12, (byte)74, (byte)97, (byte)110, (byte)32, (byte)86, (byte)111, (byte)115, (byte)115, (byte)97, (byte)101, (byte)114, (byte)116, (byte)48, (byte)32, (byte)23, (byte)13, (byte)49, (byte)48, (byte)48, (byte)50, (byte)50, (byte)52, (byte)48, (byte)57, (byte)52, (byte)51, (byte)48, (byte)50, (byte)90, (byte)24, (byte)15, (byte)53, (byte)49, (byte)55, (byte)57, (byte)48, (byte)49, (byte)48, (byte)57, (byte)49, (byte)57, (byte)50, (byte)57, (byte)52, (byte)50, (byte)90, (byte)48, (byte)100, (byte)49, (byte)11, (byte)48, (byte)9, (byte)6, (byte)3, (byte)85, (byte)4, (byte)6, (byte)19, (byte)2, (byte)66, (byte)69, (byte)49, (byte)13, (byte)48, (byte)11, (byte)6, (byte)3, (byte)85, (byte)4, (byte)7, (byte)12, (byte)4, (byte)71, (byte)101, (byte)110, (byte)116, (byte)49, (byte)25, (byte)48, (byte)23, (byte)6, (byte)3, (byte)85, (byte)4, (byte)10, (byte)12, (byte)16, (byte)75, (byte)97, (byte)72, (byte)111, (byte)32, (byte)83, (byte)105, (byte)110, (byte)116, (byte)45, (byte)76, (byte)105, (byte)101, (byte)118, (byte)101, (byte)110, (byte)49, (byte)20, (byte)48, (byte)18, (byte)6, (byte)3, (byte)85, (byte)4, (byte)11, (byte)12, (byte)11, (byte)86, (byte)97, (byte)107, (byte)103, (byte)114, (byte)111, (byte)101, (byte)112, (byte)32, (byte)73, (byte)84, (byte)49, (byte)21, (byte)48, (byte)19, (byte)6, (byte)3, (byte)85, (byte)4, (byte)3, (byte)12, (byte)12, (byte)74, (byte)97, (byte)110, (byte)32, (byte)86, (byte)111, (byte)115, (byte)115, (byte)97, (byte)101, (byte)114, (byte)116, (byte)48, (byte)92, (byte)48, (byte)13, (byte)6, (byte)9, (byte)42, (byte)-122, (byte)72, (byte)-122, (byte)-9, (byte)13, (byte)1, (byte)1, (byte)1, (byte)5, (byte)0, (byte)3, (byte)75, (byte)0, (byte)48, (byte)72, (byte)2, (byte)65, (byte)0, (byte)-73, (byte)-43, (byte)96, (byte)-107, (byte)82, (byte)25, (byte)-66, (byte)34, (byte)5, (byte)-58, (byte)75, (byte)-39, (byte)-54, (byte)43, (byte)25, (byte)-117, (byte)80, (byte)-62, (byte)51, (byte)19, (byte)59, (byte)-70, (byte)-100, (byte)85, (byte)24, (byte)-57, (byte)108, (byte)-98, (byte)-2, (byte)1, (byte)-80, (byte)-39, (byte)63, (byte)93, (byte)112, (byte)7, (byte)4, (byte)18, (byte)-11, (byte)-98, (byte)17, (byte)126, (byte)-54, (byte)27, (byte)-56, (byte)33, (byte)77, (byte)-111, (byte)-74, (byte)-78, (byte)88, (byte)70, (byte)-22, (byte)-3, (byte)15, (byte)16, (byte)37, (byte)-18, (byte)92, (byte)74, (byte)124, (byte)-107, (byte)-116, (byte)-125, (byte)2, (byte)3, (byte)1, (byte)0, (byte)1, (byte)48, (byte)13, (byte)6, (byte)9, (byte)42, (byte)-122, (byte)72, (byte)-122, (byte)-9, (byte)13, (byte)1, (byte)1, (byte)5, (byte)5, (byte)0, (byte)3, (byte)65, (byte)0, (byte)33, (byte)97, (byte)121, (byte)-25, (byte)43, (byte)-47, (byte)113, (byte)-104, (byte)-11, (byte)-42, (byte)-46, (byte)-17, (byte)1, (byte)-38, (byte)50, (byte)59, (byte)-63, (byte)-74, (byte)-33, (byte)90, (byte)92, (byte)-59, (byte)99, (byte)-17, (byte)-60, (byte)17, (byte)25, (byte)79, (byte)68, (byte)68, (byte)-57, (byte)-8, (byte)-64, (byte)35, (byte)-19, (byte)-114, (byte)110, (byte)-116, (byte)31, (byte)-126, (byte)-24, (byte)54, (byte)71, (byte)82, (byte)-53, (byte)-78, (byte)-84, (byte)-45, (byte)-83, (byte)87, (byte)68, (byte)124, (byte)-1, (byte)-128, (byte)-49, (byte)124, (byte)103, (byte)28, (byte)56, (byte)-114, (byte)-10, (byte)97, (byte)-78, (byte)54};

		System.out.println("length: " + byteCertificate.length + " ------ real length: " + realCertificateByteArray.length );
		
//		outputStream.write( byteCertificate );
//		byte [] byteCertificate2 = Arrays.copyOfRange( r.getData(), 1, r.getData().length);
//		outputStream.write( byteCertificate2);
//		byteCertificate = outputStream.toByteArray();
//		System.out.println(byteCertificate.length);
//		CertificateFactory certFac = CertificateFactory.getInstance("X.509");
//
		for (int i = 0; i < byteCertificate.length; i++) {
			if(byteCertificate[i] != realCertificateByteArray[i]) {
				System.out.println("vershil bij: " + i + ": " + byteCertificate[i] + 
						" vs: " + realCertificateByteArray[i]);
			}
		}
		
	
		
//		InputStream is = new ByteArrayInputStream(byteCertificate);
//		X509Certificate certificate2 = (X509Certificate) certFac.generateCertificate(is);
//		System.out.println("Succesfully created certificate on the host app.");
		
//		System.out.println("Now we send something and it must be signed and validated!");
//		System.out.println("Send random byte array name");
//		SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
//		byte [] randbytes = new byte[20];
//		random.nextBytes(randbytes);
//		a = new CommandAPDU(IDENTITY_CARD_CLA, SIGN_RANDOM_BYTE, 0x00, 0x00, randbytes);
//		r = c.transmit(a);
//		if (r.getSW()==SW_VERIFICATION_FAILED) throw new Exception("ERROR");
//		else if(r.getSW()!=0x9000) throw new Exception("Exception on the card: " + r.getSW());
//		String str = new String(r.getBytes(), StandardCharsets.UTF_8);
//		System.out.println("Signed is: " + str);
//		Signature signature = Signature.getInstance("SHA1withRSA");
////		signature.initVerify(certificate2.getPublicKey());
//		signature.update(randbytes);
////		byte [] byteCertificate2 = Arrays.copyOfRange( r.getData(), 1, r.getData().length);
//		System.out.println("length of data: " + r.getData().length);
//		boolean ok = signature.verify(Arrays.copyOfRange( r.getData(), 0, r.getData().length));
//		System.out.println(ok);
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
	
}
