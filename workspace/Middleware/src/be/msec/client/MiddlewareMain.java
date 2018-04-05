package be.msec.client;

import be.msec.client.connection.Connection;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.SocketFactory;
import javax.net.ssl.SSLSocketFactory;
import be.msec.client.connection.IConnection;
import be.msec.client.connection.SimulatedConnection;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Scene;
import javafx.scene.layout.AnchorPane;
import javafx.scene.layout.BorderPane;
import javafx.stage.Stage;
import javax.smartcardio.*;

public class MiddlewareMain extends Application {

	private Stage primaryStage;
	private BorderPane rootLayout;

	private final static byte IDENTITY_CARD_CLA = (byte) 0x80;
	private static final byte VALIDATE_PIN_INS = 0x22;
	private final static short SW_VERIFICATION_FAILED = 0x6300;
	private final static short SW_PIN_VERIFICATION_REQUIRED = 0x6301;
	private static final byte GET_SERIAL_INS = 0x26;
	private static final byte UPDATE_TIME = 0x25;
	private static final byte GET_NAME_INS = 0x24;
	private static final byte SIGN_RANDOM_BYTE = 0x27;
	private static final byte GET_CERTIFICATE = 0x28;
	private static final byte test = 0x01;
	static final int portG = 8001;
	static final int portSP = 8003;
	private Socket timestampSocket = null;
	private Socket serviceProviderSocket = null;
	IConnection c;
	CommandAPDU a;
	ResponseAPDU r;
	
	private ServerSocket socket;
    private Socket middlewareSocket;

	public void start(Stage stage) throws IOException {
		this.primaryStage = stage;
        this.primaryStage.setTitle("Card reader UI");
//      initRootLayout();
        try {
        	
//			askName();     	
        	// 1. UPDATE_TIME_ON_CARD_ROUTINE
			if(connectTimestampServer()) {
				TimeInfoStruct signedTime = askTimeToTimestampServer();
			 	if(signedTime !=null) {
			 		// make connection to the card (simulator) and send the bytes
					connectToCard(true); // true => simulatedconnection
					sendTimeToCard(signedTime);
			 	}
			}

//			checkChallenge();
			
//			InfoStruct infoStruct = new ServiceProviderInfoStruct(null, "een serviceke", 24);
//			OwnCertificate ownCertificate = CAService.getSignedCertificate(infoStruct);
//			System.out.println(ownCertificate.verifySignature(CAService.getPublicKey()));
			
		} catch (Exception e) {
			e.printStackTrace();
		}
	}


	private void listenToServiceProvider() {
		ObjectInputStream objectinputstream = null;
		try {
			ObjectOutputStream out = new ObjectOutputStream(middlewareSocket.getOutputStream());
			while(true) {
				System.out.println("Listening to service provider...");
				objectinputstream = new ObjectInputStream(middlewareSocket.getInputStream());
				Integer received = (Integer) objectinputstream.readObject();
				System.out.println("received: " + received);
				
				byte[] time = new byte[] { (byte) 1, (byte) 0, (byte) 1 };
				TimeInfoStruct timeinfostruct = new TimeInfoStruct(new byte[4], time);
				out.writeObject(timeinfostruct);
				
			}
		
		
		} catch (IOException | ClassNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		
	}


	// -------------------------------------------------
	// ------- TEST METHODES wITH USEFULL CODE ----------
	// -------------------------------------------------

	public void testSetup()
			throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException {
		// aan de CA kant
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
		kpg.initialize(2048);
		KeyPair kp = kpg.genKeyPair();

		KeyFactory fact = KeyFactory.getInstance("RSA");
		RSAPublicKeySpec publicKeyCARSA = fact.getKeySpec(kp.getPublic(), RSAPublicKeySpec.class);
		RSAPrivateKeySpec privateKeyCARSA = fact.getKeySpec(kp.getPrivate(), RSAPrivateKeySpec.class);

		PublicKey publicKeyCA = fact.generatePublic(publicKeyCARSA);
		PrivateKey privateKeyCA = fact.generatePrivate(privateKeyCARSA);

		// aan de kant van G
		// maak eerst een keypair aan
		kpg.initialize(2048);
		kp = kpg.genKeyPair();

		fact = KeyFactory.getInstance("RSA");
		RSAPublicKeySpec publicKeyGovernment = fact.getKeySpec(kp.getPublic(), RSAPublicKeySpec.class);
		RSAPrivateKeySpec privateKeyGovernment = fact.getKeySpec(kp.getPrivate(), RSAPrivateKeySpec.class);
		PublicKey publicKeyG = fact.generatePublic(publicKeyGovernment);
		PrivateKey privateKeyG = fact.generatePrivate(privateKeyGovernment);

		// digital signature met privkey van CA
		Signature rsa = Signature.getInstance("SHA1withRSA");
		rsa.initSign(privateKeyCA);
		// OwnCertificate certificateG = new OwnCertificate(publicKeyG, "government",
		// 365);
		// rsa.update(certificateG.getBytes());
		byte[] signedCertificateG = rsa.sign();

		// nu kan op de smartcard gechecked worden of dat de publickey van G klopt!
		rsa.initVerify(publicKeyCA);
		// rsa.update(certificateG.getBytes());
		System.out.println("Is it verified? " + rsa.verify(signedCertificateG));

	}

	/**
	 * Test Methode 
	 * First get the certificate with the public key
	 * then send challenge and check the challenge!
	 * ( transfer big amount of data)
	 * @throws Exception
	 */
	public void checkChallenge() throws Exception {
		// first get the certificate with the public key
		// then send challenge and check the challenge!

		// 5. transferring large amounts of data
		// ask for the public key (certificate)
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		byte[] byteCertificate = new byte[256];
		System.out.println("Ask for the certificate");
		a = new CommandAPDU(IDENTITY_CARD_CLA, GET_CERTIFICATE, (byte) 0x00, (byte) 0x00);
		r = c.transmit(a);
		if (r.getSW() == SW_VERIFICATION_FAILED)
			throw new Exception("ERROR, verification failed");
		else if (r.getSW() != 0x9000) {
			throw new Exception("ERROR, " + r.getSW()); // print error number if not succeded
		} else {
			System.out.println(" status 9000 ! dus oke");
			byteCertificate = Arrays.copyOfRange(r.getBytes(), 0, r.getBytes().length - 2); // -2 bytes to cut off the SW-bytes
			System.out.println(bytesToHex(byteCertificate));

		}
		// change Byte array into Certificate object
		CertificateFactory certFac = CertificateFactory.getInstance("X.509");
		InputStream is = new ByteArrayInputStream(byteCertificate);
		X509Certificate certificateObj = (X509Certificate) certFac.generateCertificate(is);
		System.out.println("Succesfully created certificate on the host app.");

		// test Sign methode on card
		System.out.println("Send random byte array :");
		SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
		random.setSeed(1);
		// send 10 random bytes
		byte[] randbytes = new byte[20];
		random.nextBytes(randbytes);
		System.out.println(bytesToDec(randbytes));
		a = new CommandAPDU(IDENTITY_CARD_CLA, SIGN_RANDOM_BYTE, 0x00, 0x00, randbytes);
		r = c.transmit(a);
		if (r.getSW() == SW_VERIFICATION_FAILED)
			throw new Exception("ERROR");
		else if (r.getSW() != 0x9000)
			throw new Exception("Exception on the card: " + r.getSW());

		System.out.println("Signed is:");
		Signature signature = Signature.getInstance("SHA1withRSA");
		signature.initVerify(certificateObj.getPublicKey());
		signature.update(randbytes);
		byte[] signedBytes = Arrays.copyOfRange(r.getData(), 1, r.getData().length); // receive signed data from card.
		// Wel nog niet helemaal duidelijk wnr je hoeveel bytes er af moet knippen. Bij
		// het doorsturen van het certificaat werden de SW bits op het einde ook
		// duurgestuurd.
		// Nu is dit niet het geval dus mogen de twee laatste er ook niet afgeknipt
		// worden. Dus steeds checken met debugger!
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
		a = new CommandAPDU(IDENTITY_CARD_CLA, VALIDATE_PIN_INS, 0x00, 0x00,new byte[]{0x31,0x32,0x33,0x34});
		r = c.transmit(a);
		System.out.print("Pin ok? ");
		if (r.getSW()==SW_VERIFICATION_FAILED) throw new Exception("PIN INVALID");
		else if(r.getSW()!=0x9000) throw new Exception("Exception on the card: " + r.getSW());
		System.out.println("PIN Verified");
		
		System.out.println("Asking serial number");
		a = new CommandAPDU(IDENTITY_CARD_CLA, GET_SERIAL_INS, 0x00, 0x00,new byte[]{0x31,0x32,0x33,0x34});
		r = c.transmit(a);
		if (r.getSW()==SW_VERIFICATION_FAILED) throw new Exception("ERROR");
		else if(r.getSW()!=0x9000) throw new Exception("Exception on the card: " + r.getSW());
		String str = new String(r.getData(), StandardCharsets.UTF_8);
		System.out.println("SN is: " + str);

		//3. ask name
		System.out.println("Get name");
		a = new CommandAPDU(IDENTITY_CARD_CLA, GET_NAME_INS, 0x00, 0x00,new byte[]{0x31,0x32,0x33,0x34});
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
	
	// ---------------------------
	// ------- INIT GUI ----------
	// ---------------------------
	
	public void initRootLayout() {
        try {
            // Load root layout from fxml file.
            FXMLLoader loader = new FXMLLoader();
            loader.setLocation(MiddlewareMain.class.getResource("RootMenu.fxml"));
            rootLayout = (BorderPane) loader.load();

            // Show the scene containing the root layout.
            Scene scene = new Scene(rootLayout);
            primaryStage.setScene(scene);
            //scene.getStylesheets().add("be.msec.stylesheet.css");

            // Give the controller access to the main app.
            RootMenuController controllerRoot = loader.getController();
            controllerRoot.setMain(this);
            primaryStage.show();
            
            initPinLoginView();
            
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
	private void initPinLoginView() throws IOException {
		FXMLLoader loader = new FXMLLoader();
        loader.setLocation(MiddlewareMain.class.getResource("pinLoginView.fxml"));
        System.out.println("Loading Main login Page");
        AnchorPane loginView = (AnchorPane) loader.load();
        
        //controller initialiseren + koppelen aan mainClient
        MiddlewareController controller = loader.getController();
        controller.setMain(this);
        rootLayout.setCenter(loginView);
	}
	
	// ----------------------------------
	// ------- CONNECT TO CARD ----------
	// ----------------------------------
	
	/**
	 * Connect to the javacard
	 * @param simulatedConnection, true= simulated connection ; false = connect to real card terminal
	 * @throws Exception
	 */
	public void connectToCard(boolean simulatedConnection) throws Exception {
		
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
		
		if(simulatedConnection) {
			System.out.println("Simulated connection");
			c = new SimulatedConnection();
			c.connect();
			createAppletForSimulator();
		}else {
			System.out.println("Real connection");
			c = new Connection();
			((Connection) c).setTerminal(0); // depending on which cardreader you use
			c.connect();
		}
	}
	
	private void createAppletForSimulator() {
		try {
			// 0. create applet (only for simulator!!!)
			a = new CommandAPDU(0x00, 0xa4, 0x04, 0x00,
					new byte[] { (byte) 0xa0, 0x00, 0x00, 0x00, 0x62, 0x03, 0x01, 0x08, 0x01 }, 0x7f);
			r = c.transmit(a);
			System.out.println(r);
			if (r.getSW() != 0x9000)
				throw new Exception("select installer applet failed");

			a = new CommandAPDU(0x80, 0xB8, 0x00, 0x00,
					new byte[] { 0xb, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x00, 0x00 }, 0x7f);
			r = c.transmit(a);
			System.out.println(r);
			if (r.getSW() != 0x9000)
				throw new Exception("Applet creation failed");

			// 1. Select applet (not required on a real card, applet is selected by default)
			a = new CommandAPDU(0x00, 0xa4, 0x04, 0x00,
					new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x00 }, 0x7f);
			r = c.transmit(a);
			System.out.println(r);
			if (r.getSW() != 0x9000)
				throw new Exception("Applet selection failed");

		} catch (Exception e) {
			System.out.println("ERROR IN MAKING CONNECTION WITH SIMULATOR: " + e);
		}
	}

	
	// -------------------------------------------------
	// ------- TIMESTAMP SERVER COMMUNICATION ----------
	// -------------------------------------------------
	public boolean connectTimestampServer() {
		// setup ssl properties
		System.setProperty("javax.net.ssl.keyStore", "sslKeyStore.store");
        System.setProperty("javax.net.ssl.keyStorePassword", "jonasaxel");
        System.setProperty("javax.net.ssl.trustStore", "sslKeyStore.store");
        System.setProperty("javax.net.ssl.trustStorePassword", "jonasaxel");
		
		SSLSocketFactory sslSocketFactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
		try {
			timestampSocket = sslSocketFactory.createSocket("localhost", portG);
		} catch (IOException ex) {
			System.out.println("ERROR WITH CONNECTION TO G: " + ex);
			return false;
		}
		System.out.println("Connected to timestamp server:" + timestampSocket);
		return true;

	}
	
	public void connectServiceProvider() {
		try {
			socket = new ServerSocket(portSP);
			System.out.println("Serversocket is listening");
			middlewareSocket = socket.accept();
			System.out.println("Socket connection accepted");
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	public TimeInfoStruct askTimeToTimestampServer() throws Exception {
		// hiervoor is eigenlijk geen certificaat nodig want de smartcard heeft de PKg
		// hier wil ik enkel de tijd terug krijgen: eenmaal gehashed endan gesigned met
		// SKg en eenmaal plain text
		TimeInfoStruct timeInfoStruct = null;
		ObjectOutputStream objectoutputstream = null;
		ObjectInputStream objectinputstream = null;
		try {
			System.out.println("Try to send to the timestampserver");

			try {
				objectoutputstream = new ObjectOutputStream(timestampSocket.getOutputStream());
				// Command = 1 => GetSignedTime
				objectoutputstream.writeObject(1);
				objectinputstream = new ObjectInputStream(timestampSocket.getInputStream());
				// Cast serialized object into new object
				timeInfoStruct = (TimeInfoStruct) objectinputstream.readObject();
				
				System.out.println("Received date and signedData (both in byte array)");
				// System.out.println("Date from server: " + timeInfoStruct.getDate());
				// System.out.println(bytesToDec(timeInfoStruct.getSignedData()));
				objectinputstream.close();

			} catch (EOFException | ClassNotFoundException exc) {
				objectinputstream.close();
			}
		} catch (IOException ex) {
			System.out.println("ERROR WITH RECEIVING TIME: " + ex);
		}
		return timeInfoStruct;
	}
	
	// ------------------------------------------
	// ------- JAVA CARD COMMUNICATION ----------
	// ------------------------------------------
	
	/**
	 * Send the signedtimestamp to the card so the time can be verifyed and updated
	 * @param timeInfoStruct
	 */
	private boolean sendTimeToCard(TimeInfoStruct timeInfoStruct) {
		// concatenate all bytes into one big data array, this toSend needs to be given to the card
		byte[] toSend = new byte[timeInfoStruct.getSignedData().length + timeInfoStruct.getDate().length];
		System.arraycopy(timeInfoStruct.getSignedData(), 0, toSend, 0, timeInfoStruct.getSignedData().length);
		System.arraycopy(timeInfoStruct.getDate(), 0, toSend, timeInfoStruct.getSignedData().length, timeInfoStruct.getDate().length);
		
		System.out.println("Send signed time bytes with extended APDU"); 
		a = new CommandAPDU(IDENTITY_CARD_CLA, UPDATE_TIME, 0x00, 0x00, toSend);
		try {
			if(r.getSW()!=0x9000) throw new Exception("Exception on the card: " + r.getSW());
			System.out.println("DATE UPDATED ");
			
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return false;
		}
		return true;
	}
	
	public Boolean loginWithPin(byte[] pin) throws Exception {
		if(pin.length != 4) { // limit length of the pin to prevent dangerous input
			throw new Exception("Pin has to be 4 characters");
		}
		System.out.println(bytesToHex(pin));
		a = new CommandAPDU(IDENTITY_CARD_CLA, VALIDATE_PIN_INS, 0x00, 0x00, pin);
		r = c.transmit(a);
		System.out.print("Pin ok? ");
		if (r.getSW()==SW_VERIFICATION_FAILED) return false;
		else if(r.getSW() == 0x26368) throw new Exception("Wrong Pin size!");
		else if(r.getSW()!=0x9000) throw new Exception("Exception on the card: " + r.getSW());
	
		return true;
	}
	

	public static void main(String[] args) throws Exception {
		launch(args);
	}

	// ------------------------------------
	// ------- UTILITY FUNCTIONS ----------
	// ------------------------------------
	
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
			str += "0x" + hexChars[j] + hexChars[j + 1] + ", ";
		}
		return str;
	}

	public String bytesToDec(byte[] barray) {
		String str = "";
		for (byte b : barray)
			str += (int) b + ", ";
		return str;
	}
}
