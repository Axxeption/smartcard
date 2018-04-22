package be.msec.client;

import be.msec.ServiceProviderAction;
import be.msec.client.connection.Connection;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URISyntaxException;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.SocketFactory;
import javax.net.ssl.SSLSocketFactory;
import be.msec.client.connection.IConnection;
import be.msec.client.connection.SimulatedConnection;
//import javacard.security.KeyBuilder;
//import javacard.security.RSAPublicKey;

import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import javafx.application.Application;
import javafx.application.Platform;
import javafx.fxml.FXMLLoader;
import javafx.scene.Scene;
import javafx.scene.layout.AnchorPane;
import javafx.scene.layout.BorderPane;
import javafx.stage.Stage;
import javax.smartcardio.*;

public class MiddlewareMain extends Application {

	private Stage primaryStage;
	private BorderPane rootLayout;
	private MiddlewareController middlewareController;
	

	private final static byte IDENTITY_CARD_CLA = (byte) 0x80;
	private static final byte VALIDATE_PIN_INS = 0x22;
	private final static short SW_VERIFICATION_FAILED = 0x6300;
	private final static short SW_PIN_VERIFICATION_REQUIRED = 0x6301;
	private static final byte GET_SERIAL_INS = 0x26;
	private static final byte UPDATE_TIME = 0x25;
	private static final byte GET_NAME_INS = 0x24;
	private static final byte SIGN_RANDOM_BYTE = 0x27;
	private static final byte GET_CERTIFICATE = 0x28;
	private static final byte AUTHENTICATE_SP = 0x21;
	private static final byte VERIFY_CHALLENGE = 0x29;
	private static final byte AUTHENTICATE_CARD = 0x30;
	private static final byte RELEASE_ATTRIBUTE = 0x31;
	static final int portG = 8001;
	static final int portSP = 8003;
	private Socket timestampSocket = null;
	private Socket serviceProviderSocket = null;
	IConnection c;
	CommandAPDU a;
	ResponseAPDU r;
	boolean connectedWithSC = false;
	boolean pinVerified = false;

	private ServerSocket socket;
	private Socket middlewareSocket;
	
	//for testing
	private byte[] pubMod_CA = new byte[] {(byte) -40, (byte) -96, (byte) 115, (byte) 21, (byte) -10, (byte) -66, (byte) 80, (byte) 28, (byte) -124, (byte) 29, (byte) 98, (byte) -23, (byte) -72, (byte) 60, (byte) 89, (byte) 21, (byte) -37, (byte) -122, (byte) -14, (byte) 94, (byte) -92, (byte) 48, (byte) 98, (byte) -35, (byte) 5, (byte) -37, (byte) -50, (byte) -46, (byte) 21, (byte) -117, (byte) -48, (byte) -20, (byte) 50, (byte) -80, (byte) -41, (byte) -126, (byte) -102, (byte) 63, (byte) -2, (byte) -10, (byte) 3, (byte) -86, (byte) -54, (byte) 105, (byte) -64, (byte) 47, (byte) -23, (byte) -104, (byte) -39, (byte) 35, (byte) 107, (byte) -46, (byte) -73, (byte) 2, (byte) 120, (byte) 112, (byte) -127, (byte) -37, (byte) 117, (byte) -79, (byte) 15, (byte) 9, (byte) 48, (byte) -45}; 
	private byte[] pubExp_CA = new byte[] { (byte) 1, (byte) 0, (byte) 1 };


	public void start(Stage stage) throws IOException {
		this.primaryStage = stage;
		this.primaryStage.setTitle("Card reader UI");
		launchPinInputScreen();
		try {
//			UPDATE_TIME_ON_CARD_ROUTINE();
			connectToCard(true);
			connectServiceProvider();
			// askName();

			// UPDATE_TIME_ON_CARD_ROUTINE();

			// checkChallenge();

		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private void UPDATE_TIME_ON_CARD_ROUTINE() throws Exception {
		if (connectTimestampServer()) {
			TimeStruct signedTime = askTimeToTimestampServer();
			if (signedTime != null) {
				// make connection to the card (simulator) and send the bytes
				connectToCard(false); // true => simulatedconnection
				sendTimeToCard(signedTime);
			}
		}
	}
	// -------------------------------------------------
	// ------- TEST METHODES wITH USEFULL CODE ----------
	// -------------------------------------------------


	/**
	 * Test Methode First get the certificate with the public key then send
	 * challenge and check the challenge! ( transfer big amount of data)
	 * 
	 * @throws Exception
	 */
	public void checkChallenge() throws Exception {
		// first get the certificate with the public key
		// then send challenge and check the challenge!

		// 5. transferring large amounts of data
		// ask for the public key (certificate)
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		byte[] byteCertificate = new byte[256];
		//System.out.println("Ask for the certificate");
		a = new CommandAPDU(IDENTITY_CARD_CLA, GET_CERTIFICATE, (byte) 0x00, (byte) 0x00);
		r = c.transmit(a);
		if (r.getSW() == SW_VERIFICATION_FAILED)
			throw new Exception("ERROR, verification failed");
		else if (r.getSW() != 0x9000) {
			throw new Exception("ERROR, " + r.getSW()); // print error number if not succeded
		} else {
			//System.out.println(" status 9000 ! dus oke");
			byteCertificate = Arrays.copyOfRange(r.getBytes(), 0, r.getBytes().length - 2); // -2 bytes to cut off the
																							// SW-bytes
			//System.out.println(bytesToHex(byteCertificate));

		}
		// change Byte array into Certificate object
		CertificateFactory certFac = CertificateFactory.getInstance("X.509");
		InputStream is = new ByteArrayInputStream(byteCertificate);
		X509Certificate certificateObj = (X509Certificate) certFac.generateCertificate(is);
		//System.out.println("Succesfully created certificate on the host app.");

		// test Sign methode on card
		//System.out.println("Send random byte array :");
		SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
		random.setSeed(1);
		// send 10 random bytes
		byte[] randbytes = new byte[20];
		random.nextBytes(randbytes);
		//System.out.println(bytesToDec(randbytes));
		a = new CommandAPDU(IDENTITY_CARD_CLA, SIGN_RANDOM_BYTE, 0x00, 0x00, randbytes);
		r = c.transmit(a);
		if (r.getSW() == SW_VERIFICATION_FAILED)
			throw new Exception("ERROR");
		else if (r.getSW() != 0x9000)
			throw new Exception("Exception on the card: " + r.getSW());

		//System.out.println("Signed is:");
		Signature signature = Signature.getInstance("SHA1withRSA");
		signature.initVerify(certificateObj.getPublicKey());
		signature.update(randbytes);
		byte[] signedBytes = Arrays.copyOfRange(r.getData(), 1, r.getData().length); // receive signed data from card.
		// Wel nog niet helemaal duidelijk wnr je hoeveel bytes er af moet knippen. Bij
		// het doorsturen van het certificaat werden de SW bits op het einde ook
		// duurgestuurd.
		// Nu is dit niet het geval dus mogen de twee laatste er ook niet afgeknipt
		// worden. Dus steeds checken met debugger!
		//System.out.println(bytesToDec(signedBytes));
		boolean ok = signature.verify(signedBytes);
		//System.out.println(ok);
	}

	public void askName() {
		try {
			// 2. Send PIN
			// die cla is altijd zelfde: gwn aangeven welke instructieset
			// ins geeft aan wat er moet gebeuren --> dit getal staat ook vast in applet
			// new byte[] geeft de pincode aan dus dit zou je normaal ingeven door de
			// gebruiker

			//System.out.println("Asking serial number");
			a = new CommandAPDU(IDENTITY_CARD_CLA, GET_SERIAL_INS, 0x00, 0x00, new byte[] { 0x31, 0x32, 0x33, 0x34 });
			r = c.transmit(a);
			if (r.getSW() == SW_VERIFICATION_FAILED)
				throw new Exception("ERROR");
			else if (r.getSW() != 0x9000)
				throw new Exception("Exception on the card: " + r.getSW());
			String str = new String(r.getData(), StandardCharsets.UTF_8);
			//System.out.println("SN is: " + str);

			// 3. ask name
			//System.out.println("Get name");
			a = new CommandAPDU(IDENTITY_CARD_CLA, GET_NAME_INS, 0x00, 0x00, new byte[] { 0x31, 0x32, 0x33, 0x34 });
			r = c.transmit(a);
			if (r.getSW() == SW_VERIFICATION_FAILED)
				throw new Exception("ERROR");
			else if (r.getSW() != 0x9000)
				throw new Exception("Exception on the card: " + r.getSW());
			str = new String(r.getData(), StandardCharsets.UTF_8);

		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	// ---------------------------
	// ------- INIT GUI ----------
	// ---------------------------

	public void launchPinInputScreen() {
		try {
			// Load root layout from fxml file.
			FXMLLoader loader = new FXMLLoader();
			loader.setLocation(MiddlewareMain.class.getResource("RootMenu.fxml"));
			rootLayout = (BorderPane) loader.load();

			// Show the scene containing the root layout.
			Scene scene = new Scene(rootLayout);
			primaryStage.setScene(scene);
			// scene.getStylesheets().add("be.msec.stylesheet.css");

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
		AnchorPane loginView = (AnchorPane) loader.load();

		// controller initialiseren + koppelen aan mainClient
		middlewareController = loader.getController();
		middlewareController.setMain(this);
		rootLayout.setCenter(loginView);
	}

	// ----------------------------------
	// ------- CONNECT TO CARD ----------
	// ----------------------------------

	/**
	 * Connect to the javacard
	 * 
	 * @param simulatedConnection,
	 *            true= simulated connection ; false = connect to real card terminal
	 * @throws Exception
	 */
	public boolean connectToCard(boolean simulatedConnection) {
		try {
			ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
			if (simulatedConnection) {
				//System.out.println("Simulated connection");
				c = new SimulatedConnection();

				c.connect();

				createAppletForSimulator();
			} else {
				//System.out.println("Real connection");
				c = new Connection();
				((Connection) c).setTerminal(0); // depending on which cardreader you use
				c.connect();
			}
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return true;
	}

	private void createAppletForSimulator() {
		try {
			// 0. create applet (only for simulator!!!)
			a = new CommandAPDU(0x00, 0xa4, 0x04, 0x00,
					new byte[] { (byte) 0xa0, 0x00, 0x00, 0x00, 0x62, 0x03, 0x01, 0x08, 0x01 }, 0x7f);
			r = c.transmit(a);
			//System.out.println(r);
			if (r.getSW() != 0x9000)
				throw new Exception("select installer applet failed");

			a = new CommandAPDU(0x80, 0xB8, 0x00, 0x00,
					new byte[] { 0xb, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x00, 0x00 }, 0x7f);
			r = c.transmit(a);
			//System.out.println(r);
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
		System.setProperty("javax.net.ssl.keyStorePassword", "eenpaswoord");
		System.setProperty("javax.net.ssl.trustStore", "sslKeyStore.store");
		System.setProperty("javax.net.ssl.trustStorePassword", "eenpaswoord");

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

	public TimeStruct askTimeToTimestampServer() throws Exception {
		// hiervoor is eigenlijk geen certificaat nodig want de smartcard heeft de PKg
		// hier wil ik enkel de tijd terug krijgen: eenmaal gehashed endan gesigned met
		// SKg en eenmaal plain text
		TimeStruct timeInfoStruct = null;
		ObjectOutputStream objectoutputstream = null;
		ObjectInputStream objectinputstream = null;
		try {

			try {
				objectoutputstream = new ObjectOutputStream(timestampSocket.getOutputStream());
				// Command = 1 => GetSignedTime
				objectoutputstream.writeObject(1);
				objectinputstream = new ObjectInputStream(timestampSocket.getInputStream());
				// Cast serialized object into new object
				timeInfoStruct = (TimeStruct) objectinputstream.readObject();

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

	// -------------------------------------------------
	// ------- SERVICE PROVIDER COMMUNICATION ----------
	// -------------------------------------------------
	public void connectServiceProvider() {
		try {
			socket = new ServerSocket(portSP);
			middlewareSocket = socket.accept();
			System.out.println("Socket connection");

			// start thread to listen for commands from ServiceProvider client
			Thread listenerThread = new ListenForServiceProviderCommandThread();
			listenerThread.start();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	
	private void sendToServiceProvider(Object message) {
		ObjectOutputStream out;
		try {
			out =  new ObjectOutputStream(middlewareSocket.getOutputStream());
			out.writeObject(message);
			
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	// ------------------------------------------
	// ------- JAVA CARD COMMUNICATION ----------
	// ------------------------------------------

	/**
	 * Send the signedtimestamp to the card so the time can be verifyed and updated
	 * 
	 * @param timeInfoStruct
	 */
	private boolean sendTimeToCard(TimeStruct timeInfoStruct) {
		// concatenate all bytes into one big data array, this toSend needs to be given
		// to the card
		byte[] toSend = new byte[timeInfoStruct.getSignedData().length + timeInfoStruct.getDate().length];
		System.arraycopy(timeInfoStruct.getSignedData(), 0, toSend, 0, timeInfoStruct.getSignedData().length);
		System.arraycopy(timeInfoStruct.getDate(), 0, toSend, timeInfoStruct.getSignedData().length,
				timeInfoStruct.getDate().length);

		//
		//System.out.println("Send signed time bytes with extended APDU with length: " + toSend.length);
		toSend = new byte[10];
		a = new CommandAPDU(IDENTITY_CARD_CLA, UPDATE_TIME, 0x00, 0x00, toSend);
		try {
			r = c.transmit(a);
			if (r.getSW() != 0x9000)
				throw new Exception("Exception on the card: " + r.getSW());
			//System.out.println("DATE UPDATED ");

		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return false;
		}
		return true;
	}

	public Boolean loginWithPin(byte[] pin) throws Exception {
		if (pin.length != 4) { // limit length of the pin to prevent dangerous input
			throw new Exception("Pin has to be 4 characters");
		}
		//System.out.println(bytesToHex(pin));
		a = new CommandAPDU(IDENTITY_CARD_CLA, VALIDATE_PIN_INS, 0x00, 0x00, pin);
		r = c.transmit(a);
		if (r.getSW() == SW_VERIFICATION_FAILED) {
			pinVerified = false;
			return false;}
		else if (r.getSW() == 0x26368)
			throw new Exception("Wrong Pin size!");
		else if (r.getSW() != 0x9000)
			throw new Exception("Exception on the card: " + r.getSW());

		pinVerified = true;
		return true;
	}

	public static void main(String[] args) throws Exception {
		launch(args);
	}

	private boolean authenticateCertificate(ServiceProviderAction received) {
		byte[] signedCertificateBytes = received.getSignedCertificate().getSignatureBytes();
		SPCertificate certificateServiceProvider = (SPCertificate) received.getSignedCertificate().getCertificateBasic();

		//prepare everything to send to the card
		byte[] certificateBytes = certificateServiceProvider.getBytes();
		byte[] toSend = new byte[signedCertificateBytes.length + certificateBytes.length];
		System.arraycopy(signedCertificateBytes, 0, toSend, 0, signedCertificateBytes.length);
		System.arraycopy(certificateBytes, 0, toSend, signedCertificateBytes.length, certificateBytes.length);
		
		a = new CommandAPDU(IDENTITY_CARD_CLA, AUTHENTICATE_SP, 0x00, 0x00, toSend);
		try {
			r = c.transmit(a);
			if (r.getSW() != 0x9000)
				throw new Exception("Exception on the card: " + r.getSW());
			else {
				//System.out.println("SUCCESFULLY VERIFIED " + r.getSW());
				//get response data and send to SP
				byte[] response = r.getData();
				System.out.println(response.length + "  response " + bytesToDec(response));	//first byte = length of response
				SPChallenge challengeToSP = new SPChallenge(Arrays.copyOfRange(response, 1, 65), Arrays.copyOfRange(response, 65, 81), Arrays.copyOfRange(response, 81, response.length));
				//System.out.println(challengeToSP);
				
				sendToServiceProvider(challengeToSP);
				//System.out.println("send challenge to SP done");
			}

		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return false;
		}
        return true;
        
	}
	
	private boolean verifyChallenge(ServiceProviderAction received) {
		byte [] toSend = new byte[received.getChallengeBytes().length];
		System.arraycopy(received.getChallengeBytes(), 0, toSend, 0, received.getChallengeBytes().length);
		a = new CommandAPDU(IDENTITY_CARD_CLA, VERIFY_CHALLENGE, 0x00, 0x00, toSend);
		
		try {
			r = c.transmit(a);
			if (r.getSW() != 0x9000)
				throw new Exception("Exception on the card: " + r.getSW());
			else {
				System.out.println("SP verified");
			}

		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return false;
		}
		return true;
		
	}
	
	private void authenticateCardSendChallenge(ServiceProviderAction received) {
		byte [] toSend = received.getChallengeBytes();
		a = new CommandAPDU(IDENTITY_CARD_CLA, AUTHENTICATE_CARD, 0x00, 0x00, toSend);
		
		try {
			r = c.transmit(a);
			if (r.getSW() != 0x9000)
				throw new Exception("Exception on the card: " + r.getSW());
			else {
				byte[] response = r.getData();
				// TODO: ER ZIT HIER NOG EEN FOUT ERGENS. Ik weet niet of het door de kaart komt. heb offset veranderd naar 0 . Stond op 1. 
				// response zou een veelvoud van 16 bytes moeten zijn zodat de sp kan decrypteren. 
				sendToServiceProvider(new CardChallenge(Arrays.copyOfRange(response, 0, response.length)));
			}
			
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}	
		return;
	}
	
	private byte[] getDataFromCard(ServiceProviderAction receivedQuery) {

//		a = new CommandAPDU(IDENTITY_CARD_CLA, RELEASE_ATTRIBUTE, 0x00, 0x00);
		ByteBuffer buffer = ByteBuffer.allocate(2);
		buffer.putShort(receivedQuery.getDataQuery());
		byte [] toSend = buffer.array();
		a = new CommandAPDU(IDENTITY_CARD_CLA, RELEASE_ATTRIBUTE, 0x00, 0x00, receivedQuery.getDataQuery());
		try {
			r = c.transmit(a);
			if (r.getSW() == SW_VERIFICATION_FAILED)
				throw new Exception("Not verified, no access");
			else if (r.getSW() != 0x9000)
				throw new Exception("Exception on the card: " + r.getSW());
//			
			return r.getBytes();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}
	
	class WaitForPinThread extends Thread{
		ServiceProviderAction query;
		
		public WaitForPinThread(ServiceProviderAction query) {
			this.query = query;
		}
		public void run() {
			Platform.runLater(new Runnable() {
	            @Override public void run() {
	            	primaryStage.setAlwaysOnTop(true);
	            	primaryStage.setAlwaysOnTop(false);
	            	middlewareController.setMainMessage("Enter pin to get data...");
            	}
			});
            while(!pinVerified) {
            	try {
					Thread.sleep(1000);
				} catch (InterruptedException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
            }
            System.out.println("Pin OK");
            byte[] data = getDataFromCard(query);
            sendToServiceProvider(data);
		}
	}

	class ListenForServiceProviderCommandThread extends Thread {
		public void run() {
			ObjectInputStream objectinputstream = null;
			try {
				while (true) {
					//System.out.println("Listening to service provider...");
					objectinputstream = new ObjectInputStream(middlewareSocket.getInputStream());
					ServiceProviderAction receivedObject = (ServiceProviderAction) objectinputstream.readObject();
					//System.out.println("received: " + receivedObject.getAction().getCommand());
					

					switch (receivedObject.getAction().getCommand()) {
					case AUTH_SP:
						System.out.println("AUTH SP");
						//sendToServiceProvider("AUTH command received");
						authenticateCertificate(receivedObject);
						
						break;
					case GET_DATA:
						System.out.println("GET DATA");
						WaitForPinThread pinWaitingThread = new WaitForPinThread(receivedObject);
						pinWaitingThread.start();
						
						break;
					case VERIFY_CHALLENGE:
						System.out.println("VERIFY CHALLENGE");
						verifyChallenge(receivedObject);
						break;
					case AUTH_CARD:
						authenticateCardSendChallenge(receivedObject);
						break;
					default:
						sendToServiceProvider("Command doesn't exists.");
					}

				}
			} catch (IOException | ClassNotFoundException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
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