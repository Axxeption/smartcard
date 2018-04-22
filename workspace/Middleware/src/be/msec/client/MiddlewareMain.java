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
	private static final byte UPDATE_TIME = 0x25;
	private static final byte AUTHENTICATE_SP = 0x21;
	private static final byte VERIFY_CHALLENGE = 0x29;
	private static final byte AUTHENTICATE_CARD = 0x30;
	private static final byte RELEASE_ATTRIBUTE = 0x31;
	static final int portG = 8001;
	static final int portSP = 8003;
	private Socket timestampSocket = null;
	IConnection c;
	CommandAPDU a;
	ResponseAPDU r;
	boolean connectedWithSC = false;
	boolean pinVerified = false;

	private ServerSocket socket;
	private Socket middlewareSocket;
	
	// ---------------------------
	// ------- GLOBAL START ------
	// ---------------------------
	
	public static void main(String[] args) throws Exception {
		launch(args);
	}
	
	public void start(Stage stage) throws IOException {
		this.primaryStage = stage;
		this.primaryStage.setTitle("Card reader UI");
		launchPinInputScreen();
		try {
			//connects to card + timestampserver and dates the time up if needed
			UPDATE_TIME_ON_CARD_ROUTINE();
			connectServiceProvider();
		} catch (Exception e) {
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
		System.out.println("Loading Main login Page");
		AnchorPane loginView = (AnchorPane) loader.load();

		middlewareController = loader.getController();
		middlewareController.setMain(this);
		rootLayout.setCenter(loginView);
	}

	private void UPDATE_TIME_ON_CARD_ROUTINE() throws Exception {
		if (connectTimestampServer()) {
			TimeInfoStruct signedTime = askTimeToTimestampServer();
			if (signedTime != null) {
				// make connection to the card (simulator) and send the bytes
				connectToCard(true); // true => simulatedconnection
				sendTimeToCard(signedTime);
			}
		}
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

	// -----------------------------------
	// ------- TIMESTAMP SERVER ----------
	// -----------------------------------
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

	// -------------------------------------------------
	// ------- SERVICE PROVIDER THREADING  -------------
	// -------------------------------------------------
	public void connectServiceProvider() {
		try {
			socket = new ServerSocket(portSP);
			System.out.println("Serversocket is listening");
			middlewareSocket = socket.accept();
			System.out.println("Socket connection accepted");

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
			System.out.println("SENDING TO SP");
			out =  new ObjectOutputStream(middlewareSocket.getOutputStream());
			out.writeObject(message);
			
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	// ------------------------------------------
	// ------- CORE JAVA CARD METHODS -----------
	// ------------------------------------------

	/**
	 * Send the signedtimestamp to the card so the time can be verifyed and updated
	 * 
	 * @param timeInfoStruct
	 */
	private boolean sendTimeToCard(TimeInfoStruct timeInfoStruct) {
		// concatenate all bytes into one big data array, this toSend needs to be given
		// to the card
		byte[] toSend = new byte[timeInfoStruct.getSignedData().length + timeInfoStruct.getDate().length];
		System.arraycopy(timeInfoStruct.getSignedData(), 0, toSend, 0, timeInfoStruct.getSignedData().length);
		System.arraycopy(timeInfoStruct.getDate(), 0, toSend, timeInfoStruct.getSignedData().length,
				timeInfoStruct.getDate().length);
		//System.out.println("Send signed time bytes with extended APDU with length: " + toSend.length);
		a = new CommandAPDU(IDENTITY_CARD_CLA, UPDATE_TIME, 0x00, 0x00, toSend);
		try {
			r = c.transmit(a);
			if (r.getSW() != 0x9000)
				throw new Exception("Exception on the card: " + r.getSW());
			System.out.println("DATE UPDATED ");

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
		System.out.print("Pin ok? " + r.getSW());
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

	private boolean authenticateCertificate(ServiceProviderAction received) {
		byte[] signedCertificateBytes = received.getSignedCertificate().getSignatureBytes();
		CertificateServiceProvider certificateServiceProvider = (CertificateServiceProvider) received.getSignedCertificate().getCertificateBasic();

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
				System.out.println("Certificate succesfully verified:  " + r.getSW());
				//get response data and send to SP
				byte[] response = r.getData();
				System.out.println(response.length + "  response " + bytesToDec(response));	//first byte = length of response
				Challenge challengeToSP = new Challenge(Arrays.copyOfRange(response, 1, 65), Arrays.copyOfRange(response, 65, 81), Arrays.copyOfRange(response, 81, response.length));
				//System.out.println(challengeToSP);
				
				sendToServiceProvider(challengeToSP);
				System.out.println("send challenge to SP done");
			}

		} catch (Exception e) {
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
				System.out.println("succesfully verified challenge");
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
				System.out.println(bytesToHex(response));
				// TODO: ER ZIT HIER NOG EEN FOUT ERGENS. Ik weet niet of het door de kaart komt. heb offset veranderd naar 0 . Stond op 1. 
				// response zou een veelvoud van 16 bytes moeten zijn zodat de sp kan decrypteren. 
				sendToServiceProvider(new MessageToAuthCard(Arrays.copyOfRange(response, 0, response.length)));
			}
			
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}	
		return;
	}
	
	/**
	 * Asks to the card for the data on the card for a specific query
	 * 
	 * @throws Exception
	 */
	private byte[] getDataFromCard(ServiceProviderAction receivedQuery) {
		System.out.println("Getting data from card");

//		a = new CommandAPDU(IDENTITY_CARD_CLA, RELEASE_ATTRIBUTE, 0x00, 0x00);
		System.out.println("Ask with query: " + receivedQuery.getDataQuery());
		ByteBuffer buffer = ByteBuffer.allocate(2);
		buffer.putShort(receivedQuery.getDataQuery());
		a = new CommandAPDU(IDENTITY_CARD_CLA, RELEASE_ATTRIBUTE, 0x00, 0x00, receivedQuery.getDataQuery());
		try {
			r = c.transmit(a);
			if (r.getSW() == SW_VERIFICATION_FAILED)
				throw new Exception("Not verified, no access");
			else if (r.getSW() != 0x9000)
				throw new Exception("Exception on the card: " + r.getSW());			
			System.out.println("Received encrypted data from the card.");
			return r.getBytes();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}
	
	// ------------------------------------------
	// ------- THREAD CLASSES -------------------
	// ------------------------------------------
	
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
					System.out.println("wait for pin ...");
				} catch (InterruptedException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
            }
            System.out.println("pin valid");
            byte[] data = getDataFromCard(query);
            sendToServiceProvider(data);
		}
	}
	
	class ListenForServiceProviderCommandThread extends Thread {
		public void run() {
			ObjectInputStream objectinputstream = null;
			try {
				while (true) {
					System.out.println("Listening to service provider...");
					objectinputstream = new ObjectInputStream(middlewareSocket.getInputStream());
					ServiceProviderAction receivedObject = (ServiceProviderAction) objectinputstream.readObject();	
					switch (receivedObject.getAction().getCommand()) {
					case AUTH_SP:
						System.out.println("AUTH SP COMMAND");
						//sendToServiceProvider("AUTH command received");
						authenticateCertificate(receivedObject);
						
						break;
					case GET_DATA:
						System.out.println("GET DATA COMMAND");
						WaitForPinThread pinWaitingThread = new WaitForPinThread(receivedObject);
						pinWaitingThread.start();
						
						break;
					case VERIFY_CHALLENGE:
						System.out.println("VERIFY CHALLENGE COMMAND");
						verifyChallenge(receivedObject);
						break;
					case AUTH_CARD:
						System.out.println("AuthenticateCard COMMAND");
						authenticateCardSendChallenge(receivedObject);
						break;
					default:
						sendToServiceProvider("Command doesn't exists.");
					}

				}
			} catch (IOException | ClassNotFoundException e) {
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