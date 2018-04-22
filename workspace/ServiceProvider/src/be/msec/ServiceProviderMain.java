package be.msec;
import be.msec.client.CAService;
import be.msec.client.MiddleWareAPI;
import be.msec.client.SPChallenge;
import be.msec.client.CardChallenge;
import be.msec.client.SignedCertificate;
import be.msec.client.TimeStruct;
import be.msec.controllers.MainServiceController;
import be.msec.controllers.RootMenuController;
import be.msec.helpers.Controller;
import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Scene;
import javafx.scene.layout.AnchorPane;
import javafx.scene.layout.BorderPane;
import javafx.stage.Stage;

import java.awt.List;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URISyntaxException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.rmi.RemoteException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.rmi.CORBA.Util;

public class ServiceProviderMain extends Application {

    private Stage primaryStage;
    private BorderPane rootLayout;
    private Controller currentViewController;
    private MainServiceController mainController;
	private Socket serviceProviderSocket = null;
	private String lastActionSPName = null;
	private ArrayList<ServiceProvider> serviceProviders;
	private SecretKeySpec symKey;
	private IvParameterSpec ivSpec;
	static final int portSP = 8003;
	private byte[] challengeToAuthCard;
	private ServiceProvider lastUsedSP;

    /**
     * Constructor
     */
    public ServiceProviderMain() throws RemoteException {
    }

    public static void main(String[] args) {
        launch(args);
    }
    
    public ArrayList<ServiceProvider> getServiceProviders() {
		return serviceProviders;
	}

	public void setServiceProviders(ArrayList<ServiceProvider> serviceProviders) {
		this.serviceProviders = serviceProviders;
	}

	@Override
    public void start(Stage primaryStage) throws Exception {
        this.primaryStage = primaryStage;
        this.primaryStage.setTitle("Service Provider overview");
        initRootLayout();
        showMainView();
        connectToMiddleWare();
    }

    @Override
    public void stop() {
        System.out.println("Stage is Normaly closed");
    }

	public void sendCommandToMiddleware(ServiceProviderAction action, boolean waitForResponse) {
		ObjectOutputStream objectoutputstream = null;
		this.lastActionSPName = action.getServiceProvider();
		try {
			System.out.println("Send action to the middleware: " + action.getAction().getName());
			objectoutputstream = new ObjectOutputStream(serviceProviderSocket.getOutputStream());
			objectoutputstream.writeObject(action);
			
			//wait for response)
			if(waitForResponse){
				//System.out.println("Commando needs response from MW! ...");	
				ListenForMiddelware();
			}
			
		}catch (Exception e) {
			System.out.println(e);
		}
    }
    
    

    public void authenticateServiceProvider(ServiceProvider selectedServiceProvider) {
    	// STEP 2
    	// 2. authenticate SP
    	System.out.println("2. auth service provider, SP");
    	ServiceProviderAction action = new ServiceProviderAction(new ServiceAction("Authenticate SP", MiddleWareAPI.AUTH_SP),selectedServiceProvider.getCertificate());
    	action.setServiceProvider(selectedServiceProvider.getName());
    	sendCommandToMiddleware(action,true);

    }
    
    public void recreateSessionKey(SPChallenge challenge) {
    	// STEP 3, after challenge response from MW.
    	System.out.println("3. recreateSessionKey, SP");
    	byte[] nameBytes = challenge.getNameBytes();
    	byte[] rndBytes = challenge.getRndBytes();
    	byte [] challengeBytes = challenge.getChallengeBytes();
    	
    	//System.out.println("encr chlng bytes  "+bytesToDec(challengeBytes));
		//System.out.println("encr name bytes   "+bytesToDec(nameBytes));
    	
    	byte[] decryptedNameBytes;
    	byte[] decryptedChallengeBytes;
    	
    	for(ServiceProvider sp : serviceProviders) {
    		if(sp.name.equals(lastActionSPName)) {
    			System.out.println("recreate session key "+sp.getName());
    			try {
					Cipher rsaCipher = Cipher.getInstance("RSA");
					rsaCipher.init(Cipher.DECRYPT_MODE, (RSAPrivateKey)sp.getPrivateKey());
					System.out.println();
					byte [] rnd = rsaCipher.doFinal(rndBytes);
					//byte[] rnd = new String(decrypted);
					//System.out.println("decrypted rndbytes "+bytesToDec(rnd));
					
					
					//create session key
					byte[] ivdata = new byte[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
					this.ivSpec = new IvParameterSpec(ivdata);
					this.symKey = new SecretKeySpec(rnd, "AES");
					System.out.println("SETTING SESSION KEY!!!! " + symKey);
					
					Cipher aesCipher = Cipher.getInstance("AES/CBC/NoPadding");
					aesCipher.init(Cipher.DECRYPT_MODE, symKey, ivSpec);
					decryptedChallengeBytes = aesCipher.doFinal(challengeBytes);
					decryptedNameBytes = aesCipher.doFinal(nameBytes);
					
					//System.out.println("decrypted chlng bytes  "+bytesToDec(decryptedChallengeBytes));
					//System.out.println("decrypted name bytes   "+bytesToDec(decryptedNameBytes));
					String name = new String(decryptedNameBytes);
					
					byte [] respChallengeBytes = addOne_Bad(decryptedChallengeBytes);
					
					//TODO beno encrypt challenge response
					aesCipher.init(Cipher.ENCRYPT_MODE, this.symKey, this.ivSpec);
					byte[] encryptedRespChallenge = aesCipher.doFinal(respChallengeBytes);
					
					//send challenge response back to MW
					ServiceProviderAction action = new ServiceProviderAction(new ServiceAction("verify challenge, session key", MiddleWareAPI.VERIFY_CHALLENGE), null);
					action.setChallengeBytes(encryptedRespChallenge);
					sendCommandToMiddleware(action,false); // verwacht niks terug
					
				} catch (NoSuchAlgorithmException | InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException | NoSuchPaddingException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} 
		    		
    		}
    	}
    	
    }
    
    public void authenticateCard() {
    	// STEP 4
    	System.out.println("4. auth card, SP");
    	mainController.addToDataLog("Start authentication of card" );
    	//generate random bytes for challenge
    	byte[] b = new byte[16];
    	new Random().nextBytes(b);
    	challengeToAuthCard = b;
    	byte[] encryptedChallengeBytes = null;
    	//encrypt challengeBytes
    	try {
			Cipher aesCipher = Cipher.getInstance("AES/CBC/NoPadding");
			aesCipher.init(Cipher.ENCRYPT_MODE, symKey, ivSpec);
			encryptedChallengeBytes = aesCipher.doFinal(b);
			
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			System.out.println("ERROR IN auth card, SP :");
			System.out.println(symKey.getEncoded() +"  "+ ivSpec.getIV());
			e.printStackTrace();
		}	
    	
    	
    	//generate an action to send to the card
    	ServiceProviderAction action = new ServiceProviderAction(new ServiceAction("verify challenge to authenticate card", MiddleWareAPI.AUTH_CARD));
    	action.setChallengeBytes(encryptedChallengeBytes);
    	sendCommandToMiddleware(action,true);
    	
    }
    
    public void authenticateCard(CardChallenge cardMessage) {
    	// STEP 5, after second response from MW
    	System.out.println("5. AUTH CARD WITH MESSAGE");
    	//System.out.println("DONE " + bytesToHex(cardMessage.getMessage()));
    	Cipher aesCipher;
		try {
			//decrypte message
			aesCipher = Cipher.getInstance("AES/CBC/NoPadding");
			aesCipher.init(Cipher.DECRYPT_MODE, symKey, ivSpec);
			byte[] message = aesCipher.doFinal(padding(cardMessage.getMessage()));
			//System.out.println(bytesToDec(message));
			
			//check signature
			byte[] signedBytes = Arrays.copyOfRange(message, 0, 72);
			byte[] signature = Arrays.copyOfRange(message, 72, 136);
			Signature signer = Signature.getInstance("SHA1WithRSA");
			signer.initVerify(CAService.loadPublicKey("RSA"));
			signer.update(signedBytes);
			if(!signer.verify(signature)) {
				System.out.println("Card has a valid common certificate. (authenticate card)");
			} else {
				System.out.println("Card doesn't have a valid common certificate.");
				return;
			}
			
			//check if sign with CommonCert key is ok
			//first regenerate public key from commoncertificate
			BigInteger exponent = new BigInteger(1,Arrays.copyOfRange(message, 0, 3));
			BigInteger modulus = new BigInteger(1,Arrays.copyOfRange(message, 4, 68));
			RSAPublicKeySpec spec = new RSAPublicKeySpec(modulus, exponent);
			signer.initVerify(KeyFactory.getInstance("RSA").generatePublic(spec));
			//generate byte array
			ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
			outputStream.write(challengeToAuthCard);
			outputStream.write("AUTH".getBytes());
		    byte[] bytesToSign = outputStream.toByteArray();
		    //System.out.println("bytes to sign : " + bytesToDec(Arrays.copyOfRange(message, 156, 220)));
		    //System.out.println("bytes to sign : " + KeyFactory.getInstance("RSA").generatePublic(spec));
			//check sign
		    
			
		    if(signer.verify(Arrays.copyOfRange(message, 156, 220))) {
				System.out.println("Card is valid, challenge is ok. (authenticate card)");
			} else {
				System.out.println("Card is not valid, challenge is nok. HIER ZIT ER NOG EEN FOUT, DIE public key wordt verkeerd opgebouwd door die BigIntegers, de bytes zijn sws juist.");
				return;
			}
			
		} catch (NoSuchAlgorithmException | SignatureException | IOException | InvalidKeySpecException | InvalidKeyException | URISyntaxException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException | NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} 
		
    }
    
    public void submitDataQuery(ServiceProvider selectedServiceProvider, int query) {
    	System.out.println("1, Start query, SP");
    	// STEP 1
    	// Do Authentication
    	if(lastUsedSP != selectedServiceProvider) {
    		System.out.println("First time with this SP --> athenticate");
	    	authenticateServiceProvider(selectedServiceProvider);
	    
	    	// STEP 4
	    	//start the authentication of the card (step 3)
	    	authenticateCard();
    	
    	//STEP 7
    	// Get data
    	System.out.println("7. Get Data, SP");
    	ServiceProviderAction request = new ServiceProviderAction(new ServiceAction("Get Data",MiddleWareAPI.GET_DATA), selectedServiceProvider.getCertificate());
        request.setServiceProvider(selectedServiceProvider.getName());
        request.setDataQuery((short) query);
    	sendCommandToMiddleware(request,true);
    	lastUsedSP = selectedServiceProvider;
    	}else {
    		System.out.println("Skipping authentication phase because already logged in to this service provider!");
        	ServiceProviderAction request = new ServiceProviderAction(new ServiceAction("Get Data",MiddleWareAPI.GET_DATA), selectedServiceProvider.getCertificate());
            request.setServiceProvider(selectedServiceProvider.getName());
            request.setDataQuery((short) query);
        	sendCommandToMiddleware(request,true);
    	}
    }
    
    
    public void connectToMiddleWare() {
    	try {
			serviceProviderSocket = new Socket("localhost", portSP);
		} catch (IOException ex) {
			//System.out.println("CANNOT CONNECT TO MIDDLEWARE " + ex);
		}
		//System.out.println("Serviceprovider connected to middleware: " + serviceProviderSocket);

    }
    
    public void initRootLayout() {
        try {
            // Load root layout from fxml file.
            FXMLLoader loader = new FXMLLoader();
            loader.setLocation(ServiceProviderMain.class.getResource("RootMenu.fxml"));
            rootLayout = (BorderPane) loader.load();

            // Show the scene containing the root layout.
            Scene scene = new Scene(rootLayout);
            primaryStage.setScene(scene);
            //scene.getStylesheets().add("be.msec.stylesheet.css");


            // Give the controller access to the main app.
            RootMenuController controller = loader.getController();
            controller.setMain(this);
            currentViewController = controller;

            primaryStage.show();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public Controller getCurrentViewController() {
        return currentViewController;
    }

    // --------------------- LOGIN VIEW ------------------------

    public void showMainView() {
        try {
            FXMLLoader loader = new FXMLLoader();
            loader.setLocation(ServiceProviderMain.class.getResource("mainServiceView.fxml"));
            System.out.println("Loading Main Page");
            AnchorPane loginView = (AnchorPane) loader.load();
            //controller initialiseren + koppelen aan mainClient
            MainServiceController controller = loader.getController();
            controller.setMainController(this);
            currentViewController = controller;
            mainController = controller;
            rootLayout.setCenter(loginView);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void ListenForMiddelware() {
    	System.out.println("Listening for MW...");
    	Object obj = null;
    	try {
			ObjectInputStream objectinputstream = new ObjectInputStream(serviceProviderSocket.getInputStream());
			
			obj = objectinputstream.readObject();
			System.out.println("OBJECT RECEIVED");
			if(obj instanceof SPChallenge) {
				SPChallenge challengeFromSC = (SPChallenge)obj;
				mainController.addToDataLog("Succesfully received challenge" );
				System.out.println("CHALLENGE RECEIVED");
				//recreate session key, respond to challenge
				recreateSessionKey(challengeFromSC);
				notify();
			}
			else if( obj instanceof String) {
				// STEP 8
				String answer = (String)obj;
				System.out.println("STRING RECEIVEC, "+answer);
				mainController.addToDataLog("Succesfully received: " +answer);
			}
			else if(obj instanceof CardChallenge) {
				System.out.println("MESSTOAUTHCARD RECEIVED");
				authenticateCard((CardChallenge) obj);
			}
			else if(obj instanceof byte[]) {
				decryptAndShowData((byte[]) obj); 
			}
			else {
				System.out.println("UNKNOW OBJECT received "+ obj);
			}
			
			System.out.println("succesfully received an answer!");
			
    	}catch (Exception e) {
			System.out.println(e);
		}
    }

		private void decryptAndShowData(byte[] encryptedData) {
			//decrypt and show in log
			try {
				System.out.println("Start decrypting from received data");
				Cipher aesCipher = Cipher.getInstance("AES/CBC/NoPadding");
				aesCipher.init(Cipher.DECRYPT_MODE, symKey, ivSpec);
				byte [] cropped = new byte[encryptedData.length - 2];
				cropped = Arrays.copyOfRange(encryptedData, 2, cropped.length);
				cropped = padding(cropped);
				System.out.println("the length is: "+ cropped.length);

				byte[] data = aesCipher.doFinal(cropped);
				String str = new String(data, StandardCharsets.UTF_8);
				mainController.addToDataLog("Received data from card: "+ str );
				System.out.println("data is: " + str);
				System.out.println("Succesfully decrypted");
			} catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (NoSuchAlgorithmException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (NoSuchPaddingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (IllegalBlockSizeException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (BadPaddingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
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
	
	private byte [] padding(byte[] data) {
		if(data.length %16 != 0) {
			short length = (short) (data.length + 16 - data.length %16);
			byte [] paddedData = new byte[length];
			paddedData = Arrays.copyOfRange(data, 0, data.length-1);
			return paddedData;
		}
		return data;
	}

	public String bytesToDec(byte[] barray) {
		String str = "";
		for (byte b : barray)
			str += (int) b + ", ";
		return str;
	}
	
	public static byte[] addOne_Bad(byte[] A) {
	    short lastPosition = (short)(A.length - 1); 
	    // Looping from right to left
	    A[lastPosition] += 1;
	    
	    return A;         
	}

}
