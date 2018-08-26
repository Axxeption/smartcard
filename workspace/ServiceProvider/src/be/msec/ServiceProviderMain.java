package be.msec;
import be.msec.client.AuthenticateToSPResponse;
import be.msec.client.CAService;
import be.msec.client.CallableMiddelwareMethodes;
import be.msec.client.Challenge;
import be.msec.client.IdInfo;
import be.msec.client.MessageToAuthCard;
import be.msec.client.SignedCertificate;
import be.msec.client.SignedDocumentResponse;
import be.msec.client.TimeInfoStruct;
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
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.rmi.RemoteException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
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
import java.security.spec.X509EncodedKeySpec;
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
import javax.xml.bind.DatatypeConverter;

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
	private byte[] challengeToMW;
	private ServiceProvider lastUsedSP;
	private boolean errorAuth = false;
	private boolean errorAuthCard = false;
	private ArrayList <BigInteger> CRL = new ArrayList<>(3);
	
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
        CRL.add(new BigInteger("125422014097029724918108792105071187178873784845384312037013610507433438597578390785240316080683301401867427452546962388774824104444331913648865840870706609"));
        CRL.add(new BigInteger("12542201409702972491810953105071187178873784845384312037013610507433438597578390785240316080683301401867427452546962388774824104444331913648865840870706609"));
    }

    @Override
    public void stop() {
        System.out.println("Stage is Normaly closed");
    }
    
    public void submitDataQuery(ServiceProvider selectedServiceProvider, int query) {
    	//Digitale identificatie
    	if(query == 5) {
    		ServiceProviderAction request = new ServiceProviderAction(new ServiceAction("Identification",CallableMiddelwareMethodes.IDENTIFICATION));
            request.setServiceProvider(selectedServiceProvider.getName());
            request.setDataQuery((short) query);
        	sendCommandToMiddleware(request,true);
    	}
    	
    	//Authenticatie
    	else if(query == 6) {
    		//1. vraag PIN voor confirmation
    		confirmRequest();
    		//2. stuur challenge naar gebruiker
    		authenticateToSP();
    	}
    	
    	else if(query == 7) {
    		//1. stuur command naar MW voor digital sign init
    		initSignDocument();
    	}
    	
    	 
    	
//    	mainController.addToDataLog("---- 2. SP was chosen --> start authenticateSP -----");
//    	// STEP 1
//    	// Do Authentication
//    	if(lastUsedSP != selectedServiceProvider) {
//    		mainController.addToDataLog("First time with this SP --> need for authenticate");
//	    	authenticateServiceProvider(selectedServiceProvider);
//	    
//	    	// STEP 4
//	    	//start the authentication of the card (step 3)
//	    	if(!errorAuth) {
//	    	mainController.addToDataLog("---- 3. Authenticate the card to the SP -----");
//	    	authenticateCard();
//    	
//    	//STEP 7
//    	// Get data
//    	mainController.addToDataLog("---- 4. ask to release the attributes from the smartcard ---- ");
//    	ServiceProviderAction request = new ServiceProviderAction(new ServiceAction("Get Data",CallableMiddelwareMethodes.GET_DATA), selectedServiceProvider.getCertificate());
//        request.setServiceProvider(selectedServiceProvider.getName());
//        request.setDataQuery((short) query);
//    	sendCommandToMiddleware(request,true);
//    	lastUsedSP = selectedServiceProvider;
//	    	}else {
//	    		mainController.addToDataLog("There was an error in the authentication of the serviceprovider");
//				mainController.addToDataLog("Cannot give the data!");
//	    	}
//    	}else {
//    		mainController.addToDataLog("Skipping authentication phase because already logged in to this service provider!");
//    		mainController.addToDataLog("---- 4. ask to release the attributes from the smartcard ---- ");
//        	ServiceProviderAction request = new ServiceProviderAction(new ServiceAction("Get Data",CallableMiddelwareMethodes.GET_DATA), selectedServiceProvider.getCertificate());
//            request.setServiceProvider(selectedServiceProvider.getName());
//            request.setDataQuery((short) query);
//        	sendCommandToMiddleware(request,true);
//    	}
    }
    

	public void sendCommandToMiddleware(ServiceProviderAction action, boolean waitForResponse) {
		ObjectOutputStream objectoutputstream = null;
		this.lastActionSPName = action.getServiceProvider();
		try {
	    	mainController.addToDataLog("Send something to the middleware, want something back: " + waitForResponse );
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
    	mainController.addToDataLog("Start authentication of ServiceProvider to card.");
    	ServiceProviderAction action = new ServiceProviderAction(new ServiceAction("Authenticate SP", CallableMiddelwareMethodes.AUTH_SP),selectedServiceProvider.getCertificate());
    	action.setServiceProvider(selectedServiceProvider.getName());
    	sendCommandToMiddleware(action,true);

    }
    
    public void recreateSessionKey(Challenge challenge) {
    	// STEP 3, after challenge response from MW.
    	mainController.addToDataLog("Create the received symmetric key from the smartcard in the serviceProvider");
    	byte[] nameBytes = challenge.getNameBytes();
    	byte[] rndBytes = challenge.getRndBytes();
    	byte [] challengeBytes = challenge.getChallengeBytes();
    	byte[] decryptedNameBytes;
    	byte[] decryptedChallengeBytes;
    	
    	for(ServiceProvider sp : serviceProviders) {
    		if(sp.name.equals(lastActionSPName)) {
    			try {
					Cipher rsaCipher = Cipher.getInstance("RSA");
					rsaCipher.init(Cipher.DECRYPT_MODE, (RSAPrivateKey)sp.getPrivateKey());
					byte [] rnd = rsaCipher.doFinal(rndBytes);
					//byte[] rnd = new String(decrypted);
					//System.out.println("decrypted rndbytes "+bytesToDec(rnd));
					
					
					//create session key
					byte[] ivdata = new byte[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
					this.ivSpec = new IvParameterSpec(ivdata);
					this.symKey = new SecretKeySpec(rnd, "AES");					
					Cipher aesCipher = Cipher.getInstance("AES/CBC/NoPadding");
					aesCipher.init(Cipher.DECRYPT_MODE, symKey, ivSpec);
					decryptedChallengeBytes = aesCipher.doFinal(challengeBytes);
					decryptedNameBytes = aesCipher.doFinal(nameBytes);
					
					//System.out.println("decrypted chlng bytes  "+bytesToDec(decryptedChallengeBytes));
					//System.out.println("decrypted name bytes   "+bytesToDec(decryptedNameBytes));
					String name = new String(decryptedNameBytes);
					
					mainController.addToDataLog("Did +1 on the challenge and send it back now!");
					byte [] respChallengeBytes = addOne_Bad(decryptedChallengeBytes);
					
					aesCipher.init(Cipher.ENCRYPT_MODE, this.symKey, this.ivSpec);
					byte[] encryptedRespChallenge = aesCipher.doFinal(respChallengeBytes);
					
					//send challenge response back to MW
					ServiceProviderAction action = new ServiceProviderAction(new ServiceAction("verify challenge, session key", CallableMiddelwareMethodes.VERIFY_CHALLENGE), null);
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
    	ServiceProviderAction action = new ServiceProviderAction(new ServiceAction("verify challenge to authenticate card", CallableMiddelwareMethodes.AUTH_CARD));
    	action.setChallengeBytes(encryptedChallengeBytes);
    	sendCommandToMiddleware(action,true);
    	
    }
    
    public void initSignDocument() {
    	mainController.addToDataLog("Sign doc command sent to MW");
    	ServiceProviderAction action = new ServiceProviderAction(new ServiceAction("Init digital signing", CallableMiddelwareMethodes.INIT_SIGN));
    	sendCommandToMiddleware(action, true);
    }
    
    public void confirmRequest() {
    	//eerst pin opvragen voor confirmatie van de gebruiker
    	mainController.addToDataLog("Confirm request by entering PIN");
    	
    	//generate an action to send to the card
    	ServiceProviderAction action = new ServiceProviderAction(new ServiceAction("Confirm request by entering PIN", CallableMiddelwareMethodes.CONFIRM_REQUEST));
    	sendCommandToMiddleware(action,true);
    }
    
    public void authenticateToSP() {
    	// STEP 4
    	mainController.addToDataLog("Start authentication of citizen" );
    	mainController.addToDataLog("sending challenge...");
    	//generate random bytes for challenge
    	byte[] b = new byte[16];
    	new Random().nextBytes(b);
    	challengeToMW = b;
    	
    	//generate an action to send to the card
    	ServiceProviderAction action = new ServiceProviderAction(new ServiceAction("verify challenge to authenticate card", CallableMiddelwareMethodes.AUTH_TO_SP));
    	action.setChallengeBytes(challengeToMW);
    	sendCommandToMiddleware(action,true);
    }
    
    public void authenticateCard(MessageToAuthCard cardMessage) {
    	// STEP 5, after second response from MW
    	mainController.addToDataLog("Received the message from the SC to authenticate the card.");
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
				mainController.addToDataLog("The card has a valid common certificate!");
			} else {
				errorAuthCard = true;
				mainController.addToDataLog("The card dos not have a valid common certificate!");
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
		    
			
		    if(!signer.verify(Arrays.copyOfRange(message, 156, 220))) {
				mainController.addToDataLog("There is a valid challenge send by the card.");
			} else {
				errorAuthCard = true;
				mainController.addToDataLog("There is no valid challenge send by the card.");
				return;
			}
			
		} catch (NoSuchAlgorithmException | SignatureException | IOException | InvalidKeySpecException | InvalidKeyException | URISyntaxException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException | NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
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
    	mainController.addToDataLog("Waiting for an answer from the middleware.");
    	Object obj = null;
    	try {
			ObjectInputStream objectinputstream = new ObjectInputStream(serviceProviderSocket.getInputStream());
			obj = objectinputstream.readObject();
			if(obj == null) {
				mainController.addToDataLog("Something went wrong with the authentication of the SP... ");
				errorAuth = true;
			}
			else if(obj instanceof Challenge) {
				Challenge challengeFromSC = (Challenge)obj;
				mainController.addToDataLog("Succesfully received challenge and symKey from smartcard" );
				//recreate session key, respond to challenge
				recreateSessionKey(challengeFromSC);
				notify();
			}
			else if(obj instanceof IdInfo) {
				//digitale identificatie
				checkAndPrintInfo(obj);	
			}
			else if( obj instanceof Boolean) {
				mainController.addToDataLog("pin correct!");
			}
			else if( obj instanceof String) {
				// STEP 8
				String answer = (String) obj;
				mainController.addToDataLog("Succesfully received the data from the smartcard: " + answer);
			}
			else if(obj instanceof MessageToAuthCard) {
				authenticateCard((MessageToAuthCard) obj);
			}
			else if(obj instanceof AuthenticateToSPResponse) {
				mainController.addToDataLog("received response from SC");
				verifyResponseAndCertificate((AuthenticateToSPResponse)obj);
			}
			else if(obj instanceof byte[]) {
				decryptAndShowData((byte[]) obj); 
			}
			else if(obj instanceof SignedDocumentResponse){
				SignedDocumentResponse signedDocumentResponse = (SignedDocumentResponse) obj;
				mainController.addToDataLog("received signed document from SC");
				verifyDigitalSignature(signedDocumentResponse);
				
			}
			else {
				System.out.println("UNKNOW OBJECT received "+ obj);
			}
			
			System.out.println("succesfully received an answer!");
			
    	}catch (Exception e) {
			System.out.println(e);
		}
    }
    
    private void checkAndPrintInfo(Object obj) {
		IdInfo info = (IdInfo) obj;
		//Check signature: idFile = signIDFile = ADDRESSFile = ADDRESFIleSign
		System.out.println("Total received: " + info.getInfo());
		byte[] IDFile = null, SignIDFile = null, AddressFile = null, SignAddressFile = null;
		byte [] totalArray = info.getInfo();
		int counter = 0 ;
		for(int i = 0 ; i < totalArray.length; i ++) {
			if(totalArray[i] == 0x3D) {
				if(counter == 0) {
					IDFile = Arrays.copyOfRange(totalArray, 0, i + 1);
				}
				if(counter == 1) {
					SignIDFile = Arrays.copyOfRange(totalArray, IDFile.length, i);
				}
				if(counter == 2) {
					AddressFile = Arrays.copyOfRange(totalArray, IDFile.length + SignIDFile.length + 1,	i+1 );
					SignAddressFile = Arrays.copyOfRange(totalArray, IDFile.length + SignIDFile.length + AddressFile.length + 1, totalArray.length);
				}
				counter++;
			}
		}
		System.out.println("Received IDFile: " +  bytesToHex(Arrays.copyOfRange(IDFile, 0,	(IDFile.length -1) )));
		System.out.println("SignedFile (length: " + SignIDFile.length + "): " + bytesToHex(SignIDFile));
		String IDText = new String(IDFile, StandardCharsets.UTF_8);
		String AddressText = new String(AddressFile, StandardCharsets.UTF_8);
		Signature sig;
		try {
			sig = Signature.getInstance("SHA1WithRSA");
			sig.initVerify(loadPublicKeyRRN("RSA"));
//			final byte[] att_name = new byte[] {(byte) 0x41, (byte) 0x78, (byte) 0x65, (byte) 0x6C, (byte) 0x20, (byte) 0x43, (byte) 0x61, (byte) 0x72, (byte) 0x6C, (byte) 0x20, (byte) 0x4C, (byte) 0x2E, (byte) 0x20, (byte) 0x56, (byte) 0x75, (byte) 0x6C, (byte) 0x73, (byte) 0x74, (byte) 0x65, (byte) 0x6B, (byte) 0x65, (byte) 0x0D, (byte) 0x0A, (byte) 0x39, (byte) 0x36, (byte) 0x30, (byte) 0x32, (byte) 0x32, (byte) 0x31, (byte) 0x34, (byte) 0x37, (byte) 0x37, (byte) 0x35, (byte) 0x31, (byte) 0x0D, (byte) 0x0A, (byte) 0x42, (byte) 0x65, (byte) 0x6C, (byte) 0x67, (byte) 0x69, (byte) 0x75, (byte) 0x6D, (byte) 0x0D, (byte) 0x0A, (byte) 0x52, (byte) 0x6F, (byte) 0x65, (byte) 0x73, (byte) 0x65, (byte) 0x6C, (byte) 0x61, (byte) 0x72, (byte) 0x65, (byte) 0x20, (byte) 0x32, (byte) 0x31, (byte) 0x20, (byte) 0x46, (byte) 0x45, (byte) 0x42, (byte) 0x20, (byte) 0x31, (byte) 0x39, (byte) 0x39, (byte) 0x36, (byte) 0x0D, (byte) 0x0A, (byte) 0x4D, (byte) 0x61, (byte) 0x6C, (byte) 0x65, (byte) 0x0D, (byte) 0x0A, (byte) 0x35, (byte) 0x39, (byte) 0x32, (byte) 0x2D, (byte) 0x35, (byte) 0x37, (byte) 0x30, (byte) 0x34, (byte) 0x33, (byte) 0x34, (byte) 0x30, (byte) 0x34, (byte) 0x2D, (byte) 0x30, (byte) 0x39, (byte) 0x0D, (byte) 0x0A, (byte) 0x3D};
//			sig.update(att_name);
			sig.update(IDFile);
//			final byte[] tmp = new byte[] {(byte) 0x94, (byte) 0x43, (byte) 0x7F, (byte) 0x42, (byte) 0xC9, (byte) 0xD4, (byte) 0xF6, (byte) 0xCC, (byte) 0xF8, (byte) 0x1A, (byte) 0xFA, (byte) 0xF9, (byte) 0x19, (byte) 0x23, (byte) 0x7E, (byte) 0x36, (byte) 0xDA, (byte) 0xF8, (byte) 0xCE, (byte) 0x9B, (byte) 0xBA, (byte) 0x10, (byte) 0x19, (byte) 0x59, (byte) 0x95, (byte) 0x6D, (byte) 0x77, (byte) 0x99, (byte) 0x6E, (byte) 0xB8, (byte) 0x21, (byte) 0xEA, (byte) 0x6B, (byte) 0x28, (byte) 0x48, (byte) 0xD5, (byte) 0x11, (byte) 0x44, (byte) 0xBC, (byte) 0xBC, (byte) 0x43, (byte) 0x6A, (byte) 0x09, (byte) 0x0F, (byte) 0x7F, (byte) 0x71, (byte) 0x37, (byte) 0x27, (byte) 0x6D, (byte) 0x71, (byte) 0x1E, (byte) 0xDB, (byte) 0xC9, (byte) 0xD9, (byte) 0xF9, (byte) 0x0B, (byte) 0x5B, (byte) 0xAD, (byte) 0xEE, (byte) 0x89, (byte) 0xE7, (byte) 0xC0, (byte) 0x08, (byte) 0x9D};
			if(sig.verify(SignIDFile)) {
				System.out.println("The signature on the IDFile is valid by the RRN");
				mainController.addToDataLog("Signature on IDFile is valid by the RRN");
				mainController.addToDataLog("Received IDFile from smartcard: " + IDText.substring(0, (IDText.length()-1)) );
				System.out.println("The received address: " + AddressText);
				System.out.println("The address in bytes: " + bytesToHex(AddressFile));
				System.out.println(SignAddressFile.length + "is: " + bytesToHex(SignAddressFile));
				sig.update(AddressFile);
				if(sig.verify(SignAddressFile)) {
					mainController.addToDataLog("Signature on AddressFile is valid by the RRN");
					System.out.println("The signature on the AddressFile is valid by the RRN!");
					mainController.addToDataLog("Received AddressFile from smartcard: " + AddressText.substring(0, (AddressText.length() -1 )));
				}
				else {
					mainController.addToDataLog("AddressFile not valid!");
				}
				
			}else {
				System.out.println("The signature is not valid!");
				mainController.addToDataLog("The signature is not valid!");
			}
				
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (URISyntaxException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (SignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
    
    
	private PublicKey loadPublicKeyRRN(String algorithm)
				throws IOException, NoSuchAlgorithmException,
				InvalidKeySpecException, URISyntaxException {
			// Read Public Key.		
			URL d = new URL("file:\\"+ System.getProperty("user.dir") + "\\key\\publicRRN.key");
			//We assume that the pkRRN is know for every SP
//			URL d = new URL("file:///C:\\Users\\vulst\\Documents\\School_4elict\\Veilige_software\\smartcard\\workspace\\CertificateAuthority\\src\\key\\publicRRN.key");
			System.out.println("the public key of the CA is succesfully found at: " + d);
			File filePublicKey = new File(d.toURI());
			FileInputStream fis = new FileInputStream(filePublicKey);
			byte[] encodedPublicKey = new byte[(int) filePublicKey.length()];
			fis.read(encodedPublicKey);
			fis.close();
	 
			// Generate Key
			KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
			X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(
					encodedPublicKey);
			PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
			
			//print out once to place him on the SC
//			RSAPublicKey rsapublicKey = (RSAPublicKey) publicKey;
//			System.out.println("CA_PK_EXP: " + bytesToDec(rsapublicKey.getPublicExponent().toByteArray()));
//			System.out.println("CA_PK_MOD: " + bytesToDec(rsapublicKey.getModulus().toByteArray()));
//			System.out.println("Length of PK mod after loading: (bits)" + rsapublicKey.getModulus().bitLength());

			return publicKey;
		}
	

	/***
     * TODO verify signature and sign certificate
     * @param signedDocumentResponse
     */
    private void verifyDigitalSignature(SignedDocumentResponse signedDocumentResponse) {
    	byte [] response = signedDocumentResponse.getResponse(); //nog samengeplakt cert (length 136) + gesignede hash
    	byte [] documentHash = signedDocumentResponse.getDocumentHash();
    	byte [] unsignedDocument = signedDocumentResponse.getUnsignedDocument();
    	
    	byte[] certificate = Arrays.copyOfRange(response, 0, 137);
    	byte[] bytesToSignCert = Arrays.copyOfRange(certificate, 1, 73);
    	byte[] bytesSignedCert = Arrays.copyOfRange(certificate, 73, 137);
    	
    	byte[] signedHashData = Arrays.copyOfRange(response, 137, response.length);
    	
    	//authenticiteit van document controleren
    	MessageDigest md;
		try {
			md = MessageDigest.getInstance("MD5");
			md.update(unsignedDocument);
			byte[] digest = md.digest();
			String checkSum = DatatypeConverter.printHexBinary(digest).toUpperCase();
			String receivedCheckSum = DatatypeConverter.printHexBinary(documentHash).toUpperCase();
			
			if(receivedCheckSum.equals(checkSum)) {
				mainController.addToDataLog("Checksum valid:");
				mainController.addToDataLog("	Sent hash = "+receivedCheckSum);
				mainController.addToDataLog("	Calculated hash = "+checkSum);
			}
			else {
				mainController.addToDataLog("Checksum invalid");
				mainController.addToDataLog("	Sent hash = "+receivedCheckSum);
				mainController.addToDataLog("	Calculated hash = "+checkSum);
				return;
			}
			
			//TODO authenticiteit van signature controleren op zelfde manier als verifyCert methode (gebruik doorgestuurd Cert met signedhash en unsignedhash)
			//controleer eerst certificaat als de sign van de CA klopt
			Signature verifier = Signature.getInstance("SHA1WithRSA");
			verifier.initVerify(CAService.loadPublicKey("RSA"));
			verifier.update(bytesToSignCert);
			System.out.println("To sign length: " + bytesToSignCert.length + "   signed length: " + bytesSignedCert.length);
			System.out.println("ToSign: " + bytesToDec(bytesToSignCert) );
			System.out.println("Signed: " + bytesToDec(bytesSignedCert));

            if(verifier.verify(bytesSignedCert)) {
    			mainController.addToDataLog("The certificate is valid signed by the CA!");
    			
    			//controleer signature op het doc met de op te bouwen pk van de kaart.
//    			System.out.println("where he cuts: bytesTosigncert: " + bytesToDec(bytesToSignCert));
    			BigInteger exponent = new BigInteger(1,Arrays.copyOfRange(bytesToSignCert, 0, 3));
    			byte [] exparray = exponent.toByteArray();
    			System.out.println("Exponent PK: "+ bytesToDec(exparray));
    			BigInteger modulus = new BigInteger(1,Arrays.copyOfRange(bytesToSignCert, 4, 68));
    			System.out.println(modulus);
    			
    			//CRL op basis van modulus, aangezien dit uniek is in deze omgeving.
    			if(!CRL.contains(modulus)) {
    			
    			byte [] modarray = modulus.toByteArray();
    			System.out.println( modarray.length + " modulus: "+ bytesToDec(modarray));
    			
    			RSAPublicKeySpec spec = new RSAPublicKeySpec(modulus, exponent);
    			KeyFactory factory = KeyFactory.getInstance("RSA");
    			PublicKey publicAuthKey = factory.generatePublic(spec);
    			verifier.initVerify(publicAuthKey);
    			verifier.update(documentHash); //hash van doc
    			System.out.println(bytesToDec(documentHash));

//    			System.out.println("check digital signature on doc: "+ verifier.verify(signedHashData)); //sign van hash van documentHash
    			if(verifier.verify(signedHashData)) {
        			mainController.addToDataLog("The document has a valid signature!");
    			}	
            }else {
    			mainController.addToDataLog("The beID is in the revocationlist, so it is not possible to put digital signatures!");
            }
            }
			
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}	
    }
    
    private void verifyResponseAndCertificate(AuthenticateToSPResponse responseFromSC) {
    	byte[] message = responseFromSC.getMessage();
    	//response en certificaat verifiëren
    	//check signature
    	try {
    		
    		//check if authentication certificate is valid
    		byte[] signedBytes = Arrays.copyOfRange(message, 0, 72);
			byte[] signature = Arrays.copyOfRange(message, 72, 136);
			Signature verifier = Signature.getInstance("SHA1WithRSA");
			verifier.initVerify(CAService.loadPublicKey("RSA"));
			verifier.update(signedBytes);
			
			if(!verifier.verify(signature)) {
				mainController.addToDataLog("eID authentication certificate is valid!");
			} 
			else {
				errorAuthCard = true;
				mainController.addToDataLog("eID authentication certificate is invalid!");
				return;
			}
			
			//verifieer signature op de response
			//eerst public authentication key opbouwen
			BigInteger exponent = new BigInteger(1,Arrays.copyOfRange(message, 1, 4));
			byte [] exparray = exponent.toByteArray();
			System.out.println("exponent: "+exponent);
			BigInteger modulus = new BigInteger(1,Arrays.copyOfRange(message, 6, 70));
			byte [] modarray = modulus.toByteArray();
			System.out.println("modulus: "+modulus);
			
			RSAPublicKeySpec spec = new RSAPublicKeySpec(modulus, exponent);
			KeyFactory factory = KeyFactory.getInstance("RSA");
			PublicKey publicAuthKey = factory.generatePublic(spec);
			verifier.initVerify(publicAuthKey);
			
			if(!verifier.verify(Arrays.copyOfRange(message, 156, 220))) {
				mainController.addToDataLog("eID sent valid response");
				mainController.addToDataLog("VALID AUTHENTICATION");
			} else {
				errorAuthCard = true;
				mainController.addToDataLog("eID sent invalid response");
				return;
			}
    	}
    	catch(Exception e) {
    		e.printStackTrace();
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
