package be.msec;
import be.msec.client.CallableMiddelwareMethodes;
import be.msec.client.Challenge;
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
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.rmi.RemoteException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

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
    
    public void sendServiceProviderActionToMiddleWare(ServiceProviderAction action) {
		ObjectOutputStream objectoutputstream = null;
		this.lastActionSPName = action.getServiceProvider();
		try {
			System.out.println("Send something to the middleware");
			objectoutputstream = new ObjectOutputStream(serviceProviderSocket.getOutputStream());
			objectoutputstream.writeObject(action);
			
			//wait for response
			receiveResponseFromMiddleWare();
			
		}catch (Exception e) {
			System.out.println(e);
		}
    }
    public void receiveResponseFromMiddleWare() {	
    	ObjectInputStream objectinputstream = null;
    	Object obj = null;
    	try {
			objectinputstream = new ObjectInputStream(serviceProviderSocket.getInputStream());
			
			obj = objectinputstream.readObject();
			if(obj instanceof Challenge) {
				Challenge challengeFromSC = (Challenge)obj;
				mainController.addToDataLog("Succesfully received challenge" );
				System.out.println(challengeFromSC.toString());
				//recreate session key, respond to challenge
				recreateSessionKey(challengeFromSC);
			}
			else if( obj instanceof String) {
				String answer = (String)obj;
				System.out.println("received string "+answer);
				mainController.addToDataLog("Succesfully received: " +answer);
			}
			else {
				System.out.println("unknown obj received");
			}
			
	
			System.out.println("succesfully received an answer!");
			
    	}catch (Exception e) {
			System.out.println(e);
		}
    }
    
    public void recreateSessionKey(Challenge challenge) {
    	byte[] nameBytes = challenge.getNameBytes();
    	byte[] rndBytes = challenge.getRndBytes();
    	byte [] challengeBytes = challenge.getChallengeBytes();
    	
    	System.out.println("encr chlng bytes  "+bytesToDec(challengeBytes));
		System.out.println("encr name bytes   "+bytesToDec(nameBytes));
    	
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
					System.out.println("decrypted rndbytes "+bytesToDec(rnd));
					
					
					//create session key
					byte[] ivdata = new byte[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
					this.ivSpec = new IvParameterSpec(ivdata);
					this.symKey = new SecretKeySpec(rnd, "AES");
					
					Cipher aesCipher = Cipher.getInstance("AES/CBC/NoPadding");
					aesCipher.init(Cipher.DECRYPT_MODE, this.symKey, this.ivSpec);
					decryptedChallengeBytes = aesCipher.doFinal(challengeBytes);
					decryptedNameBytes = aesCipher.doFinal(nameBytes);
					
					System.out.println("decrypted chlng bytes  "+bytesToDec(decryptedChallengeBytes));
					System.out.println("decrypted name bytes   "+bytesToDec(decryptedNameBytes));
					String name = new String(decryptedNameBytes);
					
					
					BigInteger reqChallenge = new BigInteger(decryptedChallengeBytes);
					System.out.println(name + "  " + reqChallenge.toString());
					BigInteger respChallenge =reqChallenge.add(BigInteger.ONE);
					byte [] respChallengeBytes = respChallenge.toByteArray();
					
					//TODO encrypt challenge response
					aesCipher.init(Cipher.ENCRYPT_MODE, this.symKey, this.ivSpec);
					byte[] encryptedRespChallenge = aesCipher.doFinal(respChallengeBytes);
					//send challenge response back to MW
					ServiceProviderAction action = new ServiceProviderAction(new ServiceAction("verify challenge", CallableMiddelwareMethodes.VERIFY_CHALLENGE), null);
					action.setChallengeBytes(encryptedRespChallenge);
					sendServiceProviderActionToMiddleWare(action);
					
				} catch (Exception e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} 
    			
    			
    		}
    	}
    	
    }
    public void connectToMiddleWare() {
    	try {
			serviceProviderSocket = new Socket("localhost", portSP);
		} catch (IOException ex) {
			System.out.println("CANNOT CONNECT TO MIDDLEWARE " + ex);
		}
		System.out.println("Serviceprovider connected to middleware: " + serviceProviderSocket);

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

    //utility
    public String bytesToDec(byte[] barray) {
		String str = "";
		for (byte b : barray)
			str += (int) b + ", ";
		return str;
	}

}
