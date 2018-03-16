package be.msec.client;

import be.msec.client.connection.Connection;
import be.msec.client.connection.IConnection;
import be.msec.client.connection.SimulatedConnection;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

import javax.smartcardio.*;

public class Client {
	
	private final static byte IDENTITY_CARD_CLA =(byte)0x80;
	private static final byte VALIDATE_PIN_INS = 0x22;
	private final static short SW_VERIFICATION_FAILED = 0x6300;
	private final static short SW_PIN_VERIFICATION_REQUIRED = 0x6301;
	private static final byte GET_SERIAL_INS = 0x26;
	private static final byte GET_NAME_INS = 0x24;
	private static final byte SIGN_RANDOM_BYTE = 0x27;


	/**
	 * @param args
	 */
	public static void main(String[] args) throws Exception {
		IConnection c;

		//Simulation:
		c = new SimulatedConnection();

		//Real Card:
//		c = new Connection();
//		((Connection)c).setTerminal(0); //depending on which cardreader you use
		System.out.println("Do simulate connecting...");
		c.connect(); 
		System.out.println("Connected");
		try {

			/*
			 * For more info on the use of CommandAPDU and ResponseAPDU:
			 * See http://java.sun.com/javase/6/docs/jre/api/security/smartcardio/spec/index.html
			 */
			
			CommandAPDU a;
			ResponseAPDU r;
			
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
			
			//2. Send PIN
			//die cla is altijd zelfde: gwn aangeven welke instructieset
			//ins geeft aan wat er moet gebeuren --> dit getal staat ook vast in applet
			//new byte[] geeft de pincode aan dus dit zou je normaal ingeven door de gebruiker
			a = new CommandAPDU(IDENTITY_CARD_CLA, VALIDATE_PIN_INS, 0x00, 0x00,new byte[]{0x01,0x02,0x03,0x04});
			r = c.transmit(a);
			System.out.print("Pin ok? ");
			System.out.println(r);
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
			
			//4. cryptographic operation on card: send a random byte array
			System.out.println("Send random byte array name");
			SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
			byte [] randbytes = new byte[20];
			random.nextBytes(randbytes);
			System.out.println(randbytes);
			a = new CommandAPDU(IDENTITY_CARD_CLA, SIGN_RANDOM_BYTE, 0x00, 0x00, randbytes);
			r = c.transmit(a);
			if (r.getSW()==SW_VERIFICATION_FAILED) throw new Exception("ERROR");
			else if(r.getSW()!=0x9000) throw new Exception("Exception on the card: " + r.getSW());
			str = new String(r.getData(), StandardCharsets.UTF_8);
			System.out.println("Signed is: " + str);
			
			//5. transferring large amounts of data
			
		} catch (Exception e) {
			throw e;
		}
		finally {
			c.close();  // close the connection with the card
		}


	}

}
