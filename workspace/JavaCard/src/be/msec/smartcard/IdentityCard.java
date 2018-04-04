package be.msec.smartcard;

import javacard.framework.APDU;
import javacardx.apdu.ExtendedLength; 
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.*;
import javacard.framework.JCSystem;
import javacard.framework.OwnerPIN;
import javacard.security.KeyBuilder;
import javacard.security.RSAPrivateKey;
import javacard.security.Signature;

public class IdentityCard extends Applet implements ExtendedLength {
	private final static byte IDENTITY_CARD_CLA =(byte)0x80;
	
	private static final byte VALIDATE_PIN_INS = 0x22;
	private static final byte GET_NAME_INS = 0x24;
	private static final byte GET_SERIAL_INS = 0x26;
	private static final byte SIGN_RANDOM_BYTE = 0x27;
	private static final byte GET_CERTIFICATE = 0x28;
	private static final byte GET_BIGDATA = 0x29;
	
	private final static byte PIN_TRY_LIMIT =(byte)0x03;
	private final static byte PIN_SIZE =(byte)0x04;
	
	private final static short SW_VERIFICATION_FAILED = 0x6300;
	private final static short SW_PIN_VERIFICATION_REQUIRED = 0x6301;
	
	private final static short ERROR_OUT_OF_BOUNDS = (short) 0x8001;
	private final static short ERROR_UNKNOW = (short) 0x8888;

	private byte[] privModulus = new byte[]{(byte)-73, (byte)-43, (byte)96, (byte)-107, (byte)82, (byte)25, (byte)-66, (byte)34, (byte)5, (byte)-58, (byte)75, (byte)-39, (byte)-54, (byte)43, (byte)25, (byte)-117, (byte)80, (byte)-62, (byte)51, (byte)19, (byte)59, (byte)-70, (byte)-100, (byte)85, (byte)24, (byte)-57, (byte)108, (byte)-98, (byte)-2, (byte)1, (byte)-80, (byte)-39, (byte)63, (byte)93, (byte)112, (byte)7, (byte)4, (byte)18, (byte)-11, (byte)-98, (byte)17, (byte)126, (byte)-54, (byte)27, (byte)-56, (byte)33, (byte)77, (byte)-111, (byte)-74, (byte)-78, (byte)88, (byte)70, (byte)-22, (byte)-3, (byte)15, (byte)16, (byte)37, (byte)-18, (byte)92, (byte)74, (byte)124, (byte)-107, (byte)-116, (byte)-125};
	private byte[] privExponent = new byte[]{(byte)24, (byte)75, (byte)93, (byte)-79, (byte)62, (byte)33, (byte)98, (byte)-52, (byte)50, (byte)65, (byte)43, (byte)-125, (byte)3, (byte)-63, (byte)-64, (byte)101, (byte)117, (byte)-19, (byte)-60, (byte)60, (byte)53, (byte)119, (byte)-118, (byte)-13, (byte)-128, (byte)11, (byte)-46, (byte)-30, (byte)12, (byte)37, (byte)-125, (byte)14, (byte)104, (byte)-5, (byte)-15, (byte)-120, (byte)-113, (byte)-49, (byte)-70, (byte)-78, (byte)114, (byte)122, (byte)34, (byte)114, (byte)-99, (byte)-102, (byte)43, (byte)-43, (byte)-102, (byte)71, (byte)115, (byte)116, (byte)-105, (byte)-48, (byte)-80, (byte)109, (byte)117, (byte)106, (byte)88, (byte)6, (byte)-69, (byte)-42, (byte)-83, (byte)25};

	private byte[] certificate = new byte[]{(byte)48, (byte)-126, (byte)1, (byte)-67, (byte)48, (byte)-126, (byte)1, (byte)103, (byte)-96, (byte)3, (byte)2, (byte)1, (byte)2, (byte)2, (byte)5, (byte)0, (byte)-73, (byte)-43, (byte)96, (byte)-107, (byte)48, (byte)13, (byte)6, (byte)9, (byte)42, (byte)-122, (byte)72, (byte)-122, (byte)-9, (byte)13, (byte)1, (byte)1, (byte)5, (byte)5, (byte)0, (byte)48, (byte)100, (byte)49, (byte)11, (byte)48, (byte)9, (byte)6, (byte)3, (byte)85, (byte)4, (byte)6, (byte)19, (byte)2, (byte)66, (byte)69, (byte)49, (byte)13, (byte)48, (byte)11, (byte)6, (byte)3, (byte)85, (byte)4, (byte)7, (byte)12, (byte)4, (byte)71, (byte)101, (byte)110, (byte)116, (byte)49, (byte)25, (byte)48, (byte)23, (byte)6, (byte)3, (byte)85, (byte)4, (byte)10, (byte)12, (byte)16, (byte)75, (byte)97, (byte)72, (byte)111, (byte)32, (byte)83, (byte)105, (byte)110, (byte)116, (byte)45, (byte)76, (byte)105, (byte)101, (byte)118, (byte)101, (byte)110, (byte)49, (byte)20, (byte)48, (byte)18, (byte)6, (byte)3, (byte)85, (byte)4, (byte)11, (byte)12, (byte)11, (byte)86, (byte)97, (byte)107, (byte)103, (byte)114, (byte)111, (byte)101, (byte)112, (byte)32, (byte)73, (byte)84, (byte)49, (byte)21, (byte)48, (byte)19, (byte)6, (byte)3, (byte)85, (byte)4, (byte)3, (byte)12, (byte)12, (byte)74, (byte)97, (byte)110, (byte)32, (byte)86, (byte)111, (byte)115, (byte)115, (byte)97, (byte)101, (byte)114, (byte)116, (byte)48, (byte)32, (byte)23, (byte)13, (byte)49, (byte)48, (byte)48, (byte)50, (byte)50, (byte)52, (byte)48, (byte)57, (byte)52, (byte)51, (byte)48, (byte)50, (byte)90, (byte)24, (byte)15, (byte)53, (byte)49, (byte)55, (byte)57, (byte)48, (byte)49, (byte)48, (byte)57, (byte)49, (byte)57, (byte)50, (byte)57, (byte)52, (byte)50, (byte)90, (byte)48, (byte)100, (byte)49, (byte)11, (byte)48, (byte)9, (byte)6, (byte)3, (byte)85, (byte)4, (byte)6, (byte)19, (byte)2, (byte)66, (byte)69, (byte)49, (byte)13, (byte)48, (byte)11, (byte)6, (byte)3, (byte)85, (byte)4, (byte)7, (byte)12, (byte)4, (byte)71, (byte)101, (byte)110, (byte)116, (byte)49, (byte)25, (byte)48, (byte)23, (byte)6, (byte)3, (byte)85, (byte)4, (byte)10, (byte)12, (byte)16, (byte)75, (byte)97, (byte)72, (byte)111, (byte)32, (byte)83, (byte)105, (byte)110, (byte)116, (byte)45, (byte)76, (byte)105, (byte)101, (byte)118, (byte)101, (byte)110, (byte)49, (byte)20, (byte)48, (byte)18, (byte)6, (byte)3, (byte)85, (byte)4, (byte)11, (byte)12, (byte)11, (byte)86, (byte)97, (byte)107, (byte)103, (byte)114, (byte)111, (byte)101, (byte)112, (byte)32, (byte)73, (byte)84, (byte)49, (byte)21, (byte)48, (byte)19, (byte)6, (byte)3, (byte)85, (byte)4, (byte)3, (byte)12, (byte)12, (byte)74, (byte)97, (byte)110, (byte)32, (byte)86, (byte)111, (byte)115, (byte)115, (byte)97, (byte)101, (byte)114, (byte)116, (byte)48, (byte)92, (byte)48, (byte)13, (byte)6, (byte)9, (byte)42, (byte)-122, (byte)72, (byte)-122, (byte)-9, (byte)13, (byte)1, (byte)1, (byte)1, (byte)5, (byte)0, (byte)3, (byte)75, (byte)0, (byte)48, (byte)72, (byte)2, (byte)65, (byte)0, (byte)-73, (byte)-43, (byte)96, (byte)-107, (byte)82, (byte)25, (byte)-66, (byte)34, (byte)5, (byte)-58, (byte)75, (byte)-39, (byte)-54, (byte)43, (byte)25, (byte)-117, (byte)80, (byte)-62, (byte)51, (byte)19, (byte)59, (byte)-70, (byte)-100, (byte)85, (byte)24, (byte)-57, (byte)108, (byte)-98, (byte)-2, (byte)1, (byte)-80, (byte)-39, (byte)63, (byte)93, (byte)112, (byte)7, (byte)4, (byte)18, (byte)-11, (byte)-98, (byte)17, (byte)126, (byte)-54, (byte)27, (byte)-56, (byte)33, (byte)77, (byte)-111, (byte)-74, (byte)-78, (byte)88, (byte)70, (byte)-22, (byte)-3, (byte)15, (byte)16, (byte)37, (byte)-18, (byte)92, (byte)74, (byte)124, (byte)-107, (byte)-116, (byte)-125, (byte)2, (byte)3, (byte)1, (byte)0, (byte)1, (byte)48, (byte)13, (byte)6, (byte)9, (byte)42, (byte)-122, (byte)72, (byte)-122, (byte)-9, (byte)13, (byte)1, (byte)1, (byte)5, (byte)5, (byte)0, (byte)3, (byte)65, (byte)0, (byte)33, (byte)97, (byte)121, (byte)-25, (byte)43, (byte)-47, (byte)113, (byte)-104, (byte)-11, (byte)-42, (byte)-46, (byte)-17, (byte)1, (byte)-38, (byte)50, (byte)59, (byte)-63, (byte)-74, (byte)-33, (byte)90, (byte)92, (byte)-59, (byte)99, (byte)-17, (byte)-60, (byte)17, (byte)25, (byte)79, (byte)68, (byte)68, (byte)-57, (byte)-8, (byte)-64, (byte)35, (byte)-19, (byte)-114, (byte)110, (byte)-116, (byte)31, (byte)-126, (byte)-24, (byte)54, (byte)71, (byte)82, (byte)-53, (byte)-78, (byte)-84, (byte)-45, (byte)-83, (byte)87, (byte)68, (byte)124, (byte)-1, (byte)-128, (byte)-49, (byte)124, (byte)103, (byte)28, (byte)56, (byte)-114, (byte)-10, (byte)97, (byte)-78, (byte)54};
	// test data
	private byte[] bigdata = new byte[]{(byte)1, (byte)2, (byte)3, (byte)4, (byte)5, (byte)6, (byte)7, (byte)8, (byte)9, (byte)10, (byte)11, (byte)12, (byte)13, (byte)14, (byte)15, (byte)16, (byte)17, (byte)18, (byte)19, (byte)20, (byte)21, (byte)22, (byte)23, (byte)24, (byte)25,(byte)26, (byte)27, (byte)28, (byte)29, (byte)30, (byte)31, (byte)32, (byte)33, (byte)34, (byte)35, (byte)36, (byte)37, (byte)38, (byte)39, (byte)40, (byte)41, (byte)42, (byte)43, (byte)44, (byte)45, (byte)46, (byte)47, (byte)48, (byte)49, (byte)50,(byte)51, (byte)52, (byte)53, (byte)54, (byte)55, (byte)56, (byte)57, (byte)58, (byte)59, (byte)60, (byte)61, (byte)62, (byte)63, (byte)64, (byte)65, (byte)66, (byte)67, (byte)68, (byte)69, (byte)70, (byte)71, (byte)72, (byte)73, (byte)74, (byte)75,(byte)76, (byte)77, (byte)78, (byte)79, (byte)80, (byte)81, (byte)82, (byte)83, (byte)84, (byte)85, (byte)86, (byte)87, (byte)88, (byte)89, (byte)90, (byte)91, (byte)92, (byte)93, (byte)94, (byte)95, (byte)96, (byte)97, (byte)98, (byte)99, (byte)100,(byte)101, (byte)102, (byte)103, (byte)104, (byte)105, (byte)106, (byte)107, (byte)108, (byte)109, (byte)110, (byte)111, (byte)112, (byte)113, (byte)114, (byte)115, (byte)116, (byte)117, (byte)118, (byte)119, (byte)120, (byte)121, (byte)122, (byte)123, (byte)124, (byte)125,(byte)126, (byte)127, (byte)128, (byte)129, (byte)130, (byte)131, (byte)132, (byte)133, (byte)134, (byte)135, (byte)136, (byte)137, (byte)138, (byte)139, (byte)140, (byte)141, (byte)142, (byte)143, (byte)144, (byte)145, (byte)146, (byte)147, (byte)148, (byte)149, (byte)150, (byte)151, (byte)152, (byte)153, (byte)154, (byte)155, (byte)156, (byte)157, (byte)158, (byte)159, (byte)160, (byte)161, (byte)162, (byte)163, (byte)164, (byte)165, (byte)166, (byte)167, (byte)168, (byte)169, (byte)170, (byte)171, (byte)172, (byte)173, (byte)174, (byte)175, (byte)176, (byte)177, (byte)178, (byte)179, (byte)180, (byte)181, (byte)182, (byte)183, (byte)184, (byte)185, (byte)186, (byte)187, (byte)188, (byte)189, (byte)190, (byte)191, (byte)192, (byte)193, (byte)194, (byte)195, (byte)196, (byte)197, (byte)198, (byte)199, (byte)200,(byte)201, (byte)202, (byte)203, (byte)204, (byte)205, (byte)206, (byte)207, (byte)208, (byte)209, (byte)210, (byte)211, (byte)212, (byte)213, (byte)214, (byte)215, (byte)216, (byte)217, (byte)218, (byte)219, (byte)220, (byte)221, (byte)222, (byte)223, (byte)224, (byte)225,(byte)226, (byte)227, (byte)228, (byte)229, (byte)230, (byte)231, (byte)232, (byte)233, (byte)234, (byte)235, (byte)236, (byte)237, (byte)238, (byte)239, (byte)240, (byte)241, (byte)242, (byte)243, (byte)244, (byte)245, (byte)246, (byte)247, (byte)248, (byte)249, (byte)250,(byte)251, (byte)252, (byte)253, (byte)254, (byte)255, (byte)256, (byte)257, (byte)258, (byte)259, (byte)260, (byte)261, (byte)262, (byte)263, (byte)264, (byte)265, (byte)266, (byte)267, (byte)268, (byte)269, (byte)270, (byte)271, (byte)272, (byte)273, (byte)274, (byte)275,(byte)276, (byte)277, (byte)278, (byte)279, (byte)280, (byte)281, (byte)282, (byte)283, (byte)284, (byte)285, (byte)286, (byte)287, (byte)288, (byte)289, (byte)290, (byte)291, (byte)292, (byte)293, (byte)294, (byte)295, (byte)296, (byte)297, (byte)298, (byte)299, (byte)300,(byte)301, (byte)302, (byte)303, (byte)304, (byte)305, (byte)306, (byte)307, (byte)308, (byte)309, (byte)310, (byte)311, (byte)312, (byte)313, (byte)314, (byte)315, (byte)316, (byte)317, (byte)318, (byte)319, (byte)320, (byte)321, (byte)322, (byte)323, (byte)324, (byte)325,(byte)326, (byte)327, (byte)328, (byte)329, (byte)330, (byte)331, (byte)332, (byte)333, (byte)334, (byte)335, (byte)336, (byte)337, (byte)338, (byte)339, (byte)340, (byte)341, (byte)342, (byte)343, (byte)344, (byte)345, (byte)346, (byte)347, (byte)348, (byte)349, (byte)350,(byte)351, (byte)352, (byte)353, (byte)354, (byte)355, (byte)356, (byte)357, (byte)358, (byte)359, (byte)360, (byte)361, (byte)362, (byte)363, (byte)364, (byte)365, (byte)366, (byte)367, (byte)368, (byte)369, (byte)370, (byte)371, (byte)372, (byte)373, (byte)374, (byte)375,(byte)376, (byte)377, (byte)378, (byte)379, (byte)380, (byte)381, (byte)382, (byte)383, (byte)384, (byte)385, (byte)386, (byte)387, (byte)388, (byte)389, (byte)390, (byte)391, (byte)392, (byte)393, (byte)394, (byte)395, (byte)396, (byte)397, (byte)398, (byte)399, (byte)400,(byte)401, (byte)402, (byte)403, (byte)404, (byte)405, (byte)406, (byte)407, (byte)408, (byte)409, (byte)410, (byte)411, (byte)412, (byte)413, (byte)414, (byte)415, (byte)416, (byte)417, (byte)418, (byte)419, (byte)420, (byte)421, (byte)422, (byte)423, (byte)424, (byte)425,(byte)426, (byte)427, (byte)428, (byte)429, (byte)430, (byte)431, (byte)432, (byte)433, (byte)434, (byte)435, (byte)436, (byte)437, (byte)438, (byte)439, (byte)440, (byte)441, (byte)442, (byte)443, (byte)444, (byte)445, (byte)446, (byte)447, (byte)448, (byte)449, (byte)450,(byte)451, (byte)452, (byte)453, (byte)454, (byte)455, (byte)456, (byte)457, (byte)458, (byte)459, (byte)460, (byte)461, (byte)462, (byte)463, (byte)464, (byte)465, (byte)466, (byte)467, (byte)468, (byte)469, (byte)470, (byte)471, (byte)472, (byte)473, (byte)474, (byte)475,(byte)476, (byte)477, (byte)478, (byte)479, (byte)480, (byte)481, (byte)482, (byte)483, (byte)484, (byte)485, (byte)486, (byte)487, (byte)488, (byte)489, (byte)490, (byte)491, (byte)492, (byte)493, (byte)494, (byte)495, (byte)496, (byte)497, (byte)498, (byte)499, (byte)500};
	private byte[] smalldata = new byte[]{(byte)1, (byte)2, (byte)3, (byte)4, (byte)5, (byte)6, (byte)7, (byte)8, (byte)9, (byte)10};
	private byte[] verysmalldata = new byte[]{(byte)1, (byte)2};
	
	private byte[] serial = new byte[]{(byte)0x4A, (byte)0x61, (byte)0x6e};
	private byte[] name = new byte[]{0x4A, 0x61, 0x6E, 0x20, 0x56, 0x6F, 0x73, 0x73, 0x61, 0x65, 0x72, 0x74};
	private OwnerPIN pin;
	private short offset = 0;
	private short keySizeInBytes = 64;
	private short keySizeInBits = 512;
	private RSAPrivateKey privKey = null;
	
	private byte messageIndex = 0x00;
	
	private final static short MAX_APDU = 240;
	private short BUF_IN_OFFSET[];
	private byte data[];

	private IdentityCard() {
		/*
		 * During instantiation of the applet, all objects are created.
		 * In this example, this is the 'pin' object.
		 */
		//max try 3 times
		pin = new OwnerPIN(PIN_TRY_LIMIT,PIN_SIZE);
		//pin is 1234
		pin.update(new byte[]{0x31,0x32,0x33,0x34},(short) 0, PIN_SIZE);
		//needed for the signature of a random byte array
		privKey = (RSAPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE, keySizeInBits, false);
		privKey.setExponent(privExponent, offset, keySizeInBytes);
		privKey.setModulus(privModulus, offset, keySizeInBytes);
		/*
		 * This method registers the applet with the JCRE on the card.
		 */
		register();
		BUF_IN_OFFSET = JCSystem.makeTransientShortArray((short) 1, JCSystem.CLEAR_ON_DESELECT);
	}

	/*
	 * This method is called by the JCRE when installing the applet on the card.
	 */
	public static void install(byte bArray[], short bOffset, byte bLength)
			throws ISOException {
		new IdentityCard();
	}
	
	/*
	 * If no tries are remaining, the applet refuses selection.
	 * The card can, therefore, no longer be used for identification.
	 */
	public boolean select() {
		if (pin.getTriesRemaining()==0)
			return false;
		return true;
	}

	/*
	 * This method is called when the applet is selected and an APDU arrives.
	 */
	public void process(APDU apdu) throws ISOException {
		//A reference to the buffer, where the APDU data is stored, is retrieved.
		byte[] buffer = apdu.getBuffer();
		
		//If the APDU selects the applet, no further processing is required.
		if(this.selectingApplet())
			return;
		
		//Check whether the indicated class of instructions is compatible with this applet.
		if (buffer[ISO7816.OFFSET_CLA] != IDENTITY_CARD_CLA)ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		//A switch statement is used to select a method depending on the instruction
		switch(buffer[ISO7816.OFFSET_INS]){
		case VALIDATE_PIN_INS:
			validatePIN(apdu);
			break;
		case GET_SERIAL_INS:
			getSerial(apdu);
			break;
		case GET_NAME_INS:
			getName(apdu);
			break;
		case GET_CERTIFICATE:
			sendCertificate(apdu);
			break;
		case SIGN_RANDOM_BYTE:
			sign(apdu);
			break;
		//If no matching instructions are found it is indicated in the status word of the response.
		//This can be done by using this method. As an argument a short is given that indicates
		//the type of warning. There are several predefined warnings in the 'ISO7816' class.
		default: ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}
	
	/*
	 * This method is used to authenticate the owner of the card using a PIN code.
	 */
	
	private void validatePIN(APDU apdu){
		byte[] buffer = apdu.getBuffer();
		//The input data needs to be of length 'PIN_SIZE'.
		//Note that the byte values in the Lc and Le fields represent values between
		//0 and 255. Therefore, if a short representation is required, the following
		//code needs to be used: short Lc = (short) (buffer[ISO7816.OFFSET_LC] & 0x00FF);
		if(buffer[ISO7816.OFFSET_LC]==PIN_SIZE){
			//This method is used to copy the incoming data in the APDU buffer.
			apdu.setIncomingAndReceive();
			//Note that the incoming APDU data size may be bigger than the APDU buffer 
			//size and may, therefore, need to be read in portions by the applet. 
			//Most recent smart cards, however, have buffers that can contain the maximum
			//data size. This can be found in the smart card specifications.
			//If the buffer is not large enough, the following method can be used:
			//
			//byte[] buffer = apdu.getBuffer();
			//short bytesLeft = (short) (buffer[ISO7816.OFFSET_LC] & 0x00FF);
			//Util.arrayCopy(buffer, START, storage, START, (short)5);
			//short readCount = apdu.setIncomingAndReceive();
			//short i = ISO7816.OFFSET_CDATA;
			//while ( bytesLeft > 0){
			//	Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, storage, i, readCount);
			//	bytesLeft -= readCount;
			//	i+=readCount;
			//	readCount = apdu.receiveBytes(ISO7816.OFFSET_CDATA);
			//}
			if (pin.check(buffer, ISO7816.OFFSET_CDATA,PIN_SIZE)==false)
				ISOException.throwIt(SW_VERIFICATION_FAILED);
		}else ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
	}
	
	
	
	private void sign(APDU apdu) {
		try {
		
		if(!pin.isValidated())ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
		else{
			 // apdu.getBuffer() bevat alle data dus eerste bits moeten er nog af want behoren niet tot dataveld.
			
			//--------- Poging voor het inlezen van data die langer is als max lengte. Zit nog een foutje in --------------
//			short dataOffset = apdu.getOffsetCdata(); // nodig om eerste 5 bytes er af te knippen.
////			hoe kun je deze lengte weten?
//			
//			short bytesLeft = (short) (apdu.getBuffer()[ISO7816.OFFSET_LC] & 0x00FF);
//			byte[] buffer = new byte[bytesLeft];
//			Util.arrayCopy(apdu.getBuffer(), dataOffset, buffer, (short) 0, bytesLeft);
//			
//			short readCount = apdu.setIncomingAndReceive();
//			bytesLeft -= readCount;
//			while ( bytesLeft > 0){
//				Util.arrayCopy(apdu.getBuffer(), ISO7816.OFFSET_CDATA, buffer, dataOffset, readCount);
//				bytesLeft -= readCount;
//				dataOffset+=readCount;
//				readCount = apdu.receiveBytes(ISO7816.OFFSET_CDATA);
//			}
			byte[] outputBuffer = new byte[100];
			byte[] buffer = new byte[apdu.getIncomingLength()];
			Util.arrayCopy(apdu.getBuffer(), apdu.getOffsetCdata(), buffer,(short) 0,(short) apdu.getIncomingLength());
			
			Signature signature = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);
			signature.init(privKey, Signature.MODE_SIGN);
			short responsLength = signature.sign(buffer,(short) 0, (short)(buffer.length), outputBuffer, (short) 0 );
			apdu.setOutgoing();
			apdu.setOutgoingLength((short)responsLength);
			apdu.sendBytesLong(outputBuffer,(short)0,responsLength);
		}
		}catch(Exception e) {
			if(e instanceof ArrayIndexOutOfBoundsException) {
            	ISOException.throwIt(ERROR_OUT_OF_BOUNDS);
            }else {
            	ISOException.throwIt(ERROR_UNKNOW);
            }
		}
	}
	
	private void getCertificate(APDU apdu) {
		//if the pin is validated --> return certificate
//		byte [] partOfCertificate = new byte[240];
//		byte[] buffer = apdu.getBuffer();
//		offset = buffer[ISO7816.OFFSET_P1];
//		short length = (short) certificate.length;
//		if(!pin.isValidated())ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
//		else{
//			if(offset == 0x01) offset = 238;
//			for (short i = 0; (i < 240) && ((offset + i) < certificate.length); i++) {
//				partOfCertificate[i] = certificate[offset + i];
//			}
//			apdu.setOutgoing();
//			apdu.setOutgoingLength((short)partOfCertificate.length);
//			apdu.sendBytesLong(partOfCertificate,(short)0,(short)partOfCertificate.length);
//		}
	}
	
	/*
	 * This method checks whether the user is authenticated and sends
	 * the serial number.
	 */
	private void getSerial(APDU apdu){
		//If the pin is not validated, a response APDU with the
		//'SW_PIN_VERIFICATION_REQUIRED' status word is transmitted.
		if(!pin.isValidated())ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
		else{
			//This sequence of three methods sends the data contained in
			//'serial' with offset '0' and length 'serial.length'
			//to the host application.
			apdu.setOutgoing();
			apdu.setOutgoingLength((short)serial.length);
			apdu.sendBytesLong(serial,(short)0,(short)serial.length);
		}
	}
	
	private void getName(APDU apdu){
		//If the pin is not validated, a response APDU with the
		//'SW_PIN_VERIFICATION_REQUIRED' status word is transmitted.
		if(!pin.isValidated())ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
		else{
			//This sequence of three methods sends the data contained in
			//'serial' with offset '0' and length 'serial.length'
			//to the host application.
			apdu.setOutgoing();
			apdu.setOutgoingLength((short)name.length);
			apdu.sendBytesLong(name,(short)0,(short)name.length);
		}
	}
	/**
	 * Method works! Send the whole certificate to the client in pieces of 32 bytes.
	 * @param apdu
	 */
	private void sendCertificate(APDU apdu) {
		//Send big files
		short toSend = (short) (certificate.length);
 
		try {
            apdu.setOutgoing(); // change direction of data channel
            apdu.setOutgoingLength(toSend); // set total amount of byte you want to transfer
            short lenToSend =32; // send all the data in pieces of each 32 bytes
            byte counter = 0;
            while (toSend > 0) {
            	if(toSend<32) { // if data to send is not muliple of 32 
            		lenToSend = toSend;
            	}
            	apdu.sendBytesLong(certificate, (short) (32 * counter),lenToSend); // send part of certificate each time.
                toSend = (short) (toSend - 32);
                counter = (byte) (counter + 1);
            }
        } catch (Exception e) {
            if (e instanceof APDUException) {
                APDUException ae = (APDUException) e;
                short reason = ae.getReason();
                if (reason == APDUException.BAD_LENGTH)
                    ISOException.throwIt((short) 0x9990);
                else
                    ISOException.throwIt((short) 0x8887);
            } else if(e instanceof ArrayIndexOutOfBoundsException) {
            	ISOException.throwIt(ERROR_OUT_OF_BOUNDS);
            }
            else {
                ISOException.throwIt(ERROR_UNKNOW);
            }
        }
    }
}