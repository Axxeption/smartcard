package be.msec.smartcard;

import javacard.framework.APDU;
import javacardx.apdu.ExtendedLength;
import javacardx.crypto.Cipher;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.util.Arrays;

import javax.swing.plaf.metal.MetalIconFactory.FolderIcon16;

//TODO beno deze magje niet gebruiken ;) cheater
//import java.io.ByteArrayOutputStream;
//import java.io.IOException;
//import java.math.BigInteger;

import javacard.framework.*;
import javacard.framework.JCSystem;
import javacard.framework.OwnerPIN;
import javacard.security.AESKey;
import javacard.security.InitializedMessageDigest;
import javacard.security.KeyBuilder;
import javacard.security.MessageDigest;
import javacard.security.RSAPrivateKey;
import javacard.security.RSAPublicKey;
import javacard.security.RandomData;
import javacard.security.Signature;

public class IdentityCard extends Applet implements ExtendedLength {
	private final static byte IDENTITY_CARD_CLA = (byte) 0x80;

	private static final byte VALIDATE_PIN_INS = 0x22;
	private static final byte GET_NAME_INS = 0x24;
	private static final byte IDENTIFICATION = 0x26;
	private static final byte SIGN_RANDOM_BYTE = 0x27;
	private static final byte GET_CERTIFICATE = 0x28;
	private static final byte GET_BIGDATA = 0x29;
	private static final byte UPDATE_TIME = 0x25;
	private static final byte AUTHENTICATE_SP = 0x21;
	private static final byte VERIFY_CHALLENGE = 0x29;
	private static final byte AUTHENTICATE_CARD = 0x30;
	private static final byte RELEASE_ATTRIBUTE = 0x31;
	private static final byte AUTH_TO_SP = 0x32;
	private static final byte SIGN_HASH  = 0x33;


	private final static byte PIN_TRY_LIMIT = (byte) 0x03;
	private final static byte PIN_SIZE = (byte) 0x04;

	private final static short SW_VERIFICATION_FAILED = 0x6300;
	private final static short SW_PIN_VERIFICATION_REQUIRED = 0x6301;

	private final static short ERROR_OUT_OF_BOUNDS = (short) 0x8001;
	private final static short ERROR_UNKNOW = (short) 0x8888;
	private final static short ERROR_AUTHENTICATESP = (short) 0x8889;

	private final static short ERROR_WRONG_TIME = (short) 0x8002;
	private final static short ERROR_WRONG_RIGHTS = (short) 0x8003;
	private final static short ENCRYPT_ERROR = (short) 0x8004;
	byte[] nameBytesCopy16;

	private byte[] privModulus = new byte[] { (byte) -73, (byte) -43, (byte) 96, (byte) -107, (byte) 82, (byte) 25,
			(byte) -66, (byte) 34, (byte) 5, (byte) -58, (byte) 75, (byte) -39, (byte) -54, (byte) 43, (byte) 25,
			(byte) -117, (byte) 80, (byte) -62, (byte) 51, (byte) 19, (byte) 59, (byte) -70, (byte) -100, (byte) 85,
			(byte) 24, (byte) -57, (byte) 108, (byte) -98, (byte) -2, (byte) 1, (byte) -80, (byte) -39, (byte) 63,
			(byte) 93, (byte) 112, (byte) 7, (byte) 4, (byte) 18, (byte) -11, (byte) -98, (byte) 17, (byte) 126,
			(byte) -54, (byte) 27, (byte) -56, (byte) 33, (byte) 77, (byte) -111, (byte) -74, (byte) -78, (byte) 88,
			(byte) 70, (byte) -22, (byte) -3, (byte) 15, (byte) 16, (byte) 37, (byte) -18, (byte) 92, (byte) 74,
			(byte) 124, (byte) -107, (byte) -116, (byte) -125 };
	private byte[] privExponent = new byte[] { (byte) 24, (byte) 75, (byte) 93, (byte) -79, (byte) 62, (byte) 33,
			(byte) 98, (byte) -52, (byte) 50, (byte) 65, (byte) 43, (byte) -125, (byte) 3, (byte) -63, (byte) -64,
			(byte) 101, (byte) 117, (byte) -19, (byte) -60, (byte) 60, (byte) 53, (byte) 119, (byte) -118, (byte) -13,
			(byte) -128, (byte) 11, (byte) -46, (byte) -30, (byte) 12, (byte) 37, (byte) -125, (byte) 14, (byte) 104,
			(byte) -5, (byte) -15, (byte) -120, (byte) -113, (byte) -49, (byte) -70, (byte) -78, (byte) 114, (byte) 122,
			(byte) 34, (byte) 114, (byte) -99, (byte) -102, (byte) 43, (byte) -43, (byte) -102, (byte) 71, (byte) 115,
			(byte) 116, (byte) -105, (byte) -48, (byte) -80, (byte) 109, (byte) 117, (byte) 106, (byte) 88, (byte) 6,
			(byte) -69, (byte) -42, (byte) -83, (byte) 25 };
	private byte[] pubMod_CA = new byte[] { (byte) -40, (byte) -96, (byte) 115, (byte) 21, (byte) -10, (byte) -66,
			(byte) 80, (byte) 28, (byte) -124, (byte) 29, (byte) 98, (byte) -23, (byte) -72, (byte) 60, (byte) 89,
			(byte) 21, (byte) -37, (byte) -122, (byte) -14, (byte) 94, (byte) -92, (byte) 48, (byte) 98, (byte) -35,
			(byte) 5, (byte) -37, (byte) -50, (byte) -46, (byte) 21, (byte) -117, (byte) -48, (byte) -20, (byte) 50,
			(byte) -80, (byte) -41, (byte) -126, (byte) -102, (byte) 63, (byte) -2, (byte) -10, (byte) 3, (byte) -86,
			(byte) -54, (byte) 105, (byte) -64, (byte) 47, (byte) -23, (byte) -104, (byte) -39, (byte) 35, (byte) 107,
			(byte) -46, (byte) -73, (byte) 2, (byte) 120, (byte) 112, (byte) -127, (byte) -37, (byte) 117, (byte) -79,
			(byte) 15, (byte) 9, (byte) 48, (byte) -45 };
	private byte[] pubExp_CA = new byte[] { (byte) 1, (byte) 0, (byte) 1 };
	private byte[] pubExp_G = new byte[] { (byte) 1, (byte) 0, (byte) 1 };
	// this length is 65 --> seems impossible? --> cropped first byte (was 0) so now
	// is length = 64
	private byte[] pubMod_G = new byte[] { (byte) -74, (byte) 55, (byte) 119, (byte) 89, (byte) 101, (byte) 50,
			(byte) 117, (byte) 36, (byte) 87, (byte) -53, (byte) -95, (byte) 37, (byte) -98, (byte) 14, (byte) 46,
			(byte) 51, (byte) 74, (byte) -2, (byte) 126, (byte) -50, (byte) 29, (byte) -58, (byte) 2, (byte) -67,
			(byte) 13, (byte) 44, (byte) -94, (byte) -30, (byte) 63, (byte) -94, (byte) -98, (byte) 63, (byte) -95,
			(byte) 38, (byte) 16, (byte) -9, (byte) -68, (byte) 94, (byte) 45, (byte) -89, (byte) -43, (byte) -39,
			(byte) -42, (byte) -39, (byte) -52, (byte) 80, (byte) 54, (byte) 3, (byte) -88, (byte) 77, (byte) 78,
			(byte) -128, (byte) 99, (byte) -17, (byte) -6, (byte) 62, (byte) 40, (byte) 29, (byte) 29, (byte) 25,
			(byte) 27, (byte) -40, (byte) -71, (byte) -127 };
	private byte[] lastValidationTime = new byte[] { (byte) 0 };
	private byte[] certificate = new byte[] { (byte) 48, (byte) -126, (byte) 1, (byte) -67, (byte) 48, (byte) -126,
			(byte) 1, (byte) 103, (byte) -96, (byte) 3, (byte) 2, (byte) 1, (byte) 2, (byte) 2, (byte) 5, (byte) 0,
			(byte) -73, (byte) -43, (byte) 96, (byte) -107, (byte) 48, (byte) 13, (byte) 6, (byte) 9, (byte) 42,
			(byte) -122, (byte) 72, (byte) -122, (byte) -9, (byte) 13, (byte) 1, (byte) 1, (byte) 5, (byte) 5, (byte) 0,
			(byte) 48, (byte) 100, (byte) 49, (byte) 11, (byte) 48, (byte) 9, (byte) 6, (byte) 3, (byte) 85, (byte) 4,
			(byte) 6, (byte) 19, (byte) 2, (byte) 66, (byte) 69, (byte) 49, (byte) 13, (byte) 48, (byte) 11, (byte) 6,
			(byte) 3, (byte) 85, (byte) 4, (byte) 7, (byte) 12, (byte) 4, (byte) 71, (byte) 101, (byte) 110, (byte) 116,
			(byte) 49, (byte) 25, (byte) 48, (byte) 23, (byte) 6, (byte) 3, (byte) 85, (byte) 4, (byte) 10, (byte) 12,
			(byte) 16, (byte) 75, (byte) 97, (byte) 72, (byte) 111, (byte) 32, (byte) 83, (byte) 105, (byte) 110,
			(byte) 116, (byte) 45, (byte) 76, (byte) 105, (byte) 101, (byte) 118, (byte) 101, (byte) 110, (byte) 49,
			(byte) 20, (byte) 48, (byte) 18, (byte) 6, (byte) 3, (byte) 85, (byte) 4, (byte) 11, (byte) 12, (byte) 11,
			(byte) 86, (byte) 97, (byte) 107, (byte) 103, (byte) 114, (byte) 111, (byte) 101, (byte) 112, (byte) 32,
			(byte) 73, (byte) 84, (byte) 49, (byte) 21, (byte) 48, (byte) 19, (byte) 6, (byte) 3, (byte) 85, (byte) 4,
			(byte) 3, (byte) 12, (byte) 12, (byte) 74, (byte) 97, (byte) 110, (byte) 32, (byte) 86, (byte) 111,
			(byte) 115, (byte) 115, (byte) 97, (byte) 101, (byte) 114, (byte) 116, (byte) 48, (byte) 32, (byte) 23,
			(byte) 13, (byte) 49, (byte) 48, (byte) 48, (byte) 50, (byte) 50, (byte) 52, (byte) 48, (byte) 57,
			(byte) 52, (byte) 51, (byte) 48, (byte) 50, (byte) 90, (byte) 24, (byte) 15, (byte) 53, (byte) 49,
			(byte) 55, (byte) 57, (byte) 48, (byte) 49, (byte) 48, (byte) 57, (byte) 49, (byte) 57, (byte) 50,
			(byte) 57, (byte) 52, (byte) 50, (byte) 90, (byte) 48, (byte) 100, (byte) 49, (byte) 11, (byte) 48,
			(byte) 9, (byte) 6, (byte) 3, (byte) 85, (byte) 4, (byte) 6, (byte) 19, (byte) 2, (byte) 66, (byte) 69,
			(byte) 49, (byte) 13, (byte) 48, (byte) 11, (byte) 6, (byte) 3, (byte) 85, (byte) 4, (byte) 7, (byte) 12,
			(byte) 4, (byte) 71, (byte) 101, (byte) 110, (byte) 116, (byte) 49, (byte) 25, (byte) 48, (byte) 23,
			(byte) 6, (byte) 3, (byte) 85, (byte) 4, (byte) 10, (byte) 12, (byte) 16, (byte) 75, (byte) 97, (byte) 72,
			(byte) 111, (byte) 32, (byte) 83, (byte) 105, (byte) 110, (byte) 116, (byte) 45, (byte) 76, (byte) 105,
			(byte) 101, (byte) 118, (byte) 101, (byte) 110, (byte) 49, (byte) 20, (byte) 48, (byte) 18, (byte) 6,
			(byte) 3, (byte) 85, (byte) 4, (byte) 11, (byte) 12, (byte) 11, (byte) 86, (byte) 97, (byte) 107,
			(byte) 103, (byte) 114, (byte) 111, (byte) 101, (byte) 112, (byte) 32, (byte) 73, (byte) 84, (byte) 49,
			(byte) 21, (byte) 48, (byte) 19, (byte) 6, (byte) 3, (byte) 85, (byte) 4, (byte) 3, (byte) 12, (byte) 12,
			(byte) 74, (byte) 97, (byte) 110, (byte) 32, (byte) 86, (byte) 111, (byte) 115, (byte) 115, (byte) 97,
			(byte) 101, (byte) 114, (byte) 116, (byte) 48, (byte) 92, (byte) 48, (byte) 13, (byte) 6, (byte) 9,
			(byte) 42, (byte) -122, (byte) 72, (byte) -122, (byte) -9, (byte) 13, (byte) 1, (byte) 1, (byte) 1,
			(byte) 5, (byte) 0, (byte) 3, (byte) 75, (byte) 0, (byte) 48, (byte) 72, (byte) 2, (byte) 65, (byte) 0,
			(byte) -73, (byte) -43, (byte) 96, (byte) -107, (byte) 82, (byte) 25, (byte) -66, (byte) 34, (byte) 5,
			(byte) -58, (byte) 75, (byte) -39, (byte) -54, (byte) 43, (byte) 25, (byte) -117, (byte) 80, (byte) -62,
			(byte) 51, (byte) 19, (byte) 59, (byte) -70, (byte) -100, (byte) 85, (byte) 24, (byte) -57, (byte) 108,
			(byte) -98, (byte) -2, (byte) 1, (byte) -80, (byte) -39, (byte) 63, (byte) 93, (byte) 112, (byte) 7,
			(byte) 4, (byte) 18, (byte) -11, (byte) -98, (byte) 17, (byte) 126, (byte) -54, (byte) 27, (byte) -56,
			(byte) 33, (byte) 77, (byte) -111, (byte) -74, (byte) -78, (byte) 88, (byte) 70, (byte) -22, (byte) -3,
			(byte) 15, (byte) 16, (byte) 37, (byte) -18, (byte) 92, (byte) 74, (byte) 124, (byte) -107, (byte) -116,
			(byte) -125, (byte) 2, (byte) 3, (byte) 1, (byte) 0, (byte) 1, (byte) 48, (byte) 13, (byte) 6, (byte) 9,
			(byte) 42, (byte) -122, (byte) 72, (byte) -122, (byte) -9, (byte) 13, (byte) 1, (byte) 1, (byte) 5,
			(byte) 5, (byte) 0, (byte) 3, (byte) 65, (byte) 0, (byte) 33, (byte) 97, (byte) 121, (byte) -25, (byte) 43,
			(byte) -47, (byte) 113, (byte) -104, (byte) -11, (byte) -42, (byte) -46, (byte) -17, (byte) 1, (byte) -38,
			(byte) 50, (byte) 59, (byte) -63, (byte) -74, (byte) -33, (byte) 90, (byte) 92, (byte) -59, (byte) 99,
			(byte) -17, (byte) -60, (byte) 17, (byte) 25, (byte) 79, (byte) 68, (byte) 68, (byte) -57, (byte) -8,
			(byte) -64, (byte) 35, (byte) -19, (byte) -114, (byte) 110, (byte) -116, (byte) 31, (byte) -126, (byte) -24,
			(byte) 54, (byte) 71, (byte) 82, (byte) -53, (byte) -78, (byte) -84, (byte) -45, (byte) -83, (byte) 87,
			(byte) 68, (byte) 124, (byte) -1, (byte) -128, (byte) -49, (byte) 124, (byte) 103, (byte) 28, (byte) 56,
			(byte) -114, (byte) -10, (byte) 97, (byte) -78, (byte) 54 };

	private byte[] commonCertificate = new byte[] { (byte) 1, (byte) 0, (byte) 1, (byte) 0, (byte) -119, (byte) 13,
			(byte) -113, (byte) 13, (byte) 45, (byte) -34, (byte) 81, (byte) -34, (byte) -85, (byte) -49, (byte) 111,
			(byte) -55, (byte) 72, (byte) 80, (byte) 45, (byte) 109, (byte) 23, (byte) -34, (byte) 86, (byte) 87,
			(byte) 119, (byte) -116, (byte) -109, (byte) 30, (byte) -91, (byte) 59, (byte) 24, (byte) 59, (byte) -82,
			(byte) 103, (byte) -125, (byte) -70, (byte) -46, (byte) 3, (byte) 116, (byte) 103, (byte) -63, (byte) -36,
			(byte) -94, (byte) 59, (byte) -5, (byte) 32, (byte) -68, (byte) -3, (byte) -29, (byte) -80, (byte) -41,
			(byte) -106, (byte) -23, (byte) -40, (byte) -23, (byte) 35, (byte) -18, (byte) -121, (byte) -72, (byte) -53,
			(byte) 31, (byte) 59, (byte) -50, (byte) 89, (byte) 127, (byte) -46, (byte) -109, (byte) -91, (byte) 101,
			(byte) 16, (byte) -13, (byte) 41, (byte) 82, (byte) 35, (byte) -59, (byte) 101, (byte) -89, (byte) 66,
			(byte) 3, (byte) -59, (byte) -45, (byte) 32, (byte) -118, (byte) -76, (byte) -103, (byte) 21, (byte) 69,
			(byte) -97, (byte) -102, (byte) -58, (byte) -82, (byte) 112, (byte) -113, (byte) 120, (byte) 69,
			(byte) -101, (byte) -119, (byte) 98, (byte) -41, (byte) -126, (byte) -103, (byte) 25, (byte) -109,
			(byte) -63, (byte) -108, (byte) 34, (byte) 61, (byte) 39, (byte) 56, (byte) 76, (byte) 127, (byte) -90,
			(byte) 29, (byte) -95, (byte) -40, (byte) 7, (byte) 96, (byte) -20, (byte) -35, (byte) 65, (byte) 119,
			(byte) 49, (byte) 91, (byte) 99, (byte) 98, (byte) 66, (byte) -25, (byte) -15, (byte) 41, (byte) -14,
			(byte) -62, (byte) 5, (byte) 108, (byte) -110, (byte) 37, (byte) -95 };
	private byte[] privExp_ComCer = new byte[] { (byte) 81, (byte) -47, (byte) -61, (byte) 102, (byte) 21, (byte) -51,
			(byte) 20, (byte) -55, (byte) 63, (byte) 126, (byte) -34, (byte) 120, (byte) -90, (byte) -16, (byte) 30,
			(byte) -66, (byte) 115, (byte) 50, (byte) 108, (byte) 15, (byte) 89, (byte) -78, (byte) -107, (byte) -98,
			(byte) 4, (byte) -4, (byte) -117, (byte) -110, (byte) 13, (byte) -93, (byte) -124, (byte) -77, (byte) 34,
			(byte) -59, (byte) 37, (byte) 45, (byte) 62, (byte) -81, (byte) 31, (byte) 98, (byte) -118, (byte) -7,
			(byte) -114, (byte) -20, (byte) -66, (byte) 93, (byte) -32, (byte) 101, (byte) -27, (byte) -4, (byte) 86,
			(byte) -29, (byte) -79, (byte) 24, (byte) 38, (byte) -21, (byte) -104, (byte) -10, (byte) -18, (byte) -5,
			(byte) 84, (byte) 77, (byte) -2, (byte) 125 };
	private byte[] privMod_ComCer = new byte[] { (byte) -119, (byte) 13, (byte) -113, (byte) 13, (byte) 45, (byte) -34,
			(byte) 81, (byte) -34, (byte) -85, (byte) -49, (byte) 111, (byte) -55, (byte) 72, (byte) 80, (byte) 45,
			(byte) 109, (byte) 23, (byte) -34, (byte) 86, (byte) 87, (byte) 119, (byte) -116, (byte) -109, (byte) 30,
			(byte) -91, (byte) 59, (byte) 24, (byte) 59, (byte) -82, (byte) 103, (byte) -125, (byte) -70, (byte) -46,
			(byte) 3, (byte) 116, (byte) 103, (byte) -63, (byte) -36, (byte) -94, (byte) 59, (byte) -5, (byte) 32,
			(byte) -68, (byte) -3, (byte) -29, (byte) -80, (byte) -41, (byte) -106, (byte) -23, (byte) -40, (byte) -23,
			(byte) 35, (byte) -18, (byte) -121, (byte) -72, (byte) -53, (byte) 31, (byte) 59, (byte) -50, (byte) 89,
			(byte) 127, (byte) -46, (byte) -109, (byte) -91 };
	
	private byte[] signatureCertificate = new byte[] { (byte) 1, (byte) 0, (byte) 1, (byte) 0, (byte) -119, (byte) 13,
			(byte) -113, (byte) 13, (byte) 45, (byte) -34, (byte) 81, (byte) -34, (byte) -85, (byte) -49, (byte) 111,
			(byte) -55, (byte) 72, (byte) 80, (byte) 45, (byte) 109, (byte) 23, (byte) -34, (byte) 86, (byte) 87,
			(byte) 119, (byte) -116, (byte) -109, (byte) 30, (byte) -91, (byte) 59, (byte) 24, (byte) 59, (byte) -82,
			(byte) 103, (byte) -125, (byte) -70, (byte) -46, (byte) 3, (byte) 116, (byte) 103, (byte) -63, (byte) -36,
			(byte) -94, (byte) 59, (byte) -5, (byte) 32, (byte) -68, (byte) -3, (byte) -29, (byte) -80, (byte) -41,
			(byte) -106, (byte) -23, (byte) -40, (byte) -23, (byte) 35, (byte) -18, (byte) -121, (byte) -72, (byte) -53,
			(byte) 31, (byte) 59, (byte) -50, (byte) 89, (byte) 127, (byte) -46, (byte) -109, (byte) -91, (byte) 101,
			(byte) 16, (byte) -13, (byte) 41, (byte) 82, (byte) 35, (byte) -59, (byte) 101, (byte) -89, (byte) 66,
			(byte) 3, (byte) -59, (byte) -45, (byte) 32, (byte) -118, (byte) -76, (byte) -103, (byte) 21, (byte) 69,
			(byte) -97, (byte) -102, (byte) -58, (byte) -82, (byte) 112, (byte) -113, (byte) 120, (byte) 69,
			(byte) -101, (byte) -119, (byte) 98, (byte) -41, (byte) -126, (byte) -103, (byte) 25, (byte) -109,
			(byte) -63, (byte) -108, (byte) 34, (byte) 61, (byte) 39, (byte) 56, (byte) 76, (byte) 127, (byte) -90,
			(byte) 29, (byte) -95, (byte) -40, (byte) 7, (byte) 96, (byte) -20, (byte) -35, (byte) 65, (byte) 119,
			(byte) 49, (byte) 91, (byte) 99, (byte) 98, (byte) 66, (byte) -25, (byte) -15, (byte) 41, (byte) -14,
			(byte) -62, (byte) 5, (byte) 108, (byte) -110, (byte) 37, (byte) -95 };
	private byte[] privExp_signatureCertificate = new byte[] { (byte) 81, (byte) -47, (byte) -61, (byte) 102, (byte) 21, (byte) -51,
			(byte) 20, (byte) -55, (byte) 63, (byte) 126, (byte) -34, (byte) 120, (byte) -90, (byte) -16, (byte) 30,
			(byte) -66, (byte) 115, (byte) 50, (byte) 108, (byte) 15, (byte) 89, (byte) -78, (byte) -107, (byte) -98,
			(byte) 4, (byte) -4, (byte) -117, (byte) -110, (byte) 13, (byte) -93, (byte) -124, (byte) -77, (byte) 34,
			(byte) -59, (byte) 37, (byte) 45, (byte) 62, (byte) -81, (byte) 31, (byte) 98, (byte) -118, (byte) -7,
			(byte) -114, (byte) -20, (byte) -66, (byte) 93, (byte) -32, (byte) 101, (byte) -27, (byte) -4, (byte) 86,
			(byte) -29, (byte) -79, (byte) 24, (byte) 38, (byte) -21, (byte) -104, (byte) -10, (byte) -18, (byte) -5,
			(byte) 84, (byte) 77, (byte) -2, (byte) 125 };
	private byte[] privMod_signatureCertificate = new byte[] { (byte) -119, (byte) 13, (byte) -113, (byte) 13, (byte) 45, (byte) -34,
			(byte) 81, (byte) -34, (byte) -85, (byte) -49, (byte) 111, (byte) -55, (byte) 72, (byte) 80, (byte) 45,
			(byte) 109, (byte) 23, (byte) -34, (byte) 86, (byte) 87, (byte) 119, (byte) -116, (byte) -109, (byte) 30,
			(byte) -91, (byte) 59, (byte) 24, (byte) 59, (byte) -82, (byte) 103, (byte) -125, (byte) -70, (byte) -46,
			(byte) 3, (byte) 116, (byte) 103, (byte) -63, (byte) -36, (byte) -94, (byte) 59, (byte) -5, (byte) 32,
			(byte) -68, (byte) -3, (byte) -29, (byte) -80, (byte) -41, (byte) -106, (byte) -23, (byte) -40, (byte) -23,
			(byte) 35, (byte) -18, (byte) -121, (byte) -72, (byte) -53, (byte) 31, (byte) 59, (byte) -50, (byte) 89,
			(byte) 127, (byte) -46, (byte) -109, (byte) -91 };

	private byte[] att_name = new byte[] { (byte) 0x41, (byte) 0x78, (byte) 0x65, (byte) 0x6C, (byte) 0x20, (byte) 0x56,
			(byte) 0x75, (byte) 0x6C, (byte) 0x73, (byte) 0x74, (byte) 0x65, (byte) 0x6B, (byte) 0x65 };
	private byte[] att_address = new byte[] { (byte) 0x48, (byte) 0x6F, (byte) 0x73, (byte) 0x70, (byte) 0x69,
			(byte) 0x74, (byte) 0x61, (byte) 0x61, (byte) 0x6C, (byte) 0x73, (byte) 0x74, (byte) 0x72, (byte) 0x61,
			(byte) 0x61, (byte) 0x74, (byte) 0x20, (byte) 0x31, (byte) 0x33, (byte) 0x20, (byte) 0x38, (byte) 0x36,
			(byte) 0x31, (byte) 0x30, (byte) 0x20, (byte) 0x4B, (byte) 0x6F, (byte) 0x72, (byte) 0x74, (byte) 0x65,
			(byte) 0x6D, (byte) 0x61, (byte) 0x72, (byte) 0x6B };
	private byte[] att_country = new byte[] { (byte) 0x42, (byte) 0x65, (byte) 0x6c, (byte) 0x67, (byte) 0x69,
			(byte) 0x75, (byte) 0x6d };
	private byte[] att_birthDate = new byte[] { (byte) 0x32, (byte) 0x31, (byte) 0x2F, (byte) 0x30, (byte) 0x32,
			(byte) 0x2F, (byte) 0x31, (byte) 0x39, (byte) 0x39, (byte) 0x36 };
	private byte[] att_age = new byte[] { (byte) 0x32, (byte) 0x32 };
	private byte[] att_gender = new byte[] { (byte) 0x6d, (byte) 0x61, (byte) 0x6c, (byte) 0x65 };
	private byte[] sorryMessage = new byte[] { (byte) 0x53, (byte) 0x6F, (byte) 0x72, (byte) 0x72, (byte) 0x79,
			(byte) 0x20, (byte) 0x79, (byte) 0x6F, (byte) 0x75, (byte) 0x20, (byte) 0x64, (byte) 0x6F, (byte) 0x20,
			(byte) 0x6E, (byte) 0x6F, (byte) 0x74, (byte) 0x20, (byte) 0x68, (byte) 0x61, (byte) 0x76, (byte) 0x65,
			(byte) 0x20, (byte) 0x74, (byte) 0x68, (byte) 0x65, (byte) 0x20, (byte) 0x6E, (byte) 0x65, (byte) 0x65,
			(byte) 0x64, (byte) 0x65, (byte) 0x64, (byte) 0x20, (byte) 0x72, (byte) 0x69, (byte) 0x67, (byte) 0x68,
			(byte) 0x74, (byte) 0x73, (byte) 0x20, (byte) 0x66, (byte) 0x6F, (byte) 0x72, (byte) 0x20, (byte) 0x74,
			(byte) 0x68, (byte) 0x69, (byte) 0x73, (byte) 0x20, (byte) 0x64, (byte) 0x61, (byte) 0x74, (byte) 0x61,
			(byte) 0x21 };
	private byte[] notAuthenticate = new byte[] { (byte) 0x53, (byte) 0x6F, (byte) 0x72, (byte) 0x72, (byte) 0x79, (byte) 0x20, (byte) 0x74, (byte) 0x68, (byte) 0x65, (byte) 0x20, (byte) 0x73, (byte) 0x65, (byte) 0x72, (byte) 0x76, (byte) 0x69, (byte) 0x63, (byte) 0x65, (byte) 0x20, (byte) 0x70, (byte) 0x72, (byte) 0x6F, (byte) 0x76, (byte) 0x69, (byte) 0x64, (byte) 0x65, (byte) 0x72, (byte) 0x20, (byte) 0x77, (byte) 0x61, (byte) 0x73, (byte) 0x20, (byte) 0x6E, (byte) 0x6F, (byte) 0x74, (byte) 0x20, (byte) 0x61, (byte) 0x75, (byte) 0x74, (byte) 0x68, (byte) 0x65, (byte) 0x6E, (byte) 0x74, (byte) 0x69, (byte) 0x63, (byte) 0x61, (byte) 0x74, (byte) 0x65, (byte) 0x64, (byte) 0x21};
	
	private byte[] dataIdentificationSignedRRN = new byte[] {(byte) 0x78, (byte) 0x1F, (byte) 0x5E, (byte) 0xF9, (byte) 0x90, (byte) 0xBC, (byte) 0x41, (byte) 0x69, (byte) 0x81, (byte) 0x28, (byte) 0x43, (byte) 0x8C, (byte) 0xDE, (byte) 0x34, (byte) 0x37, (byte) 0x21, (byte) 0x2F, (byte) 0x77, (byte) 0x3C, (byte) 0xBD, (byte) 0x86, (byte) 0x0E, (byte) 0x5D, (byte) 0x57, (byte) 0xF1, (byte) 0x86, (byte) 0xC3, (byte) 0xEA, (byte) 0x8D, (byte) 0x6E, (byte) 0x86, (byte) 0x8A, (byte) 0xB7, (byte) 0x65, (byte) 0x3D, (byte) 0x00, (byte) 0x49, (byte) 0xE2, (byte) 0xB6, (byte) 0x58, (byte) 0x95, (byte) 0x1C, (byte) 0xCC, (byte) 0x61, (byte) 0x6B, (byte) 0xF7, (byte) 0x77, (byte) 0x97, (byte) 0xC3, (byte) 0x6F, (byte) 0x46, (byte) 0xF9, (byte) 0x6C, (byte) 0x5D, (byte) 0x33, (byte) 0x53, (byte) 0xC4, (byte) 0xE3, (byte) 0x8E, (byte) 0xCD, (byte) 0xA6, (byte) 0xF5, (byte) 0x7B, (byte) 0xF5};

	private byte[] dataIdentification = new byte[] { (byte) 0x41, (byte) 0x78, (byte) 0x65, (byte) 0x6C, (byte) 0x20, (byte) 0x56,
			(byte) 0x75, (byte) 0x6C, (byte) 0x73, (byte) 0x74, (byte) 0x65, (byte) 0x6B, (byte) 0x65, (byte) 0xa, 
			(byte) 0x48, (byte) 0x6F, (byte) 0x73, (byte) 0x70, (byte) 0x69, (byte) 0x74, (byte) 0x61, (byte) 0x61, (byte) 0x6C, (byte) 0x73, (byte) 0x74, (byte) 0x72, (byte) 0x61,
			(byte) 0x61, (byte) 0x74, (byte) 0x20, (byte) 0x31, (byte) 0x33, (byte) 0x20, (byte) 0x38, (byte) 0x36,
			(byte) 0x31, (byte) 0x30, (byte) 0x20, (byte) 0x4B, (byte) 0x6F, (byte) 0x72, (byte) 0x74, (byte) 0x65,
			(byte) 0x6D, (byte) 0x61, (byte) 0x72, (byte) 0x6B, (byte) 0xa,
			(byte) 0x32, (byte) 0x31, (byte) 0x2F, (byte) 0x30, (byte) 0x32,
			(byte) 0x2F, (byte) 0x31, (byte) 0x39, (byte) 0x39, (byte) 0x36, (byte) 0xa,
			(byte) 0x32, (byte) 0x32, (byte) 0xa,
			(byte) 0x6d, (byte) 0x61, (byte) 0x6c, (byte) 0x65};
	
	byte[] K_u = new byte[] { (byte) 1, (byte) 2, (byte) 3 }; // id of the card
	private InitializedMessageDigest sha1;
	private byte[] serial = new byte[] { (byte) 0x4A, (byte) 0x61, (byte) 0x6e };
	private byte[] name = new byte[] { (byte) 0x4A, (byte) 0x61, (byte) 0x6E, (byte) 0x20, (byte) 0x56, (byte) 0x6F,
			(byte) 0x73, (byte) 0x73, (byte) 0x61, (byte) 0x65, (byte) 0x72, (byte) 0x74 };
	private OwnerPIN pin;
	private short offset = (short) 0;
	private short keySizeInBytes = 64;
	private short keySizeInBits = (short) 512;
	private RSAPrivateKey privKey = null;
	private AESKey symKey;
	private boolean auth = false;
	private byte[] synomym;
	private final static short MAX_APDU = (short) 240;
	private short BUF_IN_OFFSET[];
	private byte date[];
	private byte[] rnd; // used to create session key while authenticating SP
	private byte[] challenge; // used to verify SP
	private short maxRights;

	private IdentityCard() {
		System.out.println("setup");
		// max try 3 times
		pin = new OwnerPIN(PIN_TRY_LIMIT, PIN_SIZE);
		// pin is 1234
		byte[] pinBytes = new byte[] { 0x32, 0x32, 0x32, 0x32};
		pin.update(pinBytes, (short) 0, PIN_SIZE);
		// needed for the signature of a random byte array
		privKey = (RSAPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE, keySizeInBits, false);
		privKey.setExponent(privExponent, offset, keySizeInBytes);
		privKey.setModulus(privModulus, offset, keySizeInBytes);

		date = new byte[(short) 8];
		register();
		BUF_IN_OFFSET = JCSystem.makeTransientShortArray((short) 1, JCSystem.CLEAR_ON_DESELECT);
		sha1 = MessageDigest.getInitializedMessageDigestInstance(MessageDigest.ALG_SHA, false);
	}

	/*
	 * This method is called by the JCRE when installing the applet on the card.
	 */
	public static void install(byte bArray[], short bOffset, byte bLength) throws ISOException {
		new IdentityCard();
	}

	/*
	 * If no tries are remaining, the applet refuses selection. The card can,
	 * therefore, no longer be used for identification.
	 */
	public boolean select() {
		if (pin.getTriesRemaining() == (short) 0)
			return false;
		return true;
	}

	/**
	 * This method is called when the applet is selected and an APDU arrives.
	 * 
	 * @param apdu
	 * @return void
	 */
	public void process(APDU apdu) throws ISOException {
		// A reference to the buffer, where the APDU data is stored, is retrieved.
		byte[] buffer = apdu.getBuffer();

		// If the APDU selects the applet, no further processing is required.
		if (this.selectingApplet())
			return;

		// Check whether the indicated class of instructions is compatible with this
		// applet.
		if (buffer[ISO7816.OFFSET_CLA] != IDENTITY_CARD_CLA)
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		// A switch statement is used to select a method depending on the instruction
		switch (buffer[ISO7816.OFFSET_INS]) {
		case IDENTIFICATION:
			identification(apdu);
			break;
		case VALIDATE_PIN_INS:
			validatePIN(apdu);
			break;
		case UPDATE_TIME:
			updateTime(apdu);
			break;
		case AUTHENTICATE_SP:
			authenticateServiceProvider(apdu);
			break;
		case VERIFY_CHALLENGE:
			verifyChallenge(apdu);
			break;
		case AUTHENTICATE_CARD:
			authenticateCard(apdu);
			break;
		case RELEASE_ATTRIBUTE:
			releaseAttribute(apdu);
			break;
		case AUTH_TO_SP:
			authenticateToSP(apdu);
			break;
		case SIGN_HASH:
			signHash(apdu);
			break;
		default:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}
	
	private void identification(APDU apdu) {
		byte[] toSend = new byte [dataIdentification.length + dataIdentificationSignedRRN.length];
		Util.arrayCopy(dataIdentification, (short) 0, toSend, (short) 0, (short) dataIdentification.length);
		Util.arrayCopy(dataIdentificationSignedRRN, (short) 0, toSend, (short) dataIdentification.length, (short) dataIdentificationSignedRRN.length);
		sendBigFile(apdu, toSend);
	}

	/**
	 * Method releases the asked attributes if the SP has the rights
	 * 
	 * @param apdu
	 * @return byte[]
	 */
	private void releaseAttribute(APDU apdu) {
		if (!pin.isValidated())
			ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
		if(!auth) {
			Cipher symCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
			symCipher.init(this.symKey, Cipher.MODE_ENCRYPT);
			sorryMessage = padding(notAuthenticate);
			byte[] encryptedData = new byte[(short) sorryMessage.length];

			try {
				symCipher.doFinal(sorryMessage, (short) 0, (short) sorryMessage.length, encryptedData, (short) 0);
			} catch (Exception e) {
				ISOException.throwIt(ERROR_UNKNOW);
			}
			// System.out.println("The data is succesfully encrypted");
			// send everything back can be big!
			if (sendBigFile(apdu, encryptedData)) {
				System.out.println("The sorry message is send to the SP");
			}
		}
		else {
			byte [] buffer = apdu.getBuffer();
			short query = (short) buffer[4];
			System.out.println("SP with rights: " + maxRights + " asks for data type: " + query);
			if (query <= maxRights) {
				// get the synomym for the SP
				// 19 = 16 + 3
				synomym = new byte[19];
				byte[] synomymHashed = new byte[20]; // sha1 gives ouput of 20 btyes
				Util.arrayCopy(K_u, (short) 0, synomym, (short) 0, (short) K_u.length);
				Util.arrayCopy(nameBytesCopy16, (short) (0), synomym, (short) K_u.length, (short) 16);
				InitializedMessageDigest hash = sha1;
				hash.reset();
				// hash.update(synomym, (short) 0, (short) (K_u.length +
				// nameBytesCopy16.length));
				hash.doFinal(synomym, (short) 0, (short) synomym.length, synomymHashed, (short) 0);

				// get the asked data
				byte[] queryResults = solveQuery(query);

				// set everything togheter in one big byte array and send it back
				byte[] enter = new byte[] { (byte) 0xa };
				byte[] sendBack = new byte[(short) (queryResults.length + synomymHashed.length + 1)];
				Util.arrayCopy(synomymHashed, (short) 0, sendBack, (short) 0, (short) synomymHashed.length);
				Util.arrayCopy(enter, (short) 0, sendBack, (short) synomymHashed.length, (short) 1);
				Util.arrayCopy(queryResults, (short) 0, sendBack, (short) (synomymHashed.length + 1),
						(short) queryResults.length);

				// encrypt data with symmetric key
				Cipher symCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
				symCipher.init(this.symKey, Cipher.MODE_ENCRYPT);
				// sendBack = new byte[16];
				sendBack = padding(sendBack);
				byte[] encryptedData = new byte[(short) sendBack.length];

				try {
					symCipher.doFinal(sendBack, (short) 0, (short) sendBack.length, encryptedData, (short) 0);
				} catch (Exception e) {
					ISOException.throwIt(ERROR_UNKNOW);
				}
				// System.out.println("The data is succesfully encrypted");
				// send everything back can be big!
				if (sendBigFile(apdu, encryptedData)) {
					System.out.println("The data is succesfully transferred!");
				}
			}else {
				Cipher symCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
				symCipher.init(this.symKey, Cipher.MODE_ENCRYPT);
				sorryMessage = padding(sorryMessage);
				byte[] encryptedData = new byte[(short) sorryMessage.length];

				try {
					symCipher.doFinal(sorryMessage, (short) 0, (short) sorryMessage.length, encryptedData, (short) 0);
				} catch (Exception e) {
					ISOException.throwIt(ERROR_UNKNOW);
				}
				// System.out.println("The data is succesfully encrypted");
				// send everything back can be big!
				if (sendBigFile(apdu, encryptedData)) {
					System.out.println("The sorry message is send to the SP");
				}
			}
		}
		// }

	}

	private byte[] padding(byte[] data) {
		if (data.length % 16 != 0) {
			short length = (short) (data.length + 16 - data.length % 16);
			byte[] paddedData = new byte[length];
			Util.arrayCopy(data, (short) 0, paddedData, (short) 0, (short) data.length);
			return paddedData;
		}
		return data;
	}
	
	/***
	 * sign the hash received from MW
	 * TODO!!! hier gebruik ik opnieuw commoncert omdak nie weet hoe ik nieuwe cert/keypairs moet aanmaken
	 * maar int echt is er een apart cert voor auth en voor signen, dus da moeten we sws nog in orde brengen
	 */
	private void signHash(APDU apdu) {
		try {
			//sign de hash en stuur terug naar de MW
			byte[] hashToSign = receiveBigData(apdu);
			//prepare signature
			Signature signature = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);
			RSAPrivateKey privateKey = (RSAPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE, (short) 512, false);
			privateKey.setExponent(privExp_signatureCertificate, offset, (short) privExp_signatureCertificate.length);
		    privateKey.setModulus(privMod_signatureCertificate, offset, (short) privMod_signatureCertificate.length);
			signature.init(privateKey, Signature.MODE_SIGN);
			
			//sign hash
			byte[] outputBuffer = new byte[100];
			short signatureLength = signature.sign(hashToSign, (short) 0, (short) hashToSign.length, outputBuffer,(short) 0);
			byte [] signedHash = new byte[signatureLength];
			Util.arrayCopy(outputBuffer, (short) 0, signedHash, (short) 0, signatureLength);
			
			//message samenstellen om terug te sturen naar MW, bestaande uit certificaat en getekende hash
			byte[] message = new byte[signatureCertificate.length + signedHash.length];
			Util.arrayCopy(signatureCertificate, (short) 0, message, (short) 0, (short) signatureCertificate.length);
			Util.arrayCopy(signedHash, (short) 0, message, (short) signatureCertificate.length, (short) signedHash.length);
			
			sendBigFile(apdu, message);			
		}
		catch(Exception e) {
			ISOException.throwIt(ENCRYPT_ERROR);
		}
	}
	
	/**
	 * authentication to SP
	 * generate response to the challenge the SP sent 
	 */
	private void authenticateToSP(APDU apdu) {
		
		try {
			byte[] challenge = receiveBigData(apdu);
			byte[] response = new byte[16];
			
			byte[] authBytes = "AUTH".getBytes();
			byte[] bytesToSign = new byte[response.length + authBytes.length];
			
			Util.arrayCopy(response, (short) 0, bytesToSign, (short) 0, (short) response.length);
			Util.arrayCopy(authBytes, (short) 0, bytesToSign, (short) 15, (short) authBytes.length);
			
			// prepare signature
			// nu gwn efkes voort gemak keypairs gebruiken van common cert van vorig project
			// keypair van common cert is dus hier voor auth van citizen
			// TODO renamen naar andere naam zodat duidelijk dat dit gebruikt wordt voor auth
			Signature signature = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);
			RSAPrivateKey privk = (RSAPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE, (short) 512, false);
			privk.setExponent(privExp_ComCer, offset, (short) privExp_ComCer.length);
		    privk.setModulus(privMod_ComCer, offset, (short) privMod_ComCer.length);
			signature.init(privk, Signature.MODE_SIGN);
			
			//sign response
			byte[] outputBuffer = new byte[100];
			short sigLength = signature.sign(bytesToSign, (short) 0, (short) bytesToSign.length, outputBuffer,(short) 0);
			byte[] sig = new byte[sigLength];
			Util.arrayCopy(outputBuffer, (short) 0, sig, (short) 0, sigLength);

			byte[] message = new byte[commonCertificate.length + bytesToSign.length + sig.length + 4]; //waarom plus 4??
			
			Util.arrayCopy(commonCertificate, (short) 0, message, (short) 0, (short) commonCertificate.length);
			Util.arrayCopy(bytesToSign, (short) 0, message, (short) commonCertificate.length, (short) bytesToSign.length);
			Util.arrayCopy(sig, (short) 0, message, (short) (commonCertificate.length + bytesToSign.length), (short) sig.length);
			
			sendBigFile(apdu, message);
			
			
		} catch (Exception e) {
			ISOException.throwIt(ENCRYPT_ERROR);
		}
	}
	
	
	/**
	 * This method authenticates the card for the service provider.
	 * 
	 * @param apdu
	 * @return void
	 */
	private void authenticateCard(APDU apdu) {
		// check if SP is already authenticated
		if (!auth) {
			System.out.println("Serviceprovider not yet authenticated");
			return;
		}
		try {

			// decrypt
			byte[] data = receiveBigData(apdu);
			byte[] responseChallengeBytes = new byte[16];
			Cipher aesCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
			aesCipher.init(symKey, Cipher.MODE_DECRYPT);
			aesCipher.doFinal(data, (short) 0, (short) data.length, responseChallengeBytes, (short) 0);

			byte[] authBytes = "AUTH".getBytes();
			byte[] bytesToSign = new byte[responseChallengeBytes.length + authBytes.length];
			Util.arrayCopy(responseChallengeBytes, (short) 0, bytesToSign, (short) 0,
					(short) responseChallengeBytes.length);
			Util.arrayCopy(authBytes, (short) 0, bytesToSign, (short) 15, (short) authBytes.length);

			// prepare signature
			Signature signature = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);
			RSAPrivateKey privk = (RSAPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE, (short) 512, false);
			privk.setExponent(privExp_ComCer, offset, (short) privExp_ComCer.length);
			privk.setModulus(privMod_ComCer, offset, (short) privMod_ComCer.length);
			signature.init(privk, Signature.MODE_SIGN);

			// sign
			byte[] outputBuffer = new byte[100];
			short sigLength = signature.sign(bytesToSign, (short) 0, (short) bytesToSign.length, outputBuffer,
					(short) 0);
			// System.out.println("Common cer length: " + commonCertificate.length);
			byte[] sig = new byte[sigLength];
			Util.arrayCopy(outputBuffer, (short) 0, sig, (short) 0, sigLength);

			byte[] message = new byte[commonCertificate.length + bytesToSign.length + sig.length + 4];
			Util.arrayCopy(commonCertificate, (short) 0, message, (short) 0, (short) commonCertificate.length);
			Util.arrayCopy(bytesToSign, (short) 0, message, (short) commonCertificate.length,
					(short) bytesToSign.length);
			Util.arrayCopy(sig, (short) 0, message, (short) (commonCertificate.length + bytesToSign.length),
					(short) sig.length);
			byte[] encryptedMessage = new byte[message.length];

			// init symmetric encryption
			Cipher symCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
			symCipher.init(symKey, Cipher.MODE_ENCRYPT);

			try {
				symCipher.doFinal(message, (short) 0, (short) message.length, encryptedMessage, (short) 0);

			} catch (Exception e) {
				ISOException.throwIt(ENCRYPT_ERROR);
			}

			sendBigFile(apdu, encryptedMessage);
		} catch (Exception e) {
			ISOException.throwIt(ENCRYPT_ERROR);
		}

	}

	/**
	 * This method verifies the challenge in the apdu.
	 * 
	 * @param apdu
	 * @return void
	 */
	private void verifyChallenge(APDU apdu) {
		byte[] data = receiveBigData(apdu);
		byte[] responseChallengeBytes = new byte[16];
		Cipher aesCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
		aesCipher.init(symKey, Cipher.MODE_DECRYPT);
		aesCipher.doFinal(data, (short) 0, (short) data.length, responseChallengeBytes, (short) 0);

		// Add one
		this.challenge = addOne_Bad(this.challenge);
		// verify
		if (equals(responseChallengeBytes, this.challenge)) {
			auth = true;
		}
		auth = true;

	}

	/**
	 * This method authenticates the serviceprovider to the card.
	 * 
	 * @param apdu
	 * @return void
	 */
	private void authenticateServiceProvider(APDU apdu) {
		byte[] data = receiveBigData(apdu);
		byte[] signedCertificate = new byte[64];

		byte[] certificateBytes = new byte[(short) (data.length - signedCertificate.length)];
		byte[] validEndTimeCertificate = new byte[(short) 8];
		byte[] pkExpBytesSP = new byte[(short) 3];
		byte[] pkModBytesSP = new byte[(short) 64];
		byte[] nameBytes = new byte[(short) (certificateBytes.length - pkExpBytesSP.length - pkModBytesSP.length
				- validEndTimeCertificate.length - 3)];
		nameBytesCopy16 = new byte[(short) 16];
		byte[] maxRightByteArray = new byte[2];
		// System.out.println("namebytes length: "+nameBytes.length);

		Util.arrayCopy(data, (short) (0), signedCertificate, (short) 0, (short) 64);
		Util.arrayCopy(data, (short) (64), certificateBytes, (short) 0, (short) (data.length - 64));
		Util.arrayCopy(certificateBytes, (short) (0), pkExpBytesSP, (short) (0), (short) (3));
		Util.arrayCopy(certificateBytes, (short) 4, pkModBytesSP, (short) (0), (short) 64);
		Util.arrayCopy(certificateBytes, (short) 68, validEndTimeCertificate, (short) 0, (short) 8);
		Util.arrayCopy(certificateBytes, (short) 76, maxRightByteArray, (short) 0, (short) 2);
		Util.arrayCopy(certificateBytes, (short) 78, nameBytes, (short) 0, (short) nameBytes.length);
		Util.arrayCopy(nameBytes, (short) 0, nameBytesCopy16, (short) 0, (short) nameBytes.length);
		
		maxRights = maxRightByteArray[0];
		System.out.println("The maxrights of this SP: " + maxRights);
		// end jonas code

		Signature signature = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);
		// this keysize must be the same size as the one given in in setModulus! but
		// another keylenght is not working!! 512 is max
		try {
			RSAPublicKey pubk = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, (short) 512, false);
			pubk.setExponent(pubExp_CA, offset, (short) 3);
			pubk.setModulus(pubMod_CA, offset, (short) pubMod_CA.length);
			signature.init(pubk, Signature.MODE_VERIFY);

			boolean result = signature.verify(certificateBytes, (short) 0, (short) certificateBytes.length,
					signedCertificate, (short) 0, (short) signedCertificate.length);
			// result is true if everything went fine
			// but now just commented for not losing time
			if (!result) {
				// misschien iets opgooien dat zegt dat cert niet geldig is?
				System.out.println("Whoa! the serviceproveder certificate is not correct!");
				ISOException.throwIt(ERROR_AUTHENTICATESP);
			}
			if (isSmaller(validEndTimeCertificate, lastValidationTime)) {
				// throw other exception?
				ISOException.throwIt(ERROR_UNKNOW);
			}
			// if everything okay --> create new symmetric key
			this.symKey = getSymKey();

			// rebuild SP PK
			RSAPublicKey publicKeySP = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, (short) (512),
					false);
			publicKeySP.setExponent(pkExpBytesSP, offset, (short) 3);
			publicKeySP.setModulus(pkModBytesSP, offset, (short) (pkModBytesSP.length));
			// //encrypt rnd to send to SP
			// //met rnd kan SP de symmetrische key heropbouwen
			//
			Cipher asymCipher = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);
			byte[] encryptedRnd = JCSystem.makeTransientByteArray((short) 64, JCSystem.CLEAR_ON_DESELECT);
			asymCipher.init((RSAPublicKey) publicKeySP, Cipher.MODE_ENCRYPT);

			try {
				asymCipher.doFinal(this.rnd, (short) 0, (short) this.rnd.length, encryptedRnd, (short) 0);

			} catch (Exception e) {
				ISOException.throwIt(ERROR_UNKNOW);
			}

			// generate challenge
			byte[] challengeBytes = generateRandomBytes();
			// BigInteger challenge = new BigInteger(1, challengeBytes); //for testing
			this.challenge = challengeBytes;
			// challengebytes symmetrisch encrypteren
			Cipher symCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
			symCipher.init(symKey, Cipher.MODE_ENCRYPT);
			byte[] encryptedChallengeBytes = new byte[(short) 16];
			byte[] encryptedNameBytes = new byte[(short) 16];
			try {
				symCipher.doFinal(challengeBytes, (short) 0, (short) challengeBytes.length, encryptedChallengeBytes,
						(short) 0);
				symCipher.init(symKey, Cipher.MODE_ENCRYPT);
				symCipher.doFinal(nameBytesCopy16, (short) 0, (short) nameBytesCopy16.length, encryptedNameBytes,
						(short) 0);
			} catch (Exception e) {
				// TODO Auto-generated catch block
				ISOException.throwIt(ERROR_UNKNOW);
			}

			// msg opbouwen om terug te zenden
			byte[] toSend = new byte[(short) (encryptedRnd.length + encryptedChallengeBytes.length
					+ encryptedNameBytes.length)];
			Util.arrayCopy(encryptedRnd, (short) 0, toSend, (short) 0, (short) encryptedRnd.length);
			Util.arrayCopy(encryptedChallengeBytes, (short) 0, toSend, (short) encryptedRnd.length,
					(short) encryptedChallengeBytes.length);
			Util.arrayCopy(encryptedNameBytes, (short) 0, toSend, (short) (encryptedRnd.length + challengeBytes.length),
					(short) encryptedNameBytes.length);

			// send msg to SP
			if (sendBigFile(apdu, toSend)) {
				// System.out.println("success send challenge");
			}

		} catch (Exception e) {
			ISOException.throwIt(ERROR_UNKNOW);
		}
	}

	private boolean sendBigFile(APDU apdu, byte[] toSend) {
		short length = (short) toSend.length;
		try {
			apdu.setOutgoing();
			apdu.setOutgoingLength(length);
			short lenToSend = 64; // send all the data in pieces of each 32 bytes
			byte counter = 0;
			while (length > 0) {
				if (length < 64) { // if data to send is not muliple of 32
					lenToSend = length;
				}
				apdu.sendBytesLong(toSend, (short) (64 * counter), lenToSend); // send part of certificate each
																				// time.
				length = (short) (length - 64);
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
			} else if (e instanceof ArrayIndexOutOfBoundsException) {
				ISOException.throwIt(ERROR_OUT_OF_BOUNDS);
			} else {
				ISOException.throwIt(ERROR_UNKNOW);
			}
			return false;
		}
		return true;
	}

	/**
	 * Update the time on the card, received from the timestampserver.
	 * 
	 * @param apdu
	 * @return void
	 */
	private void updateTime(APDU apdu) {
		byte[] data = receiveBigData(apdu);
		byte[] signedData = new byte[64];
		// slice data field into Signature and date
		Util.arrayCopy(data, (short) (data.length - 8), date, (short) 0, (short) 8);
		Util.arrayCopy(data, (short) (0), signedData, (short) 0, (short) 64);

		try {
			Signature signature = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);

			// this keysize must be the same size as the one given in in setModulus! but
			// another keylenght is not working??
			RSAPublicKey pubk = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, (short) 512, false);
			pubk.setExponent(pubExp_G, offset, (short) 3);
			pubk.setModulus(pubMod_G, offset, (short) pubMod_G.length);
			signature.init(pubk, Signature.MODE_VERIFY);
			boolean result = signature.verify(date, (short) 0, (short) date.length, signedData, (short) 0,
					(short) signedData.length);
			if (result) {
				lastValidationTime = date;
			} else {
				ISOException.throwIt(ERROR_UNKNOW);
			}
		} catch (Exception e) {
			ISOException.throwIt(ERROR_WRONG_TIME);
		}
	}

	/**
	 * Validate the given pin.
	 * 
	 * @param apdu
	 * @return void
	 */
	private void validatePIN(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		if (apdu.getIncomingLength() == PIN_SIZE) {
			// This method is used to copy the incoming data in the APDU buffer.
			apdu.setIncomingAndReceive();
			if (pin.check(buffer, apdu.getOffsetCdata(), PIN_SIZE) == false)
				ISOException.throwIt(SW_VERIFICATION_FAILED);
		} else
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

	}

	/**
	 * Method that calculates with byte array (represents an number) is smaller if
	 * array1 < array2 --> true;
	 * 
	 * @param byte[],
	 *            byte[]
	 * @return boolean
	 */
	private boolean isSmaller(byte[] array1, byte[] array2) {
		if (array1.length != array2.length) {
			if (array1.length < array2.length) {
				return true;
			} else {
				return false;
			}
		} else {
			for (short i = 0; i < array1.length; i++) {
				if (array1[i] > array2[i]) {
					return false;
				}
				if (array1[i] < array2[i]) {
					return true;
				}
			}
		}
		// if equals return true
		return true;
	}

	/**
	 * Methode to extract data field from CommandAPDU with data larger than 255
	 * bytes;
	 * 
	 * @param apdu
	 * @return byte[] with extracted data
	 */
	private byte[] receiveBigData(APDU apdu) {
		// Receiving big APDU COMMANDS
		// System.out.println("lengte apdu: " + apdu.getIncomingLength());
		byte[] buffer = new byte[apdu.getIncomingLength()];
		try {

			short dataOffset = 0;
			short bytesLeft = apdu.getIncomingLength();
			short readCount = apdu.setIncomingAndReceive();
			while (bytesLeft > 0) {
				Util.arrayCopy(apdu.getBuffer(), apdu.getOffsetCdata(), buffer, dataOffset, readCount);
				bytesLeft -= readCount;
				dataOffset += readCount;
				readCount = apdu.receiveBytes(apdu.getOffsetCdata()); // reveive next package
			}

		} catch (Exception e) {
			if (e instanceof ArrayIndexOutOfBoundsException) {
				ISOException.throwIt(ERROR_OUT_OF_BOUNDS);
			} else {
				ISOException.throwIt(ERROR_UNKNOW);
			}
		}
		return buffer;
	}

	/**
	 * This method gives for the given query the asked results back when asked.
	 * atribuut, enter, attribuut, enter (ends with enter)
	 * 
	 * @param short
	 * @return byte []
	 */
	private byte[] solveQuery(short query) {
		byte[] result = null;
		byte[] enter = new byte[] { (byte) 0xa };
		short numberOfAttributes = 1;
		switch (query) {
		case ((short) 1):
			// gives default back = age
			numberOfAttributes = 1;
			result = new byte[att_age.length + numberOfAttributes];
			Util.arrayCopy(att_age, (short) 0, result, (short) 0, (short) att_age.length);
			Util.arrayCopy(enter, (short) 0, result, (short) (att_age.length), (short) 1);
			break;
		case ((short) 2):
			// gives the betting type: synonym + age + country + name
			numberOfAttributes = 3;
			result = new byte[att_age.length + att_country.length + att_name.length + numberOfAttributes];
			Util.arrayCopy(att_age, (short) 0, result, (short) (0), (short) att_age.length);
			Util.arrayCopy(enter, (short) 0, result, (short) (att_age.length), (short) 1);
			Util.arrayCopy(att_country, (short) 0, result, (short) (att_age.length + 1), (short) att_country.length);
			Util.arrayCopy(enter, (short) 0, result, (short) (att_age.length + att_country.length + 1), (short) 1);
			Util.arrayCopy(att_name, (short) 0, result, (short) (att_age.length + att_country.length + 2),
					(short) att_name.length);
			Util.arrayCopy(enter, (short) 0, result,
					(short) (att_age.length + att_country.length + att_name.length + 2), (short) 1);
			break;
		case ((short) 3):
			// gives the social networking type: synonym + name + country + age + gender
			numberOfAttributes = 4;
			result = new byte[att_age.length + att_country.length + att_name.length + att_gender.length
					+ numberOfAttributes];
			Util.arrayCopy(att_age, (short) 0, result, (short) (0), (short) att_age.length);
			Util.arrayCopy(enter, (short) 0, result, (short) (att_age.length), (short) 1);
			Util.arrayCopy(att_country, (short) 0, result, (short) (att_age.length + 1), (short) att_country.length);
			Util.arrayCopy(enter, (short) 0, result, (short) (att_age.length + att_country.length + 1), (short) 1);
			Util.arrayCopy(att_name, (short) 0, result, (short) (att_age.length + att_country.length + 2),
					(short) att_name.length);
			Util.arrayCopy(enter, (short) 0, result,
					(short) (att_age.length + att_country.length + att_name.length + 2), (short) 1);
			Util.arrayCopy(att_gender, (short) 0, result,
					(short) (att_age.length + att_country.length + att_name.length + 3), (short) att_gender.length);
			Util.arrayCopy(enter, (short) 0, result,
					(short) (att_age.length + att_country.length + att_name.length + att_gender.length + 3), (short) 1);
			break;
		case ((short) 4):
			// givesall : name + country + age + gender +
			// birth date + address
			numberOfAttributes = 6;
			result = new byte[att_age.length + att_country.length + att_name.length + att_gender.length
					+ att_birthDate.length + att_address.length + numberOfAttributes];
			Util.arrayCopy(att_age, (short) 0, result, (short) (0), (short) att_age.length);
			Util.arrayCopy(enter, (short) 0, result, (short) (att_age.length), (short) 1);
			Util.arrayCopy(att_country, (short) 0, result, (short) (att_age.length + 1), (short) att_country.length);
			Util.arrayCopy(enter, (short) 0, result, (short) (att_age.length + att_country.length + 1), (short) 1);
			Util.arrayCopy(att_name, (short) 0, result, (short) (att_age.length + att_country.length + 2),
					(short) att_name.length);
			Util.arrayCopy(enter, (short) 0, result,
					(short) (att_age.length + att_country.length + att_name.length + 2), (short) 1);
			Util.arrayCopy(att_gender, (short) 0, result,
					(short) (att_age.length + att_country.length + att_name.length + 3), (short) att_gender.length);
			Util.arrayCopy(enter, (short) 0, result,
					(short) (att_age.length + att_country.length + att_name.length + att_gender.length + 3), (short) 1);
			Util.arrayCopy(att_birthDate, (short) 0, result,
					(short) (att_age.length + att_country.length + att_name.length + att_gender.length + 4),
					(short) att_birthDate.length);
			Util.arrayCopy(enter, (short) 0, result, (short) (att_age.length + att_country.length + att_name.length + att_gender.length + att_birthDate.length + 4), (short) 1);
			Util.arrayCopy(att_address, (short) 0, result,
					(short) (att_age.length + att_country.length + att_name.length + att_gender.length + att_birthDate.length + 5),
					(short) att_address.length);
			Util.arrayCopy(enter, (short) 0, result, (short) (att_age.length + att_country.length + att_name.length + att_gender.length + att_birthDate.length + att_address.length + 5), (short) 1);
			break;
		default:
			return null;

		}
		return result;
	}

	/**
	 * This method gives a new random symmetrickey back.
	 * 
	 * @param
	 * @return AESKey
	 */
	private AESKey getSymKey() {
		RandomData randomData = RandomData.getInstance(RandomData.ALG_PSEUDO_RANDOM);
		this.rnd = JCSystem.makeTransientByteArray((short) 16, JCSystem.CLEAR_ON_RESET);
		randomData.generateData(rnd, (short) 0, (short) rnd.length);
		AESKey symKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
		symKey.setKey(rnd, (short) 0);
		return symKey;
	}

	private byte[] generateRandomBytes() {
		RandomData randomData = RandomData.getInstance(RandomData.ALG_PSEUDO_RANDOM);
		this.rnd = JCSystem.makeTransientByteArray((short) 16, JCSystem.CLEAR_ON_RESET);
		randomData.generateData(rnd, (short) 0, (short) rnd.length);
		return rnd;
	}

	public static byte[] addOne_Bad(byte[] A) {
		short lastPosition = (short) (A.length - 1);
		// Looping from right to left
		A[lastPosition] += 1;

		// mogelijk da als alle bytes 0xFF zijn dat er dan niets wordt bij opgeteld
		return A;
	}

	public static boolean equals(byte[] array1, byte[] array2) {
		short length = (short) array1.length;
		short length2 = (short) array2.length;
		if (length != length2) {
			return false;
		}

		for (short i = (short) (length - 1); i >= 0; i = (short) (i - 1)) {
			if (array1[i] != array2[i]) {
				return false;
			}
		}
		return true;
	}

}