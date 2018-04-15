package be.msec.smartcard;

import javacard.framework.APDU;
import javacardx.apdu.ExtendedLength;
import javacardx.crypto.Cipher;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;

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
	private static final byte GET_SERIAL_INS = 0x26;
	private static final byte SIGN_RANDOM_BYTE = 0x27;
	private static final byte GET_CERTIFICATE = 0x28;
	private static final byte GET_BIGDATA = 0x29;
	private static final byte UPDATE_TIME = 0x25;
	private static final byte AUTHENTICATE_SP = 0x21;
	private static final byte VERIFY_CHALLENGE = 0x29;
	private static final byte AUTHENTICATE_CARD = 0x30;
	private static final byte RELEASE_ATTRIBUTE = 0x31;
	private final static byte PIN_TRY_LIMIT = (byte) 0x03;
	private final static byte PIN_SIZE = (byte) 0x04;

	private final static short SW_VERIFICATION_FAILED = 0x6300;
	private final static short SW_PIN_VERIFICATION_REQUIRED = 0x6301;

	private final static short ERROR_OUT_OF_BOUNDS = (short) 0x8001;
	private final static short ERROR_UNKNOW = (short) 0x8888;
	private final static short ERROR_WRONG_TIME = (short) 0x8002;
	private final static short ERROR_WRONG_RIGHTS = (short) 0x8003;
	byte [] nameBytesCopy16;

	
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
	private byte[] pubMod_CA = new byte[] {(byte) -40, (byte) -96, (byte) 115, (byte) 21, (byte) -10, (byte) -66, (byte) 80, (byte) 28, (byte) -124, (byte) 29, (byte) 98, (byte) -23, (byte) -72, (byte) 60, (byte) 89, (byte) 21, (byte) -37, (byte) -122, (byte) -14, (byte) 94, (byte) -92, (byte) 48, (byte) 98, (byte) -35, (byte) 5, (byte) -37, (byte) -50, (byte) -46, (byte) 21, (byte) -117, (byte) -48, (byte) -20, (byte) 50, (byte) -80, (byte) -41, (byte) -126, (byte) -102, (byte) 63, (byte) -2, (byte) -10, (byte) 3, (byte) -86, (byte) -54, (byte) 105, (byte) -64, (byte) 47, (byte) -23, (byte) -104, (byte) -39, (byte) 35, (byte) 107, (byte) -46, (byte) -73, (byte) 2, (byte) 120, (byte) 112, (byte) -127, (byte) -37, (byte) 117, (byte) -79, (byte) 15, (byte) 9, (byte) 48, (byte) -45}; 
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
	// test data
	private byte[] bigdata = new byte[] { (byte) 1, (byte) 2, (byte) 3, (byte) 4, (byte) 5, (byte) 6, (byte) 7,
			(byte) 8, (byte) 9, (byte) 10, (byte) 11, (byte) 12, (byte) 13, (byte) 14, (byte) 15, (byte) 16, (byte) 17,
			(byte) 18, (byte) 19, (byte) 20, (byte) 21, (byte) 22, (byte) 23, (byte) 24, (byte) 25, (byte) 26,
			(byte) 27, (byte) 28, (byte) 29, (byte) 30, (byte) 31, (byte) 32, (byte) 33, (byte) 34, (byte) 35,
			(byte) 36, (byte) 37, (byte) 38, (byte) 39, (byte) 40, (byte) 41, (byte) 42, (byte) 43, (byte) 44,
			(byte) 45, (byte) 46, (byte) 47, (byte) 48, (byte) 49, (byte) 50, (byte) 51, (byte) 52, (byte) 53,
			(byte) 54, (byte) 55, (byte) 56, (byte) 57, (byte) 58, (byte) 59, (byte) 60, (byte) 61, (byte) 62,
			(byte) 63, (byte) 64, (byte) 65, (byte) 66, (byte) 67, (byte) 68, (byte) 69, (byte) 70, (byte) 71,
			(byte) 72, (byte) 73, (byte) 74, (byte) 75, (byte) 76, (byte) 77, (byte) 78, (byte) 79, (byte) 80,
			(byte) 81, (byte) 82, (byte) 83, (byte) 84, (byte) 85, (byte) 86, (byte) 87, (byte) 88, (byte) 89,
			(byte) 90, (byte) 91, (byte) 92, (byte) 93, (byte) 94, (byte) 95, (byte) 96, (byte) 97, (byte) 98,
			(byte) 99, (byte) 100, (byte) 101, (byte) 102, (byte) 103, (byte) 104, (byte) 105, (byte) 106, (byte) 107,
			(byte) 108, (byte) 109, (byte) 110, (byte) 111, (byte) 112, (byte) 113, (byte) 114, (byte) 115, (byte) 116,
			(byte) 117, (byte) 118, (byte) 119, (byte) 120, (byte) 121, (byte) 122, (byte) 123, (byte) 124, (byte) 125,
			(byte) 126, (byte) 127, (byte) 128, (byte) 129, (byte) 130, (byte) 131, (byte) 132, (byte) 133, (byte) 134,
			(byte) 135, (byte) 136, (byte) 137, (byte) 138, (byte) 139, (byte) 140, (byte) 141, (byte) 142, (byte) 143,
			(byte) 144, (byte) 145, (byte) 146, (byte) 147, (byte) 148, (byte) 149, (byte) 150, (byte) 151, (byte) 152,
			(byte) 153, (byte) 154, (byte) 155, (byte) 156, (byte) 157, (byte) 158, (byte) 159, (byte) 160, (byte) 161,
			(byte) 162, (byte) 163, (byte) 164, (byte) 165, (byte) 166, (byte) 167, (byte) 168, (byte) 169, (byte) 170,
			(byte) 171, (byte) 172, (byte) 173, (byte) 174, (byte) 175, (byte) 176, (byte) 177, (byte) 178, (byte) 179,
			(byte) 180, (byte) 181, (byte) 182, (byte) 183, (byte) 184, (byte) 185, (byte) 186, (byte) 187, (byte) 188,
			(byte) 189, (byte) 190, (byte) 191, (byte) 192, (byte) 193, (byte) 194, (byte) 195, (byte) 196, (byte) 197,
			(byte) 198, (byte) 199, (byte) 200, (byte) 201, (byte) 202, (byte) 203, (byte) 204, (byte) 205, (byte) 206,
			(byte) 207, (byte) 208, (byte) 209, (byte) 210, (byte) 211, (byte) 212, (byte) 213, (byte) 214, (byte) 215,
			(byte) 216, (byte) 217, (byte) 218, (byte) 219, (byte) 220, (byte) 221, (byte) 222, (byte) 223, (byte) 224,
			(byte) 225, (byte) 226, (byte) 227, (byte) 228, (byte) 229, (byte) 230, (byte) 231, (byte) 232, (byte) 233,
			(byte) 234, (byte) 235, (byte) 236, (byte) 237, (byte) 238, (byte) 239, (byte) 240, (byte) 241, (byte) 242,
			(byte) 243, (byte) 244, (byte) 245, (byte) 246, (byte) 247, (byte) 248, (byte) 249, (byte) 250, (byte) 251,
			(byte) 252, (byte) 253, (byte) 254, (byte) 255, (byte) 256, (byte) 257, (byte) 258, (byte) 259, (byte) 260,
			(byte) 261, (byte) 262, (byte) 263, (byte) 264, (byte) 265, (byte) 266, (byte) 267, (byte) 268, (byte) 269,
			(byte) 270, (byte) 271, (byte) 272, (byte) 273, (byte) 274, (byte) 275, (byte) 276, (byte) 277, (byte) 278,
			(byte) 279, (byte) 280, (byte) 281, (byte) 282, (byte) 283, (byte) 284, (byte) 285, (byte) 286, (byte) 287,
			(byte) 288, (byte) 289, (byte) 290, (byte) 291, (byte) 292, (byte) 293, (byte) 294, (byte) 295, (byte) 296,
			(byte) 297, (byte) 298, (byte) 299, (byte) 300, (byte) 301, (byte) 302, (byte) 303, (byte) 304, (byte) 305,
			(byte) 306, (byte) 307, (byte) 308, (byte) 309, (byte) 310, (byte) 311, (byte) 312, (byte) 313, (byte) 314,
			(byte) 315, (byte) 316, (byte) 317, (byte) 318, (byte) 319, (byte) 320, (byte) 321, (byte) 322, (byte) 323,
			(byte) 324, (byte) 325, (byte) 326, (byte) 327, (byte) 328, (byte) 329, (byte) 330, (byte) 331, (byte) 332,
			(byte) 333, (byte) 334, (byte) 335, (byte) 336, (byte) 337, (byte) 338, (byte) 339, (byte) 340, (byte) 341,
			(byte) 342, (byte) 343, (byte) 344, (byte) 345, (byte) 346, (byte) 347, (byte) 348, (byte) 349, (byte) 350,
			(byte) 351, (byte) 352, (byte) 353, (byte) 354, (byte) 355, (byte) 356, (byte) 357, (byte) 358, (byte) 359,
			(byte) 360, (byte) 361, (byte) 362, (byte) 363, (byte) 364, (byte) 365, (byte) 366, (byte) 367, (byte) 368,
			(byte) 369, (byte) 370, (byte) 371, (byte) 372, (byte) 373, (byte) 374, (byte) 375, (byte) 376, (byte) 377,
			(byte) 378, (byte) 379, (byte) 380, (byte) 381, (byte) 382, (byte) 383, (byte) 384, (byte) 385, (byte) 386,
			(byte) 387, (byte) 388, (byte) 389, (byte) 390, (byte) 391, (byte) 392, (byte) 393, (byte) 394, (byte) 395,
			(byte) 396, (byte) 397, (byte) 398, (byte) 399, (byte) 400, (byte) 401, (byte) 402, (byte) 403, (byte) 404,
			(byte) 405, (byte) 406, (byte) 407, (byte) 408, (byte) 409, (byte) 410, (byte) 411, (byte) 412, (byte) 413,
			(byte) 414, (byte) 415, (byte) 416, (byte) 417, (byte) 418, (byte) 419, (byte) 420, (byte) 421, (byte) 422,
			(byte) 423, (byte) 424, (byte) 425, (byte) 426, (byte) 427, (byte) 428, (byte) 429, (byte) 430, (byte) 431,
			(byte) 432, (byte) 433, (byte) 434, (byte) 435, (byte) 436, (byte) 437, (byte) 438, (byte) 439, (byte) 440,
			(byte) 441, (byte) 442, (byte) 443, (byte) 444, (byte) 445, (byte) 446, (byte) 447, (byte) 448, (byte) 449,
			(byte) 450, (byte) 451, (byte) 452, (byte) 453, (byte) 454, (byte) 455, (byte) 456, (byte) 457, (byte) 458,
			(byte) 459, (byte) 460, (byte) 461, (byte) 462, (byte) 463, (byte) 464, (byte) 465, (byte) 466, (byte) 467,
			(byte) 468, (byte) 469, (byte) 470, (byte) 471, (byte) 472, (byte) 473, (byte) 474, (byte) 475, (byte) 476,
			(byte) 477, (byte) 478, (byte) 479, (byte) 480, (byte) 481, (byte) 482, (byte) 483, (byte) 484, (byte) 485,
			(byte) 486, (byte) 487, (byte) 488, (byte) 489, (byte) 490, (byte) 491, (byte) 492, (byte) 493, (byte) 494,
			(byte) 495, (byte) 496, (byte) 497, (byte) 498, (byte) 499, (byte) 500 };
	private byte[] smalldata = new byte[] { (byte) 1, (byte) 2, (byte) 3, (byte) 4, (byte) 5, (byte) 6, (byte) 7,
			(byte) 8, (byte) 9, (byte) 10 };
	private byte[] verysmalldata = new byte[] { (byte) 1, (byte) 2 };
	private byte[] PKg = new byte[] { (byte) 48, (byte) -126, (byte) 1, (byte) 34, (byte) 48, (byte) 13, (byte) 6,
			(byte) 9, (byte) 42, (byte) -122, (byte) 72, (byte) -122, (byte) -9, (byte) 13, (byte) 1, (byte) 1,
			(byte) 1, (byte) 5, (byte) 0, (byte) 3, (byte) -126, (byte) 1, (byte) 15, (byte) 0, (byte) 48, (byte) -126,
			(byte) 1, (byte) 10, (byte) 2, (byte) -126, (byte) 1, (byte) 1, (byte) 0, (byte) -102, (byte) 38, (byte) 76,
			(byte) -92, (byte) 68, (byte) 120, (byte) 16, (byte) -121, (byte) 117, (byte) 80, (byte) -121, (byte) 38,
			(byte) -42, (byte) 39, (byte) -71, (byte) 41, (byte) 14, (byte) 45, (byte) 63, (byte) 17, (byte) -30,
			(byte) 20, (byte) -106, (byte) -117, (byte) -15, (byte) 82, (byte) -87, (byte) -117, (byte) -77, (byte) -38,
			(byte) 67, (byte) -25, (byte) -39, (byte) -105, (byte) 46, (byte) -116, (byte) -76, (byte) 125, (byte) -111,
			(byte) 99, (byte) -48, (byte) -45, (byte) 7, (byte) 23, (byte) 102, (byte) -10, (byte) -78, (byte) 119,
			(byte) -69, (byte) 45, (byte) 70, (byte) -92, (byte) -90, (byte) -83, (byte) 116, (byte) 0, (byte) -54,
			(byte) 67, (byte) -46, (byte) -65, (byte) 24, (byte) -118, (byte) -71, (byte) -32, (byte) 120, (byte) 62,
			(byte) 3, (byte) -60, (byte) 96, (byte) -91, (byte) -55, (byte) 116, (byte) -36, (byte) -58, (byte) -120,
			(byte) 76, (byte) 34, (byte) -37, (byte) -75, (byte) -16, (byte) 106, (byte) 61, (byte) -28, (byte) -16,
			(byte) 57, (byte) 59, (byte) 112, (byte) -106, (byte) 12, (byte) 107, (byte) 1, (byte) 123, (byte) -88,
			(byte) -35, (byte) 30, (byte) -114, (byte) 71, (byte) 59, (byte) -112, (byte) 26, (byte) -52, (byte) -33,
			(byte) -116, (byte) -35, (byte) -34, (byte) -111, (byte) -34, (byte) -74, (byte) -92, (byte) -47,
			(byte) 103, (byte) -79, (byte) 19, (byte) -28, (byte) 124, (byte) -66, (byte) 28, (byte) -14, (byte) -98,
			(byte) 104, (byte) -96, (byte) -10, (byte) 60, (byte) 2, (byte) 18, (byte) -4, (byte) 16, (byte) 108,
			(byte) 59, (byte) 26, (byte) -59, (byte) 106, (byte) 0, (byte) 48, (byte) 36, (byte) -12, (byte) -114,
			(byte) 90, (byte) -27, (byte) 122, (byte) 107, (byte) -107, (byte) 17, (byte) -75, (byte) 18, (byte) -52,
			(byte) -29, (byte) -22, (byte) 0, (byte) -32, (byte) -10, (byte) 87, (byte) 116, (byte) 89, (byte) 47,
			(byte) -116, (byte) -127, (byte) 19, (byte) -110, (byte) 53, (byte) 63, (byte) -72, (byte) 101, (byte) 76,
			(byte) -2, (byte) 117, (byte) 64, (byte) 0, (byte) 126, (byte) -2, (byte) 1, (byte) 56, (byte) 90,
			(byte) -25, (byte) -6, (byte) -11, (byte) 44, (byte) 117, (byte) 78, (byte) 73, (byte) -87, (byte) -39,
			(byte) -31, (byte) 100, (byte) -93, (byte) -122, (byte) 19, (byte) -113, (byte) 44, (byte) 83, (byte) -38,
			(byte) -57, (byte) 45, (byte) 75, (byte) 52, (byte) -104, (byte) 69, (byte) -6, (byte) 103, (byte) 104,
			(byte) -100, (byte) -44, (byte) 57, (byte) 79, (byte) -99, (byte) -108, (byte) -68, (byte) -11, (byte) -27,
			(byte) 115, (byte) 15, (byte) -107, (byte) 87, (byte) 6, (byte) 8, (byte) -94, (byte) 76, (byte) 124,
			(byte) 11, (byte) 6, (byte) 35, (byte) -6, (byte) 46, (byte) -115, (byte) 37, (byte) -62, (byte) 5,
			(byte) 70, (byte) 11, (byte) 99, (byte) -51, (byte) -4, (byte) -102, (byte) -51, (byte) 127, (byte) -87,
			(byte) 77, (byte) -112, (byte) 43, (byte) -125, (byte) -1, (byte) 101, (byte) -128, (byte) 8, (byte) -63,
			(byte) 92, (byte) 49, (byte) -78, (byte) -92, (byte) -101, (byte) 35, (byte) -63, (byte) 86, (byte) -36,
			(byte) 126, (byte) -3, (byte) 2, (byte) 3, (byte) 1, (byte) 0, (byte) 1 };
	
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
			(byte) -97, (byte) -102, (byte) -58, (byte) -82, (byte) 112, (byte) -113, (byte) 120, (byte) 69, (byte) -101, 
			(byte) -119, (byte) 98, (byte) -41, (byte) -126, (byte) -103, (byte) 25, (byte) -109, (byte) -63, (byte) -108, 
			(byte) 34, (byte) 61, (byte) 39, (byte) 56, (byte) 76, (byte) 127, (byte) -90, (byte) 29, (byte) -95, (byte) -40, 
			(byte) 7, (byte) 96, (byte) -20, (byte) -35, (byte) 65, (byte) 119, (byte) 49, (byte) 91, (byte) 99, (byte) 98, 
			(byte) 66, (byte) -25, (byte) -15, (byte) 41, (byte) -14, (byte) -62, (byte) 5, (byte) 108, (byte) -110, (byte) 37, (byte) -95 }; 
	private byte[] privExp_ComCer = new byte[] { (byte) 81, (byte) -47, (byte) -61, (byte) 102, (byte) 21, (byte) -51, 
			(byte) 20, (byte) -55, (byte) 63, (byte) 126, (byte) -34, (byte) 120, (byte) -90, (byte) -16, (byte) 30, 
			(byte) -66, (byte) 115, (byte) 50, (byte) 108, (byte) 15, (byte) 89, (byte) -78, (byte) -107, (byte) -98, 
			(byte) 4, (byte) -4, (byte) -117, (byte) -110, (byte) 13, (byte) -93, (byte) -124, (byte) -77, (byte) 34, 
			(byte) -59, (byte) 37, (byte) 45, (byte) 62, (byte) -81, (byte) 31, (byte) 98, (byte) -118, (byte) -7, 
			(byte) -114, (byte) -20, (byte) -66, (byte) 93, (byte) -32, (byte) 101, (byte) -27, (byte) -4, (byte) 86, 
			(byte) -29, (byte) -79, (byte) 24, (byte) 38, (byte) -21, (byte) -104, (byte) -10, (byte) -18, (byte) -5, 
			(byte) 84, (byte) 77, (byte) -2, (byte) 125};
	private byte[] privMod_ComCer =  new byte[] { (byte) -119, (byte) 13, (byte) -113, (byte) 13, (byte) 45, (byte) -34, 
			(byte) 81, (byte) -34, (byte) -85, (byte) -49, (byte) 111, (byte) -55, (byte) 72, (byte) 80, (byte) 45, 
			(byte) 109, (byte) 23, (byte) -34, (byte) 86, (byte) 87, (byte) 119, (byte) -116, (byte) -109, (byte) 30, 
			(byte) -91, (byte) 59, (byte) 24, (byte) 59, (byte) -82, (byte) 103, (byte) -125, (byte) -70, (byte) -46, 
			(byte) 3, (byte) 116, (byte) 103, (byte) -63, (byte) -36, (byte) -94, (byte) 59, (byte) -5, (byte) 32, 
			(byte) -68, (byte) -3, (byte) -29, (byte) -80, (byte) -41, (byte) -106, (byte) -23, (byte) -40, (byte) -23, 
			(byte) 35, (byte) -18, (byte) -121, (byte) -72, (byte) -53, (byte) 31, (byte) 59, (byte) -50, (byte) 89, 
			(byte) 127, (byte) -46, (byte) -109, (byte) -91}; 
	
	private byte[] att_name = new byte[] {(byte) 0x4b,(byte) 0x6f,(byte) 0x62,(byte) 0x65,(byte) 0x20,(byte) 0x56,(byte) 0x61,(byte) 0x6e,(byte) 0x20,(byte) 0x52,(byte) 0x65,(byte) 0x75,(byte) 0x73,(byte) 0x65,(byte) 0x6c};
	private byte[] att_address = new byte[] {(byte) 0x4c,(byte) 0x61,(byte) 0x6e,(byte) 0x67,(byte) 0x65,(byte) 0x20,(byte) 0x45,(byte) 0x6c,(byte) 0x7a,(byte) 0x65,(byte) 0x6e,(byte) 0x73,(byte) 0x74,(byte) 0x72,(byte) 0x61,(byte) 0x61,(byte) 0x74,(byte) 0x20,(byte) 0x32,(byte) 0x30,(byte) 0x39,(byte) 0x2c,(byte) 0x20,(byte) 0x38,(byte) 0x32,(byte) 0x30,(byte) 0x30,(byte) 0x20,(byte) 0x42,(byte) 0x72,(byte) 0x75,(byte) 0x67,(byte) 0x67,(byte) 0x65};
	private byte[] att_country = new byte[] {(byte) 0x42,(byte) 0x65,(byte) 0x6c,(byte) 0x67,(byte) 0x69,(byte) 0x75,(byte) 0x6d};
	private byte[] att_birthDate = new byte[] {(byte) 0x31,(byte) 0x31,(byte) 0x2f,(byte) 0x30,(byte) 0x35,(byte) 0x2f,(byte) 0x31,(byte) 0x39,(byte) 0x39,(byte) 0x36};
	private byte[] att_age = new byte[] {(byte) 0x32,(byte) 0x32};
	private byte[] att_gender = new byte[] {(byte) 0x6d,(byte) 0x61,(byte) 0x6c,(byte) 0x65};
	private byte[] att_picture = new byte[] {};
	
	byte [] K_u = new byte[] {(byte) 1, (byte) 2, (byte) 3 }; //id of the card
	private InitializedMessageDigest sha1;		
	private byte[] serial = new byte[] { (byte) 0x4A, (byte) 0x61, (byte) 0x6e };
	private byte[] name = new byte[] { (byte) 0x4A, (byte)0x61,(byte) 0x6E, (byte)0x20, (byte)0x56, (byte)0x6F, (byte)0x73, (byte)0x73,(byte) 0x61, (byte)0x65,(byte) 0x72,(byte) 0x74 };
	private OwnerPIN pin;
	private short offset = (short) 0;
	private short keySizeInBytes =  64;
	private short keySizeInBits = (short) 512;
	private RSAPrivateKey privKey = null;
	private AESKey symKey;
	private boolean auth = false;

	private final static short MAX_APDU = (short)240;
	private short BUF_IN_OFFSET[];
	private byte date[];
	private byte [] rnd; //used to create session key while authenticating SP
	private byte [] challenge; //used to verify SP
	private byte [] maxRights; 
	private IdentityCard() {
		/*
		 * During instantiation of the applet, all objects are created. In this example,
		 * this is the 'pin' object.
		 */
		// max try 3 times
		pin = new OwnerPIN(PIN_TRY_LIMIT, PIN_SIZE);
		// pin is 1234
		byte[] pinBytes = new byte[] { 0x31, 0x32, 0x33, 0x34 };
		pin.update(pinBytes, (short) 0, PIN_SIZE);
		// needed for the signature of a random byte array
		privKey = (RSAPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE, keySizeInBits, false);
		privKey.setExponent(privExponent, offset, keySizeInBytes);
		privKey.setModulus(privModulus, offset, keySizeInBytes);

		date = new byte[(short)8];
		/*
		 * This method registers the applet with the JCRE on the card.
		 */
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

	/*
	 * This method is called when the applet is selected and an APDU arrives.
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
		default:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
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
		else {
			byte [] askedData = receiveBigData(apdu);
			System.out.println(askedData[0]);
			System.out.println(askedData[1]);
			System.out.println(askedData[2]);
			System.out.println(askedData[3]);
			System.out.println(askedData[4]);
			System.out.println(askedData[5]);
			System.out.println(askedData[6]);
			System.out.println(askedData[7]);
			short query = (byte) 2;
			if(isSmaller(askedData, maxRights)) {
				//get the synomym for the SP
				byte [] synomym = new byte[19];
				byte [] synomymHashed = new byte[20]; //sha1 gives ouput of 20 btyes
				Util.arrayCopy(K_u, (short) 0 , synomym, (short) 0 , (short) K_u.length);
				Util.arrayCopy(nameBytesCopy16, (short) (0), synomym , (short) K_u.length, (short) 16);
				InitializedMessageDigest hash = sha1;
				hash.reset();
	//			hash.update(synomym, (short) 0, (short) (K_u.length + nameBytesCopy16.length));
				hash.doFinal(synomym, (short) 0 , (short) (K_u.length + nameBytesCopy16.length), synomymHashed, (short) 0);
				
				//get the asked data
				byte [] queryResults = solveQuery(query);
				
				//set everything togheter in one big byte array and send it back
				byte [] sendBack = new byte[ (short) (queryResults.length + synomymHashed.length)];
				Util.arrayCopy(synomymHashed, (short) 0 , sendBack, (short) 0 , (short) synomymHashed.length);
				Util.arrayCopy(queryResults, (short) 0 , sendBack, (short) synomymHashed.length , (short) queryResults.length);
				
				//TODO send back but first check if okey
			}
		}
		
	}

	private byte[] solveQuery(short query) {
		switch(query) {
		case((short) 1):
			
			break;
		case((short) 2):
			
			break;
		case((short) 3):
			
			break;
		default:
			

		}
		return null;
	}

	private void authenticateCard(APDU apdu) {
		//check if SP is already authenticated
		if(!auth) {
//			System.out.println("Serviceprovider not yet authenticated");
			return;
		}
		
		//decrypt 
		byte [] data = receiveBigData(apdu);
		byte [] responseChallengeBytes = new byte[16];
		Cipher aesCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
		aesCipher.init(symKey, Cipher.MODE_DECRYPT);
		aesCipher.doFinal(data, (short) 0, (short)data.length, responseChallengeBytes, (short)0);
//		System.out.println("Bytes: " + bytesToDec(responseChallengeBytes));
		
		//Concat challenge and "AUTH"
		

        try { 
        	//TODO this bytearray output stream does not work with the real card!!
        	//class java.io.ByteArrayOutputStream not found in export file io.exp
//        	ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
//			outputStream.write(responseChallengeBytes);
//			//TODO beno this auth.getbytes make use of string --> not possible on real card :(
////			outputStream.write("AUTH".getBytes());
//		    byte[] bytesToSign = outputStream.toByteArray();
//				
//		    //prepare signature
//		    Signature signature = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);
//		    RSAPrivateKey privk = (RSAPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE, (short)512 , false);
//			privk.setExponent(privExp_ComCer, offset, (short) privExp_ComCer.length);
//			privk.setModulus(privMod_ComCer, offset, (short) privMod_ComCer.length);
//			signature.init(privk, Signature.MODE_SIGN);
//			
//			//sign
//			byte[] outputBuffer = new byte[100];
//			short sigLength = signature.sign(bytesToSign, (short) 0, (short) bytesToSign.length, outputBuffer, (short) 0);
////			System.out.println("Common cer length: " + commonCertificate.length);
//			byte[] sig = new byte[sigLength];
//			Util.arrayCopy(outputBuffer, (short) 0, sig, (short) 0, sigLength);
//			
//			//Concat byte array to send: CommonCert + bytes to sign + sig
//			outputStream = new ByteArrayOutputStream();
//			outputStream.write(commonCertificate);
//			outputStream.write(bytesToSign);
//			outputStream.write(sig);
//			outputStream.write(new byte[] { (byte) -73, (byte) -43, (byte) 96, (byte) -107}); //fill up the length off the message to 224 bytes
//		    byte[] message = outputStream.toByteArray();
//		    byte[] encryptedMessage = new byte[message.length];
////		    System.out.println("message to authenticate card: " + bytesToDec(sig));
//		    
//		    //init symmetric encryption
//		    Cipher symCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
//			symCipher.init(symKey, Cipher.MODE_ENCRYPT);
//			try {
//				symCipher.doFinal(message, (short)0, (short)message.length, encryptedMessage, (short)0);
//
//			}catch(Exception e) {
//				e.printStackTrace();
//			}
//			
//			sendChallengeToSP(apdu, encryptedMessage);

					
			
			
		} catch (Exception e) {
			// TODO Auto-generated catch block
			ISOException.throwIt(ERROR_UNKNOW);
		}
       
		
	}

	private void verifyChallenge(APDU apdu) {
		byte [] data = receiveBigData(apdu);
		byte [] responseChallengeBytes = new byte[16];
		Cipher aesCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
		aesCipher.init(symKey, Cipher.MODE_DECRYPT);
		aesCipher.doFinal(data, (short) 0, (short)data.length, responseChallengeBytes, (short)0);
		//TODO beno Biginteger cannot be used on real smart card!! --> commented
//		BigInteger responseChallengeBigInt = new BigInteger(1, responseChallengeBytes);
//		BigInteger challengeBigInt = new BigInteger(1, this.challenge);
		//verify
		auth = false;
//		if(responseChallengeBigInt.equals(challengeBigInt.add(BigInteger.ONE))) {
//			auth = true;
//		}
		if(auth) {
//			System.out.println("challenge verified --> service provider verified");
		}
		
	}
	
	private void authenticateServiceProvider(APDU apdu) {
		byte[] data = receiveBigData(apdu);
		byte[] signedCertificate = new byte[64];
		
		byte [] certificateBytes = new byte[ (short) ( data.length - signedCertificate.length) ];
		byte[] validEndTimeCertificate = new byte[(short)8];
		byte[] pkExpBytesSP = new byte[(short)3];
		byte[] pkModBytesSP = new byte[(short)64];
		byte[] nameBytes = new byte[(short) (certificateBytes.length - pkExpBytesSP.length - pkModBytesSP.length - validEndTimeCertificate.length -3)];
		nameBytesCopy16 = new byte[(short)16];
		maxRights = new byte[2];
		//		System.out.println("namebytes length: "+nameBytes.length);
		
		Util.arrayCopy(data, (short) (0), signedCertificate , (short) 0, (short) 64);
		Util.arrayCopy(data, (short) (64), certificateBytes, (short) 0, (short) (data.length-64));
		Util.arrayCopy(certificateBytes, (short) (0), pkExpBytesSP, (short)(0), (short)(3));
		Util.arrayCopy(certificateBytes, (short)4, pkModBytesSP, (short)(0), (short)64);
		Util.arrayCopy(certificateBytes, (short)68, validEndTimeCertificate, (short)0, (short)8);
		Util.arrayCopy(certificateBytes, (short) 76 , maxRights, (short) 0 , (short) 2) ;
		Util.arrayCopy(certificateBytes, (short) 78, nameBytes, (short)0, (short)nameBytes.length);
		Util.arrayCopy(nameBytes, (short)0, nameBytesCopy16, (short)0, (short)nameBytes.length);

		//end jonas code
		
		Signature signature = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);
		// this keysize must be the same size as the one given in in setModulus! but
		// another keylenght is not working!! 512 is max
		try {
			RSAPublicKey pubk = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, (short)512 , false);
			pubk.setExponent(pubExp_CA, offset, (short) 3);
			pubk.setModulus(pubMod_CA, offset, (short) pubMod_CA.length);
			signature.init(pubk, Signature.MODE_VERIFY);
			
			boolean result = signature.verify(certificateBytes, (short) 0, (short) certificateBytes.length, signedCertificate , (short) 0, (short) signedCertificate .length);
			//result is true if everything went fine 
			//but now just commented for not losing time
			if(!result) {
				//misschien iets opgooien dat zegt dat cert niet geldig is?
				ISOException.throwIt(ERROR_UNKNOW);
			}
			if(isSmaller(validEndTimeCertificate, lastValidationTime)) {
				//throw other exception?
			ISOException.throwIt(ERROR_UNKNOW);
			}
			//if everything okay --> create new symmetric key
			this.symKey = getSymKey();
			
			//rebuild SP PK
			RSAPublicKey publicKeySP = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, (short) (512) , false);
			publicKeySP.setExponent(pkExpBytesSP, offset, (short) 3);
			publicKeySP.setModulus(pkModBytesSP, offset, (short) (pkModBytesSP.length));
//			//encrypt rnd to send to SP
//			//met rnd kan SP de symmetrische key heropbouwen
//			
			Cipher asymCipher = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);
			byte[] encryptedRnd = JCSystem.makeTransientByteArray((short) 64, JCSystem.CLEAR_ON_DESELECT);
			asymCipher.init((RSAPublicKey)publicKeySP, Cipher.MODE_ENCRYPT);
			
			try {
				asymCipher.doFinal(this.rnd, (short)0, (short)this.rnd.length, encryptedRnd, (short)0);

			}catch(Exception e) {
				ISOException.throwIt(ERROR_UNKNOW);
			}
			
			
			//generate challenge
			byte[] challengeBytes = generateRandomBytes();		
//			BigInteger challenge = new BigInteger(1, challengeBytes);	//for testing
			this.challenge = challengeBytes;
			//challengebytes symmetrisch encrypteren
			Cipher symCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
			symCipher.init(symKey, Cipher.MODE_ENCRYPT);
			byte[] encryptedChallengeBytes = new byte[(short) 16];
			byte[] encryptedNameBytes = new byte[(short)16];
			try {
				symCipher.doFinal(challengeBytes, (short)0, (short)challengeBytes.length, encryptedChallengeBytes, (short)0);
				symCipher.init(symKey, Cipher.MODE_ENCRYPT);
				symCipher.doFinal(nameBytesCopy16, (short)0,(short) nameBytesCopy16.length, encryptedNameBytes, (short)0);
			} catch (Exception e) {
				// TODO Auto-generated catch block
				ISOException.throwIt(ERROR_UNKNOW);
			}
			
			//msg opbouwen om terug te zenden
			byte [] toSend = new byte[(short) (encryptedRnd.length + encryptedChallengeBytes.length + encryptedNameBytes.length)];
			Util.arrayCopy(encryptedRnd, (short)0, toSend, (short)0, (short) encryptedRnd.length);
			Util.arrayCopy(encryptedChallengeBytes, (short)0, toSend, (short)encryptedRnd.length, (short)encryptedChallengeBytes.length);
			Util.arrayCopy(encryptedNameBytes, (short)0, toSend, (short)(encryptedRnd.length + challengeBytes.length),(short)encryptedNameBytes.length);
			
			//send msg to SP 
			if(sendChallengeToSP(apdu, toSend)) {
//				System.out.println("success send challenge");
			}

		}catch(Exception e) {
			ISOException.throwIt(ERROR_UNKNOW);
		}
	}
	
	private boolean sendChallengeToSP(APDU apdu, byte[] toSend) {
		short length = (short)toSend.length;
		try {
			apdu.setOutgoing();
			apdu.setOutgoingLength(length);
			short lenToSend = 32; // send all the data in pieces of each 32 bytes
			byte counter = 0;
			while (length > 0) {
				if (length < 32) { // if data to send is not muliple of 32
					lenToSend = length;
				}
				apdu.sendBytesLong(toSend, (short) (32 * counter), lenToSend); // send part of certificate each
																					// time.
				length = (short) (length - 32);
				counter = (byte) (counter + 1);
			}
			
		}catch(Exception e ) {
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
			if(result && isSmaller(lastValidationTime, date)) {
				lastValidationTime = date;
			}else {
				ISOException.throwIt(ERROR_UNKNOW);
			}
		} catch (Exception e) {
			ISOException.throwIt(ERROR_WRONG_TIME);
		}
	}
	
	/**
	 * Method that calculates with byte array (represents an number) is
	 * smaller  if array1 < array2 --> true;
	 * 
	 * @param byte[], byte[]
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
	
	private AESKey getSymKey() {
		//https://stackoverflow.com/questions/15882088/aes-key-from-javacard-to-java-encrypting?utm_medium=organic&utm_source=google_rich_qa&utm_campaign=google_rich_qa
		RandomData randomData = RandomData.getInstance(RandomData.ALG_PSEUDO_RANDOM);
		this.rnd = JCSystem.makeTransientByteArray((short)16, JCSystem.CLEAR_ON_RESET);
		randomData.generateData(rnd, (short) 0, (short) rnd.length);
		AESKey symKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
		symKey.setKey(rnd, (short) 0);
		return symKey;
	}
	
	private byte[] generateRandomBytes() {
		RandomData randomData = RandomData.getInstance(RandomData.ALG_PSEUDO_RANDOM);
		this.rnd = JCSystem.makeTransientByteArray((short)16, JCSystem.CLEAR_ON_RESET);
		randomData.generateData(rnd, (short) 0, (short) rnd.length);
		return rnd;
	}
	
	private void sign(APDU apdu) {
		try {

			if (!pin.isValidated())
				ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
			else {

				byte[] outputBuffer = new byte[100];
				byte[] buffer = new byte[apdu.getIncomingLength()];
				Util.arrayCopy(apdu.getBuffer(), apdu.getOffsetCdata(), buffer, (short) 0,
						(short) apdu.getIncomingLength());

				Signature signature = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);
				signature.init(privKey, Signature.MODE_SIGN);
				short responsLength = signature.sign(buffer, (short) 0, (short) (buffer.length), outputBuffer,
						(short) 0);
				apdu.setOutgoing();
				apdu.setOutgoingLength((short) responsLength);
				apdu.sendBytesLong(outputBuffer, (short) 0, responsLength);
			}
		} catch (Exception e) {
			if (e instanceof ArrayIndexOutOfBoundsException) {
				ISOException.throwIt(ERROR_OUT_OF_BOUNDS);
			} else {
				ISOException.throwIt(ERROR_UNKNOW);
			}
		}
	}

//	private void getCertificate(APDU apdu) {
		// if the pin is validated --> return certificate
		// byte [] partOfCertificate = new byte[240];
		// byte[] buffer = apdu.getBuffer();
		// offset = buffer[ISO7816.OFFSET_P1];
		// short length = (short) certificate.length;
		// if(!pin.isValidated())ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
		// else{
		// if(offset == 0x01) offset = 238;
		// for (short i = 0; (i < 240) && ((offset + i) < certificate.length); i++) {
		// partOfCertificate[i] = certificate[offset + i];
		// }
		// apdu.setOutgoing();
		// apdu.setOutgoingLength((short)partOfCertificate.length);
		// apdu.sendBytesLong(partOfCertificate,(short)0,(short)partOfCertificate.length);
		// }
//	}

	/*
	 * This method checks whether the user is authenticated and sends the serial
	 * number.
	 */
	private void getSerial(APDU apdu) {
		// If the pin is not validated, a response APDU with the
		// 'SW_PIN_VERIFICATION_REQUIRED' status word is transmitted.
		if (!pin.isValidated())
			ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
		else {
			// This sequence of three methods sends the data contained in
			// 'serial' with offset '0' and length 'serial.length'
			// to the host application.
			apdu.setOutgoing();
			apdu.setOutgoingLength((short) serial.length);
			apdu.sendBytesLong(serial, (short) 0, (short) serial.length);
		}
	}

	private void getName(APDU apdu) {
		// If the pin is not validated, a response APDU with the
		// 'SW_PIN_VERIFICATION_REQUIRED' status word is transmitted.
		if (!pin.isValidated())
			ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
		else {
			// This sequence of three methods sends the data contained in
			// 'serial' with offset '0' and length 'serial.length'
			// to the host application.
			apdu.setOutgoing();
			apdu.setOutgoingLength((short) name.length);
			apdu.sendBytesLong(name, (short) 0, (short) name.length);
		}
	}

	
	/**
	 * Method works! Send the whole certificate to the client in pieces of 32 bytes.
	 * 
	 * @param apdu
	 */
	private void sendCertificate(APDU apdu) {
		// Send big files
		short toSend = (short) (certificate.length);

		try {
			apdu.setOutgoing(); // change direction of data channel
			apdu.setOutgoingLength(toSend); // set total amount of byte you want to transfer
			short lenToSend = 32; // send all the data in pieces of each 32 bytes
			byte counter = 0;
			while (toSend > 0) {
				if (toSend < 32) { // if data to send is not muliple of 32
					lenToSend = toSend;
				}
				apdu.sendBytesLong(certificate, (short) (32 * counter), lenToSend); // send part of certificate each
																					// time.
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
			} else if (e instanceof ArrayIndexOutOfBoundsException) {
				ISOException.throwIt(ERROR_OUT_OF_BOUNDS);
			} else {
				ISOException.throwIt(ERROR_UNKNOW);
			}
		}
	}
}