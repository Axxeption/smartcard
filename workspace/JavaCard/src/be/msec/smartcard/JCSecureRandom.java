package be.msec.smartcard;

import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.RandomData;

public final class JCSecureRandom {

    private static final short SHORT_SIZE_BYTES = 2;
    private static final short START = 0;

    private final RandomData rnd;
    private final byte[] buf;

    /**
     * Constructor which uses the given source of random bytes. A two byte
     * buffer transient buffer is generated that is cleared on deselect.
     * 
     * @param rnd
     *            the source of random bytes
     */
    public JCSecureRandom(final RandomData rnd) {
        this.rnd = rnd;
        this.buf = JCSystem.makeTransientByteArray(SHORT_SIZE_BYTES,
                JCSystem.CLEAR_ON_DESELECT);
    }

    /**
     * Generates a single short with a random value in the range of 0
     * (inclusive) to the given parameter n (exclusive).
     * 
     * @param n
     *            the upper bound of the random value, must be positive
     *            (exclusive)
     * @return the random value in the range [0..n-1]
     */
    public short nextShort(final short n) {
        final short sn = (short) (n - 1);
        short bits, val;
        do {
            bits = next15();
            val = (short) (bits % n);
        } while ((short) (bits - val + sn) < 0);
        return val;
    }

    /**
     * Generates a single byte with a random value in the range of 0 (inclusive)
     * to the given parameter n (exclusive).
     * 
     * @param n
     *            the upper bound of the random value, must be positive
     *            (exclusive)
     * @return the random value in the range [0..n-1]
     */
    public byte nextByte(final byte n) {
        if ((n & -n) == n) {
            return (byte) ((n * next7()) >> 7);
        }

        final byte sn = (byte) (n - 1);
        byte bits, val;
        do {
            bits = next7();
            val = (byte) (bits % n);
        } while ((byte) (bits - val + sn) < 0);
        return val;
    }

    /**
     * Generates 15 bits from two bytes by setting the highest bit to zero.
     * 
     * @return the positive valued short containing 15 bits of random
     */
    private short next15() {
        this.rnd.generateData(this.buf, START, SHORT_SIZE_BYTES);
        return (short) (Util.getShort(this.buf, START) & 0x7FFF);
    }

    /**
     * Generates 7 bits from one byte by setting the highest bit to zero.
     * 
     * @return the positive valued byte containing 7 bits of random
     */
    private byte next7() {
        this.rnd.generateData(this.buf, START, SHORT_SIZE_BYTES);
        return (byte) (this.buf[START] & 0x7F);
    }
}
