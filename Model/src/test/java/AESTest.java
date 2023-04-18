import org.example.AES;
import org.junit.Assert;
import org.junit.Test;


public class AESTest {


    /* Byte values used in tests were taken from AES standard
       Link: https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.197.pdf (look at the appendix contents)
     */
    @Test
    public void subBytesTest() {
        AES aes = new AES(128);
        byte[][] test = {
                {(byte) 0x00, (byte) 0x40, (byte) 0x80, (byte) 0xc0},
                {(byte) 0x10, (byte) 0x50, (byte) 0x90, (byte) 0xd0},
                {(byte) 0x20, (byte) 0x60, (byte) 0xa0, (byte) 0xe0},
                {(byte) 0x30, (byte) 0x70, (byte) 0xb0, (byte) 0xf0}};
        Assert.assertArrayEquals(aes.subBytes(test), new byte[][] {
                {(byte) 0x63, (byte) 0x09, (byte) 0xcd, (byte) 0xba},
                {(byte) 0xca, (byte) 0x53, (byte) 0x60, (byte) 0x70},
                {(byte) 0xb7, (byte) 0xd0, (byte) 0xe0, (byte) 0xe1},
                {(byte) 0x04, (byte) 0x51, (byte) 0xe7, (byte) 0x8c}});
    }

    @Test
    public void shiftRowsTest() {
        AES aes = new AES(128);
        byte[][] test = {
                {(byte) 0x63, (byte) 0x09, (byte) 0xcd, (byte) 0xba},
                {(byte) 0xca, (byte) 0x53, (byte) 0x60, (byte) 0x70},
                {(byte) 0xb7, (byte) 0xd0, (byte) 0xe0, (byte) 0xe1},
                {(byte) 0x04, (byte) 0x51, (byte) 0xe7, (byte) 0x8c}};
        Assert.assertArrayEquals(aes.shiftRows(test), new byte[][] {
                {(byte) 0x63, (byte) 0x09, (byte) 0xcd, (byte) 0xba},
                {(byte) 0x53, (byte) 0x60, (byte) 0x70, (byte) 0xca},
                {(byte) 0xe0, (byte) 0xe1, (byte) 0xb7, (byte) 0xd0},
                {(byte) 0x8c, (byte) 0x04, (byte) 0x51, (byte) 0xe7}});
    }

    @Test
    public void mixColumnsTest() {
        AES aes = new AES(128);
        byte[][] test = new byte[][] {
                {(byte) 0x63, (byte) 0x09, (byte) 0xcd, (byte) 0xba},
                {(byte) 0x53, (byte) 0x60, (byte) 0x70, (byte) 0xca},
                {(byte) 0xe0, (byte) 0xe1, (byte) 0xb7, (byte) 0xd0},
                {(byte) 0x8c, (byte) 0x04, (byte) 0x51, (byte) 0xe7}};
        byte[][] expected = new byte[][] {
                {(byte)0x5f, (byte)0x57, (byte)0xf7, (byte)0x1d},
                {(byte)0x72, (byte)0xf5, (byte)0xbe, (byte)0xb9},
                {(byte)0x64, (byte)0xbc, (byte)0x3b, (byte)0xf9},
                {(byte)0x15, (byte)0x92, (byte)0x29, (byte)0x1a}};
        Assert.assertArrayEquals(expected, aes.mixColumns(test));
    }

    @Test
    public void subWordTest() {
        AES aes = new AES(128);
        byte[] test = new byte[] {(byte) 0x11, (byte) 0x22, (byte) 0x33, (byte) 0x44};
        byte[] expected = new byte[] {(byte) 0x82, (byte) 0x93, (byte) 0xc3, (byte) 0x1b};
        Assert.assertArrayEquals(expected, aes.subWord(test));
    }

    @Test
    public void rotWordTest() {
        AES aes = new AES(128);
        byte[] test = new byte[] {(byte) 0x11, (byte) 0x22, (byte) 0x33, (byte) 0x44};
        byte[] expected = new byte[] {(byte) 0x22, (byte) 0x33, (byte) 0x44, (byte) 0x11};
        Assert.assertArrayEquals(expected, aes.rotWord(test));
    }

    @Test
    public void getRconTest() {
        AES aes = new AES(128);
        Assert.assertEquals((byte) 0x01, aes.getRcon(1));
        Assert.assertEquals((byte) 0x02, aes.getRcon(2));
        Assert.assertEquals((byte) 0x04, aes.getRcon(3));
        Assert.assertEquals((byte) 0x08, aes.getRcon(4));
        Assert.assertEquals((byte) 0x10, aes.getRcon(5));
        Assert.assertEquals((byte) 0x20, aes.getRcon(6));
        Assert.assertEquals((byte) 0x40, aes.getRcon(7));
        Assert.assertEquals((byte) 0x80, aes.getRcon(8));
        Assert.assertEquals((byte) 0x1b, aes.getRcon(9));
        Assert.assertEquals((byte) 0x36, aes.getRcon(10));
    }

    @Test
    public void wordOperationTest() {
        AES aes = new AES(128);
        byte[] expected = new byte[] {(byte) 0x7c, (byte) 0x63, (byte) 0x9f, (byte) 0x5b};
        Assert.assertArrayEquals(aes.wordOperation(new byte[] {(byte) 0x57, (byte) 0x5c, (byte) 0x00, (byte) 0x6e}, 40), expected);
    }

    @Test
    public void expandKey128bitTest() {
        byte[] key = new byte[] {
                (byte) 0x2b, (byte) 0x7e, (byte) 0x15, (byte) 0x16,
                (byte) 0x28, (byte) 0xae, (byte) 0xd2, (byte) 0xa6,
                (byte) 0xab, (byte) 0xf7, (byte) 0x15, (byte) 0x88,
                (byte) 0x09, (byte) 0xcf, (byte) 0x4f, (byte) 0x3c};
        AES aes = new AES(128, key);
        byte[][] test = aes.expandKey();
        Assert.assertEquals(test[0][43], (byte) 0xb6);
        Assert.assertEquals(test[1][43], (byte) 0x63);
        Assert.assertEquals(test[2][43], (byte) 0x0c);
        Assert.assertEquals(test[3][43], (byte) 0xa6);
        Assert.assertEquals(test[0][42], (byte) 0xe1);
        Assert.assertEquals(test[1][42], (byte) 0x3f);
        Assert.assertEquals(test[2][42], (byte) 0x0c);
        Assert.assertEquals(test[3][42], (byte) 0xc8);
    }

    @Test
    public void expandKey192bitTest() {
        byte[] key = new byte[] {
                (byte) 0x8e, (byte) 0x73, (byte) 0xb0, (byte) 0xf7,
                (byte) 0xda, (byte) 0x0e, (byte) 0x64, (byte) 0x52,
                (byte) 0xc8, (byte) 0x10, (byte) 0xf3, (byte) 0x2b,
                (byte) 0x80, (byte) 0x90, (byte) 0x79, (byte) 0xe5,
                (byte) 0x62, (byte) 0xf8, (byte) 0xea, (byte) 0xd2,
                (byte) 0x52, (byte) 0x2c, (byte) 0x6b, (byte) 0x7b};
        AES aes = new AES(192, key);
        byte[][] test = aes.expandKey();
        Assert.assertEquals(test[0][51], (byte) 0x01);
        Assert.assertEquals(test[1][51], (byte) 0x00);
        Assert.assertEquals(test[2][51], (byte) 0x22);
        Assert.assertEquals(test[3][51], (byte) 0x02);
    }

    @Test
    public void expandKey256bitTest() {
        byte[] key = new byte[] {
                (byte) 0x60, (byte) 0x3d, (byte) 0xeb, (byte) 0x10,
                (byte) 0x15, (byte) 0xca, (byte) 0x71, (byte) 0xbe,
                (byte) 0x2b, (byte) 0x73, (byte) 0xae, (byte) 0xf0,
                (byte) 0x85, (byte) 0x7d, (byte) 0x77, (byte) 0x81,
                (byte) 0x1f, (byte) 0x35, (byte) 0x2c, (byte) 0x07,
                (byte) 0x3b, (byte) 0x61, (byte) 0x08, (byte) 0xd7,
                (byte) 0x2d, (byte) 0x98, (byte) 0x10, (byte) 0xa3,
                (byte) 0x09, (byte) 0x14, (byte) 0xdf, (byte) 0xf4};
        AES aes = new AES(256, key);
        byte[][] test = aes.expandKey();
        Assert.assertEquals(test[0][59], (byte) 0x70);
        Assert.assertEquals(test[1][59], (byte) 0x6c);
        Assert.assertEquals(test[2][59], (byte) 0x63);
        Assert.assertEquals(test[3][59], (byte) 0x1e);
    }

    @Test
    public void addRoundKeyTest() {
        byte[] key = new byte[] {
                (byte) 0x2b, (byte) 0x7e, (byte) 0x15, (byte) 0x16,
                (byte) 0x28, (byte) 0xae, (byte) 0xd2, (byte) 0xa6,
                (byte) 0xab, (byte) 0xf7, (byte) 0x15, (byte) 0x88,
                (byte) 0x09, (byte) 0xcf, (byte) 0x4f, (byte) 0x3c};
        AES aes = new AES(128, key);
        byte[][] test = new byte[][] {
                {(byte) 0x32, (byte) 0x88, (byte) 0x31, (byte) 0xe0},
                {(byte) 0x43, (byte) 0x5a, (byte) 0x31, (byte) 0x37},
                {(byte) 0xf6, (byte) 0x30, (byte) 0x98, (byte) 0x07},
                {(byte) 0xa8, (byte) 0x8d, (byte) 0xa2, (byte) 0x34}};
        byte[][] expected = new byte[][] {
                {(byte) 0x19, (byte) 0xa0, (byte) 0x9a, (byte) 0xe9},
                {(byte) 0x3d, (byte) 0xf4, (byte) 0xc6, (byte) 0xf8},
                {(byte) 0xe3, (byte) 0xe2, (byte) 0x8d, (byte) 0x48},
                {(byte) 0xbe, (byte) 0x2b, (byte) 0x2a, (byte) 0x08}};
        Assert.assertArrayEquals(expected, aes.addRoundKey(test, 0));
    }


    @Test
    public void encipher128bitTest() {
        byte[] testkey = new byte[] {
                (byte)0x00, (byte)0x01, (byte)0x02, (byte)0x03,
                (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07,
                (byte)0x08, (byte)0x09, (byte)0x0a, (byte)0x0b,
                (byte)0x0c, (byte)0x0d, (byte)0x0e, (byte)0x0f};
        AES aes = new AES(128, testkey);
        byte [] input = new byte[] {
                (byte)0x00, (byte)0x11, (byte)0x22, (byte)0x33,
                (byte)0x44, (byte)0x55, (byte)0x66, (byte)0x77,
                (byte)0x88, (byte)0x99, (byte)0xaa, (byte)0xbb,
                (byte)0xcc, (byte)0xdd, (byte)0xee, (byte)0xff};
        byte[] test2 = aes.encipher(input);
        byte[] expected = {
                (byte)0x69, (byte)0xc4, (byte)0xe0, (byte)0xd8,
                (byte)0x6a, (byte)0x7b, (byte)0x04, (byte)0x30,
                (byte)0xd8, (byte)0xcd, (byte)0xb7, (byte)0x80,
                (byte)0x70, (byte)0xb4, (byte)0xc5, (byte)0x5a};
        Assert.assertArrayEquals(expected, test2);
        Assert.assertArrayEquals(input, aes.decipher(expected));
    }

    @Test
    public void decipher128bitTest() {
        byte[] testkey = new byte[] {
                (byte)0x00, (byte)0x01, (byte)0x02, (byte)0x03,
                (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07,
                (byte)0x08, (byte)0x09, (byte)0x0a, (byte)0x0b,
                (byte)0x0c, (byte)0x0d, (byte)0x0e, (byte)0x0f};
        AES aes = new AES(128, testkey);
        byte[] input = {
                (byte)0x69, (byte)0xc4, (byte)0xe0, (byte)0xd8,
                (byte)0x6a, (byte)0x7b, (byte)0x04, (byte)0x30,
                (byte)0xd8, (byte)0xcd, (byte)0xb7, (byte)0x80,
                (byte)0x70, (byte)0xb4, (byte)0xc5, (byte)0x5a};
        byte [] expected = new byte[] {
                (byte)0x00, (byte)0x11, (byte)0x22, (byte)0x33,
                (byte)0x44, (byte)0x55, (byte)0x66, (byte)0x77,
                (byte)0x88, (byte)0x99, (byte)0xaa, (byte)0xbb,
                (byte)0xcc, (byte)0xdd, (byte)0xee, (byte)0xff};
        Assert.assertArrayEquals(expected, aes.decipher(input));
    }

    @Test
    public void encipher192bitTest() {
        byte [] input = new byte[] {
                (byte)0x00, (byte)0x11, (byte)0x22, (byte)0x33,
                (byte)0x44, (byte)0x55, (byte)0x66, (byte)0x77,
                (byte)0x88, (byte)0x99, (byte)0xaa, (byte)0xbb,
                (byte)0xcc, (byte)0xdd, (byte)0xee, (byte)0xff};
        byte[] testkey = new byte[] {
                (byte)0x00, (byte)0x01, (byte)0x02, (byte)0x03,
                (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07,
                (byte)0x08, (byte)0x09, (byte)0x0a, (byte)0x0b,
                (byte)0x0c, (byte)0x0d, (byte)0x0e, (byte)0x0f,
                (byte)0x10, (byte)0x11, (byte)0x12, (byte)0x13,
                (byte)0x14, (byte)0x15, (byte)0x16, (byte)0x17};
        AES aes = new AES(192, testkey);
        byte[] expected = new byte[] {
                (byte)0xdd, (byte)0xa9, (byte)0x7c, (byte)0xa4,
                (byte)0x86, (byte)0x4c, (byte)0xdf, (byte)0xe0,
                (byte)0x6e, (byte)0xaf, (byte)0x70, (byte)0xa0,
                (byte)0xec, (byte)0x0d, (byte)0x71, (byte)0x91};
        Assert.assertArrayEquals(expected, aes.encipher(input));
    }

    @Test
    public void decipher192bitTest() {
        byte[] testkey = new byte[] {
                (byte)0x00, (byte)0x01, (byte)0x02, (byte)0x03,
                (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07,
                (byte)0x08, (byte)0x09, (byte)0x0a, (byte)0x0b,
                (byte)0x0c, (byte)0x0d, (byte)0x0e, (byte)0x0f,
                (byte)0x10, (byte)0x11, (byte)0x12, (byte)0x13,
                (byte)0x14, (byte)0x15, (byte)0x16, (byte)0x17};
        AES aes = new AES(192, testkey);
        byte[] input = new byte[] {
                (byte)0xdd, (byte)0xa9, (byte)0x7c, (byte)0xa4,
                (byte)0x86, (byte)0x4c, (byte)0xdf, (byte)0xe0,
                (byte)0x6e, (byte)0xaf, (byte)0x70, (byte)0xa0,
                (byte)0xec, (byte)0x0d, (byte)0x71, (byte)0x91};
        byte [] expected = new byte[] {
                (byte)0x00, (byte)0x11, (byte)0x22, (byte)0x33,
                (byte)0x44, (byte)0x55, (byte)0x66, (byte)0x77,
                (byte)0x88, (byte)0x99, (byte)0xaa, (byte)0xbb,
                (byte)0xcc, (byte)0xdd, (byte)0xee, (byte)0xff};
        Assert.assertArrayEquals(expected, aes.decipher(input));
    }

    @Test
    public void encipher256bitTest() {
        byte [] input = new byte[] {
                (byte)0x00, (byte)0x11, (byte)0x22, (byte)0x33,
                (byte)0x44, (byte)0x55, (byte)0x66, (byte)0x77,
                (byte)0x88, (byte)0x99, (byte)0xaa, (byte)0xbb,
                (byte)0xcc, (byte)0xdd, (byte)0xee, (byte)0xff};
        byte[] testkey = new byte[] {
                (byte)0x00, (byte)0x01, (byte)0x02, (byte)0x03,
                (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07,
                (byte)0x08, (byte)0x09, (byte)0x0a, (byte)0x0b,
                (byte)0x0c, (byte)0x0d, (byte)0x0e, (byte)0x0f,
                (byte)0x10, (byte)0x11, (byte)0x12, (byte)0x13,
                (byte)0x14, (byte)0x15, (byte)0x16, (byte)0x17,
                (byte)0x18, (byte)0x19, (byte)0x1a, (byte)0x1b,
                (byte)0x1c, (byte)0x1d, (byte)0x1e, (byte)0x1f};
        AES aes = new AES(256, testkey);
        byte[] expected = new byte[] {
                (byte)0x8e, (byte)0xa2, (byte)0xb7, (byte)0xca,
                (byte)0x51, (byte)0x67, (byte)0x45, (byte)0xbf,
                (byte)0xea, (byte)0xfc, (byte)0x49, (byte)0x90,
                (byte)0x4b, (byte)0x49, (byte)0x60, (byte)0x89};
        Assert.assertArrayEquals(expected, aes.encipher(input));
        Assert.assertArrayEquals(input, aes.decipher(expected));
    }

    @Test
    public void decipher256bitTest() {
        byte[] testkey = new byte[] {
                (byte)0x00, (byte)0x01, (byte)0x02, (byte)0x03,
                (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07,
                (byte)0x08, (byte)0x09, (byte)0x0a, (byte)0x0b,
                (byte)0x0c, (byte)0x0d, (byte)0x0e, (byte)0x0f,
                (byte)0x10, (byte)0x11, (byte)0x12, (byte)0x13,
                (byte)0x14, (byte)0x15, (byte)0x16, (byte)0x17,
                (byte)0x18, (byte)0x19, (byte)0x1a, (byte)0x1b,
                (byte)0x1c, (byte)0x1d, (byte)0x1e, (byte)0x1f};
        AES aes = new AES(256, testkey);
        byte[] input = new byte[] {
                (byte)0x8e, (byte)0xa2, (byte)0xb7, (byte)0xca,
                (byte)0x51, (byte)0x67, (byte)0x45, (byte)0xbf,
                (byte)0xea, (byte)0xfc, (byte)0x49, (byte)0x90,
                (byte)0x4b, (byte)0x49, (byte)0x60, (byte)0x89};
        byte [] expected = new byte[] {
                (byte)0x00, (byte)0x11, (byte)0x22, (byte)0x33,
                (byte)0x44, (byte)0x55, (byte)0x66, (byte)0x77,
                (byte)0x88, (byte)0x99, (byte)0xaa, (byte)0xbb,
                (byte)0xcc, (byte)0xdd, (byte)0xee, (byte)0xff};
        Assert.assertArrayEquals(expected, aes.decipher(input));
    }

    @Test
    public void invSubBytesTest() {
        AES aes = new AES(128);
        byte[][] test = {
                {(byte) 0x7a, (byte) 0x89, (byte) 0x2b, (byte) 0x3d},
                {(byte) 0x9f, (byte) 0xd5, (byte) 0xef, (byte) 0xca},
                {(byte) 0x10, (byte) 0xf5, (byte) 0xfd, (byte) 0x4e},
                {(byte) 0x27, (byte) 0x0b, (byte) 0x9f, (byte) 0xa7}};
        byte[][] expected = {
                {(byte) 0xbd, (byte) 0xf2, (byte) 0x0b, (byte) 0x8b},
                {(byte) 0x6e, (byte) 0xb5, (byte) 0x61, (byte) 0x10},
                {(byte) 0x7c, (byte) 0x77, (byte) 0x21, (byte) 0xb6},
                {(byte) 0x3d, (byte) 0x9e, (byte) 0x6e, (byte) 0x89}};
        Assert.assertArrayEquals(expected, aes.invSubBytes(test));
    }

    @Test
    public void invShiftRowsTest() {
        AES aes = new AES(128);
        byte[][] test = {
                {(byte) 0x7a, (byte) 0x89, (byte) 0x2b, (byte) 0x3d},
                {(byte) 0xd5, (byte) 0xef, (byte) 0xca, (byte) 0x9f},
                {(byte) 0xfd, (byte) 0x4e, (byte) 0x10, (byte) 0xf5},
                {(byte) 0xa7, (byte) 0x27, (byte) 0x0b, (byte) 0x9f}};
        byte[][] expected = {
                {(byte) 0x7a, (byte) 0x89, (byte) 0x2b, (byte) 0x3d},
                {(byte) 0x9f, (byte) 0xd5, (byte) 0xef, (byte) 0xca},
                {(byte) 0x10, (byte) 0xf5, (byte) 0xfd, (byte) 0x4e},
                {(byte) 0x27, (byte) 0x0b, (byte) 0x9f, (byte) 0xa7}};
        Assert.assertArrayEquals(expected, aes.invShiftRows(test));
    }

}






