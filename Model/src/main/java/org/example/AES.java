package org.example;

import java.math.BigInteger;
import java.util.Random;

public class AES implements Cipher {

    private final int nb;                         //Number of columns (32 bit word)
    private int nk;                         //Number of 32 bit words
    private int nr;                         //Number of rounds in encipher
    private byte[] key;                     //One-dimensional array which contains key

    /* Constructor of class AES takes keyLength in bits and sets other variables according to the specification */

    public AES(int keyLength) {
        this.nb = 4;
        if (keyLength == 128) {
            this.nk = 4;
            this.nr = 10;
        } else if (keyLength == 192) {
            this.nk = 6;
            this.nr = 12;
        } else if (keyLength == 256) {
            this.nk = 8;
            this.nr = 14;
        }
        generateKey();
    }

    /* Basically the same constructor as above but you can provide your own key during initialization and doesn't need to
    invoke setKey() method afterwards. */

    public AES(int keyLength, byte[] key) {
        this.key = key;
        this.nb = 4;
        if (keyLength == 128) {
            this.nk = 4;
            this.nr = 10;
        } else if (keyLength == 192) {
            this.nk = 6;
            this.nr = 12;
        } else if (keyLength == 256) {
            this.nk = 8;
            this.nr = 14;
        }
    }


    @Override
    public byte[] encipher(byte[] data) {
        byte[][] state = oneDimensionalArrayConversion(data, (int)Math.sqrt(data.length), (int)Math.sqrt(data.length));
        byte [] tmp = new byte[data.length];
        state = addRoundKey(state, 0);


        for (int round = 1; round < nr; round++)
        {
            state = subBytes(state);
            state = shiftRows(state);
            state = mixColumns(state);
            state = addRoundKey(state, round);
        }
        state = subBytes(state);
        state = shiftRows(state);
        state = addRoundKey(state, nr);

        for (int i = 0; i < tmp.length; i++) {
            tmp[i] = state[i % 4][i / 4];
        }
        return tmp;
    }

    public byte[] encode (byte [] data){
        int full16BytesBlocks = data.length / 16;
        if(data.length % 16 !=0 ){
            full16BytesBlocks++;
        }
        if (full16BytesBlocks == 0){
            full16BytesBlocks++;
        }

        int len = full16BytesBlocks * 16;
        byte[] result = new byte[len];
        byte[] temp = new byte [len];
        byte[] blok = new byte [16];

        for(int i=0;i<len;i++){
            if(i<data.length) temp[i] = data[i];
            else temp[i] = 0;
        }
        for (int k=0;k<temp.length;){
            for(int j=0;j<16;j++) blok[j] = temp[k++];
            blok = encipher(blok);
            System.arraycopy(blok,0,result,k-16,blok.length);
        }
        return result;

    }

    @Override
    public byte[] decipher(byte[] data) {
        byte[][] state = oneDimensionalArrayConversion(data, (int)Math.sqrt(data.length), (int)Math.sqrt(data.length));
        byte [] tmp = new byte[data.length];
        state = addRoundKey(state, nr);
        state = invShiftRows(state);
        state = invSubBytes(state);

        for (int round = nr - 1; round > 0; round--)
        {
            state = addRoundKey(state, round);
            state = invMixColumns(state);
            state = invShiftRows(state);
            state = invSubBytes(state);
        }

        state = addRoundKey(state, 0);
        for (int i = 0; i < tmp.length; i++) {
            tmp[i] = state[i % 4][i / 4];
        }
        return tmp;

    }

    public byte[] decode(byte[] data){
        byte[] tmpResult = new byte[data.length];
        byte[] blok = new byte[16];

        for(int i=0; i<data.length;){
            for(int j=0; j<16;j++) blok[j] = data[i++];
            blok = decipher(blok);
            System.arraycopy(blok,0,tmpResult,i-16,blok.length);
        }
        int cnt = 0;
        for(int i=1;i<17;i+=2){
            if(tmpResult[tmpResult.length - i] == 0 && tmpResult[tmpResult.length - i - 1] == 0)
                cnt += 2;
            else break;
        }
        byte[] result = new byte[tmpResult.length - cnt];
        System.arraycopy(tmpResult,0,result,0,tmpResult.length - cnt);
        return result;
    }

    /* Four main methods used in encipher method */
    public byte[][] subBytes(byte[][] data) {
        byte [][] modifiedTable = new byte[nb][nb];
        for (int i = 0; i < nb; i++) {
            for (int j = 0; j < nb; j++) {
                //do modified table przypisywane sa odpowiednie wartosci, ktore w oryginalnej tablicy zastepowane bylyby odpowiednimi wartosciami z tabeli SBOX
                modifiedTable[j][i] = substitutedByte(data[j][i]);
            }
        }
        return modifiedTable;
    }

    public byte[][] shiftRows(byte [][] data) {
        //przesuwanie bajtow w lewo: w 2 rzedzie o jeden, w 3 o dwa, w 4 o trzy
        byte [][] modifiedTable = new byte[nb][nb];
        for (int i = 0; i < nb; i++) {
            for (int j = 0; j < nb; j++) {
                if (i == 0) {
                    modifiedTable[i][j] = data[i][j];
                } else {
                    int columnIndex = j - i;
                    if (columnIndex < 0) {
                        columnIndex = nb + columnIndex;
                    }
                    modifiedTable[i][columnIndex] = data[i][j];
                }
            }
        }
        return modifiedTable;
    }
    public byte[][] mixColumns(byte[][] data) {
        //przemnozenie wszytskich kolumn macierzy przez stala macierz
        byte[][] state = new byte[nb][nb];
        int[] column = new int[nb];
        byte b02 = (byte)0x02, b03 = (byte)0x03;
        for (int i = 0; i < nb; i++)
        {
            column[0] = ((finiteFieldMultiplication(b02, data[0][i]) ^ finiteFieldMultiplication(b03, data[1][i]))
                    ^ (data[2][i]  ^ data[3][i]));
            column[1] = (data[0][i]  ^ finiteFieldMultiplication(b02, data[1][i])
                    ^ finiteFieldMultiplication(b03, data[2][i]) ^ data[3][i]);
            column[2] = (data[0][i]  ^ data[1][i]
                    ^ finiteFieldMultiplication(b02, data[2][i]) ^ finiteFieldMultiplication(b03, data[3][i]));
            column[3] = (finiteFieldMultiplication(b03, data[0][i]) ^ data[1][i]
                    ^ data[2][i]  ^ finiteFieldMultiplication(b02, data[3][i]));
            for (int j = 0; j < nb; j++) {
                state[j][i] = (byte) column[j];
            }
        }
        return state;
    }

    public byte[][] addRoundKey(byte[][] data, int round) {
        //dodanie XOR wszytskich bajtow macierzy do bajtow podklucza wlasciwego
        byte[][] modifiedTable = new byte[nb][nb];
        byte[][] keySchedule = expandKey();
        for (int i = 0; i < nb; i++) {
            for (int j = 0; j < nb; j++) {
                modifiedTable[j][i] = (byte) (data[j][i] ^ keySchedule[j][nb * round + i]);
            }
        }
        return  modifiedTable;
    }

    /* Three main methods for decipher method */

    public byte[][] invSubBytes(byte[][] data) {
        byte [][] modifiedTable = new byte[nb][nb];
        for (int i = 0; i < nb; i++) {
            for (int j = 0; j < nb; j++) {
                modifiedTable[j][i] = invSubstitutedByte(data[j][i]);
            }
        }
        return modifiedTable;
    }
    public byte[][] invShiftRows(byte[][] data) {
        byte [][] modifiedTable = new byte[nb][nb];
        for (int i = 0; i < nb; i++) {
            for (int j = 0; j < nb; j++) {
                if (i == 0) {
                    modifiedTable[i][j] = data[i][j];
                } else {
                    int columnIndex = j - i;
                    if (columnIndex < 0) {
                        columnIndex = nb + columnIndex;
                    }
                    modifiedTable[i][j] = data[i][columnIndex];
                }
            }
        }
        return modifiedTable;
    }
    public byte[][] invMixColumns(byte[][] data) {
        byte[][] state = new byte[nb][nb];
        int[] column = new int[nb];
        byte b02 = (byte)0x0e, b03 = (byte)0x0b, b04 = (byte)0x0d, b05 = (byte)0x09;
        for (int i = 0; i < nb; i++)
        {
            column[0] = finiteFieldMultiplication(b02, data[0][i]) ^ finiteFieldMultiplication(b03, data[1][i])
                    ^ finiteFieldMultiplication(b04, data[2][i])  ^ finiteFieldMultiplication(b05, data[3][i]);
            column[1] = finiteFieldMultiplication(b05, data[0][i]) ^ finiteFieldMultiplication(b02, data[1][i])
                    ^ finiteFieldMultiplication(b03, data[2][i])  ^ finiteFieldMultiplication(b04, data[3][i]);
            column[2] = finiteFieldMultiplication(b04, data[0][i]) ^ finiteFieldMultiplication(b05, data[1][i])
                    ^ finiteFieldMultiplication(b02, data[2][i])  ^ finiteFieldMultiplication(b03, data[3][i]);
            column[3] = finiteFieldMultiplication(b03, data[0][i]) ^ finiteFieldMultiplication(b04, data[1][i])
                    ^ finiteFieldMultiplication(b05, data[2][i])  ^ finiteFieldMultiplication(b02, data[3][i]);
            for (int j = 0; j < 4; j++) {
                state[j][i] = (byte) (column[j]);
            }
        }
        return state;
    }



    /* Key expansion method */

    public byte[][] expandKey() {
        byte[][] cipherKey = oneDimensionalArrayConversion(key, nb, nk);
        byte[][] extendedKey = new byte[nb][(nr + 1) * nb];
        for (int i = 0; i < nk; i++) {
            for (int j = 0; j < nb; j++) {
                extendedKey[j][i] = cipherKey[j][i];
            }
        }
        for (int i = nk; i < ((nr + 1) * nb); i++) {
            byte[] temp = new byte[] {
                    extendedKey[0][i - 1], extendedKey[1][i - 1], extendedKey[2][i - 1], extendedKey[3][i - 1]};
            if (i % nk == 0) {
                temp = wordOperation(temp, i);
            } else if (nk > 6 & i % nk == 4) {
                temp = subWord(temp);
            }
            for (int j = 0; j < nb; j++) {
                extendedKey[j][i] = (byte) (extendedKey[j][i - nk] ^ temp[j]);
            }
        }
        return extendedKey;
    }

    /* Substitute Box used by subBytes() function*/
    public int[][] sBox = {
            {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76},
            {0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0},
            {0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15},
            {0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75},
            {0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84},
            {0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf},
            {0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8},
            {0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2},
            {0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},
            {0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb},
            {0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79},
            {0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08},
            {0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a},
            {0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e},
            {0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf},
            {0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16}};

    /* Substitute Box used by invSubBytes() function*/
    public int [][] invSBox = {
            {0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb},
            {0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb},
            {0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e},
            {0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25},
            {0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92},
            {0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84},
            {0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06},
            {0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b},
            {0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73},
            {0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e},
            {0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b},
            {0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4},
            {0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f},
            {0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef},
            {0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61},
            {0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d}};

    /* Methods implemented for refactoring purposes */
    public byte[] getKey() {
        return key;
    }

    public void setKey(byte[] key) {
        this.key = key;
    }

    public byte[][] oneDimensionalArrayConversion(byte[] data, int y, int x) {
        byte [][] state = new byte[y][x];
        for (int i = 0; i < x; i++) {
            for (int j = 0; j < y; j++) {
                state[j][i] = data[(i * y) + j];
            }
        }
        return state;
    }

    public void generateKey() {
        BigInteger generatedKey = new BigInteger(nk * 32, new Random());
        setKey(generatedKey.toByteArray());
    }

    private byte substitutedByte(byte b) {
        //uzyskanie indeksow, aby z tablicy SBOX wybrac odpowiednie wartosci; higherbits to 4 starsze bity, lowerbits to 4 mlodsze bity z danej wejsciowej b
        byte higherBits = (byte) ((byte) (b >> 4) & 0x0f);
        byte lowerBits = (byte) (b & 0x0f);
        return (byte) sBox[higherBits][lowerBits];
    }

    private byte invSubstitutedByte(byte b) {
        byte higherBits = (byte) ((byte) (b >> 4) & 0x0f);
        byte lowerBits = (byte) (b & 0x0f);
        return (byte) invSBox[higherBits][lowerBits];
    }

    private byte finiteFieldMultiplication(byte a, byte b) {
        byte p = 0;

        for (int counter = 0; counter < 8; counter++) {
            if ((b & 1) != 0) {
                p ^= a;
            }

            boolean hi_bit_set = (a & 0x80) != 0;
            a <<= 1;
            if (hi_bit_set) {
                a ^= 0x1B; /* x^8 + x^4 + x^3 + x + 1 */
            }
            b >>= 1;
        }

        return p;
    }

    public byte[] subWord(byte[] word) {
        byte[] modifiedWord = new byte[nb];
        for (int i = 0; i < nb; i++) {
            modifiedWord[i] = substitutedByte(word[i]);
        }
        return modifiedWord;
    }

    public byte[] rotWord(byte[] word) {
        byte[] modifiedWord = new byte[nb];
        if (nb - 1 >= 0) {
            System.arraycopy(word, 1, modifiedWord, 0, nb - 1);
        }
        modifiedWord[nb - 1] = word[0];

        return modifiedWord;
    }

    public byte getRcon(int round) {
        byte rcon = 0x00;

        if (round == 1) {
            rcon = 0x01;
        } else if (round > 1 & round < 9) {
            rcon = (byte) (2 * getRcon(round - 1));
        } else {
            if (round == 9) {
                rcon = 0x1b;
            } else if (round == 10) {
                rcon = 0x36;
            }
        }
        return rcon;
    }

    public byte[] wordOperation(byte[] word, int round) {
        byte[] rcon = new byte[] {
                getRcon(round / nk), (byte) 0x00, (byte) 0x00, (byte) 0x00
        };
        byte[] temp = subWord(rotWord(word));
        for (int i = 0; i < nb; i++) {
            temp[i] = (byte) (temp[i] ^ rcon[i]);
        }
        return temp;
    }

}



