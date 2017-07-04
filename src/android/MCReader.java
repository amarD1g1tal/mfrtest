package net.digitaledu.mifaretest;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;

import android.content.Context;
import android.nfc.Tag;
import android.nfc.TagLostException;
import android.nfc.tech.MifareClassic;
import android.nfc.tech.NfcA;
import android.os.Bundle;
import android.os.IBinder;
import android.os.Parcel;
import android.util.Log;
//import android.util.SparseArray;
//import android.widget.Toast;

//import de.syss.MifareClassicTool.Activities.Preferences.Preference;

/**
 * Provides functions to read/write/analyze a MIFARE Classic tag.
 * @author Gerhard Klostermeier
 */
public class MCReader {

    /**
     * Placeholder for not found keys.
     */
    public static final String NO_KEY = "------------";
    /**
     * Placeholder for unreadable blocks.
     */
    public static final String NO_DATA = "--------------------------------";

    private final MifareClassic mMFC;
//    private SparseArray<byte[][]> mKeyMap = new SparseArray<byte[][]>();
//    private int mKeyMapStatus = 0;
//    private int mLastSector = -1;
//    private int mFirstSector = 0;
//    private ArrayList<byte[]> mKeysWithOrder;

    /**
     * Initialize a MIFARE Classic reader for the given tag.
     * @param tag The tag to operate on.
     */
    private MCReader(Tag tag) {
        MifareClassic tmpMFC = null;
        try {
            tmpMFC = MifareClassic.get(tag);
        } catch (Exception e) {
            Log.e("String=>", "Could not create MIFARE Classic reader for the"
                    + "provided tag (even after patching it).");
//            throw e;
        }
        mMFC = tmpMFC;
    }

    /**
     * Get new instance of {@link MCReader}.
     * If the tag is "null" or if it is not a MIFARE Classic tag, "null"
     * will be returned.
     * @param tag The tag to operate on.
     * @return {@link MCReader} object or "null" if tag is "null" or tag is
     * not MIFARE Classic.
     */
    public static MCReader get(Tag tag) {
        MCReader mcr = null;
        if (tag != null) {
            mcr = new MCReader(tag);
            if (!mcr.isMifareClassic()) {
                return null;
            }
        }
        return mcr;
    }

    /**
     * Read as much as possible from a sector with the given key.
     * Best results are gained from a valid key B (except key B is marked as
     * readable in the access conditions).
     * @param sectorIndex Index of the Sector to read. (For MIFARE Classic 1K:
     * 0-63)
     * @param key Key for authentication.
     * @param useAsKeyB If true, key will be treated as key B
     * for authentication.
     * @return Array of blocks (index 0-3 or 0-15). If a block or a key is
     * marked with {@link #NO_DATA} or {@link #NO_KEY}
     * it means that this data could not be read or found. On authentication error
     * "null" will be returned.
     * @throws TagLostException When connection with/to tag is lost.
     * @see #mergeSectorData(String[], String[])
     */
    public String[] readSector(int sectorIndex, String keyString,
            boolean useAsKeyB) throws TagLostException {
        
        byte[] key=MifareTest.hexStringToByteArray(keyString);
        
        boolean auth = authenticate(sectorIndex, key, useAsKeyB);
        String[] ret = null;
        // Read sector.
        if (auth) {
            // Read all blocks.
            ArrayList<String> blocks = new ArrayList<String>();
            int firstBlock = mMFC.sectorToBlock(sectorIndex);
            int lastBlock = firstBlock + 4;
            if (mMFC.getSize() == MifareClassic.SIZE_4K
                    && sectorIndex > 31) {
                lastBlock = firstBlock + 16;
            }
            for (int i = firstBlock; i < lastBlock; i++) {
                try {
                    byte blockBytes[] = mMFC.readBlock(i);
                    // mMFC.readBlock(i) must return 16 bytes or throw an error.
                    // At least this is what the documentation says.
                    // On Samsung's Galaxy S5 and Sony's Xperia Z2 however, it
                    // sometimes returns < 16 bytes for unknown reasons.
                    // Update: Aaand sometimes it returns more than 16 bytes...
                    // The appended byte(s) are 0x00.
                    if (blockBytes.length < 16) {
                        throw new IOException();
                    }
                    if (blockBytes.length > 16) {
                        byte[] blockBytesTmp = Arrays.copyOf(blockBytes,16);
                        blockBytes = blockBytesTmp;
                    }

                    blocks.add(MifareTest.byte2HexString(blockBytes));
                } catch (TagLostException e) {
                    throw e;
                } catch (IOException e) {
                    // Could not read block.
                    // (Maybe due to key/authentication method.)
                    Log.d("String=>", "(Recoverable) Error while reading block "
                            + i + " from tag.");
                    blocks.add(NO_DATA);
                    if (!mMFC.isConnected()) {
                        throw new TagLostException(
                                "Tag removed during readSector(...)");
                    }
                    // After an error, a re-authentication is needed.
                    authenticate(sectorIndex, key, useAsKeyB);
                }
            }
            ret = blocks.toArray(new String[blocks.size()]);
            int last = ret.length -1;

            // Merge key in last block (sector trailer).
            if (!useAsKeyB) {
                if (isKeyBReadable(MifareTest.hexStringToByteArray(
                        ret[last].substring(12, 20)))) {
                    ret[last] = MifareTest.byte2HexString(key)
                            + ret[last].substring(12, 32);
                } else {
                    ret[last] = MifareTest.byte2HexString(key)
                            + ret[last].substring(12, 20) + NO_KEY;
                }
            } else {
                if (ret[0].equals(NO_DATA)) {
                    // If Key B may be read in the corresponding Sector Trailer,
                    // it cannot serve for authentication (according to NXP).
                    // What they mean is that you can authenticate successfully,
                    // but can not read data. In this case the
                    // readBlock() result is 0 for each block.
                    ret = null;
                } else {
                    ret[last] = NO_KEY + ret[last].substring(12, 20)
                            + MifareTest.byte2HexString(key);
                }
            }
        }
        return ret;
    }

    /**
     * Authenticate with given sector of the tag.
     * @param sectorIndex The sector with which to authenticate.
     * @param key Key for the authentication.
     * @param useAsKeyB If true, key will be treated as key B
     * for authentication.
     * @return True if authentication was successful. False otherwise.
     */
    private boolean authenticate(int sectorIndex, byte[] key,
            boolean useAsKeyB) {
        try {
            if (!useAsKeyB) {
                // Key A.
                return mMFC.authenticateSectorWithKeyA(sectorIndex, key);
            } else {
                // Key B.
                return mMFC.authenticateSectorWithKeyB(sectorIndex, key);
            }
        } catch (IOException e) {
            Log.d("String=>", "Error authenticating with tag.");
        }
        return false;
    }

    /**
     * Check if key B is readable.
     * Key B is readable for the following configurations:
     * <ul>
     * <li>C1 = 0, C2 = 0, C3 = 0</li>
     * <li>C1 = 0, C2 = 0, C3 = 1</li>
     * <li>C1 = 0, C2 = 1, C3 = 0</li>
     * </ul>
     * @param ac The access conditions (4 bytes).
     * @return True if key B is readable. False otherwise.
     */
    private boolean isKeyBReadable(byte[] ac) {
        byte c1 = (byte) ((ac[1] & 0x80) >>> 7);
        byte c2 = (byte) ((ac[2] & 0x08) >>> 3);
        byte c3 = (byte) ((ac[2] & 0x80) >>> 7);
        return c1 == 0
                && (c2 == 0 && c3 == 0)
                || (c2 == 1 && c3 == 0)
                || (c2 == 0 && c3 == 1);
    }

    public boolean isMifareClassic() {
        return mMFC != null;
    }

    /**
     * Return the size of the MIFARE Classic tag in bits.
     * (e.g. MIFARE Classic 1k = 1024)
     * @return The size of the current tag.
     */
    public int getSize() {
        return mMFC.getSize();
    }

    /**
     * Return the block count of the MIFARE Classic tag.
     * @return The block count of the current tag.
     */
    public int getBlockCount() {
        return mMFC.getBlockCount();
    }

    /**
     * Return the block count in a specific sector.
     * @param sectorIndex Index of a sector.
     * @return Block count in given sector.
     */
    public int getBlockCountInSector(int sectorIndex) {
        return mMFC.getBlockCountInSector(sectorIndex);
    }

    /**
     * Check if the reader is connected to the tag.
     * @return True if the reader is connected. False otherwise.
     */
    public boolean isConnected() {
        return mMFC.isConnected();
    }

    /**
     * Connect the reader to the tag.
     */
    public void connect() throws IOException {
        try {
            mMFC.connect();
        } catch (IOException e) {
            Log.d("String=>", "Error while connecting to tag.");
            throw e;
        }
    }

    /**
     * Close the connection between reader and tag.
     */
    public void close() {
        try {
            mMFC.close();
        }
        catch (IOException e) {
            Log.d("String=>", "Error on closing tag.");
        }
    }
}
