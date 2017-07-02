
package net.digitaledu.mifaretest;

import org.apache.cordova.*;
import org.json.JSONArray;
import org.json.JSONException;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.io.IOException;

import android.app.Activity;
import android.app.AlertDialog;
import android.app.Application;
import android.app.PendingIntent;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.content.pm.PackageManager.NameNotFoundException;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.MifareClassic;
import android.nfc.tech.NfcA;
import android.os.Build;
import android.os.Environment;
import android.preference.PreferenceManager;
//import android.support.v4.content.ContextCompat;
import android.text.SpannableString;
import android.text.style.ForegroundColorSpan;
import android.util.Log;
import android.util.SparseArray;
import android.widget.Toast;
import android.nfc.TagLostException;

public class MifareTest extends CordovaPlugin{
        
        private final MifareClassic mMFC;
        
        /**
         * Placeholder for not found keys.
         */
        public static final String NO_KEY = "------------";
        /**
         * Placeholder for unreadable blocks.
         */
        public static final String NO_DATA = "--------------------------------";
        
        public String[] sectorData;
        
        public static final String ACTION_TAG_READ_SECTOR = "readTag"; 
        
        @Override
        public boolean execute(String action, JSONArray args, CallbackContext callbackContext) throws JSONException {
                try {
                        if (ACTION_TAG_READ_SECTOR.equals(action)) { 
                                sectorData=readSector(0,"FFFFFFFFFFFF",false);
                                callbackContext.success("Successful");
                                return true;
                        }
                }catch(Exception e) {
                        System.err.println("Exception: " + e.getMessage());
                        callbackContext.error(e.getMessage());
                        return false;
                } 
                return true;
        }
        
        public String[] readSector(int sectorIndex, String keyString,
            boolean useAsKeyB) throws TagLostException {
            
            byte[] key = hexStringToByteArray(keyString);
            
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

                        blocks.add(byte2HexString(blockBytes));
                    } catch (TagLostException e) {
                        throw e;
                    } catch (IOException e) {
                        // Could not read block.
                        // (Maybe due to key/authentication method.)
                        Log.d("String=>", "(Recoverable) Error while reading block "
                                + i + " from tag.");
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
                    if (isKeyBReadable(hexStringToByteArray(
                            ret[last].substring(12, 20)))) {
                        ret[last] = byte2HexString(key)
                                + ret[last].substring(12, 32);
                    } else {
                        ret[last] = byte2HexString(key)
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
                                + byte2HexString(key);
                    }
                }
            }
            return ret;
        }
        
        /**
        * Convert a string of hex data into a byte array.
        * Original author is: Dave L. (http://stackoverflow.com/a/140861).
        * @param s The hex string to convert
        * @return An array of bytes with the values of the string.
        */
       public static byte[] hexStringToByteArray(String s) {
            int len = s.length();
            byte[] data = new byte[len / 2];
            try {
                for (int i = 0; i < len; i += 2) {
                    data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                                         + Character.digit(s.charAt(i+1), 16));
                }
            } catch (Exception e) {
                Log.d("String=>", "Argument(s) for hexStringToByteArray(String s)"
                        + "was not a hex string");
            }
            return data;
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
               if (!useAsKeyB) {
                   // Key A.
                   return mMFC.authenticateSectorWithKeyA(sectorIndex, key);
               } else {
                   // Key B.
                   return mMFC.authenticateSectorWithKeyB(sectorIndex, key);
               }
       }
       
       /**
     * Convert an array of bytes into a string of hex values.
     * @param bytes Bytes to convert.
     * @return The bytes in hex string format.
     */
    public static String byte2HexString(byte[] bytes) {
            String ret = "";
            if (bytes != null) {
                for (Byte b : bytes) {
                    ret += String.format("%02X", b.intValue() & 0xFF);
                }
            }
            return ret;
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
        
}

