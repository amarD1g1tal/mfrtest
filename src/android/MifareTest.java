
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
//import android.util.SparseArray;
import android.widget.Toast;
import android.nfc.TagLostException;

public class MifareTest extends CordovaPlugin{
        
        /**
         * Placeholder for not found keys.
         */
        public static final String NO_KEY = "------------";
        /**
         * Placeholder for unreadable blocks.
         */
        public static final String NO_DATA = "--------------------------------";
        
        private String[] mRawDump;
        
        public String[] sectorData;
        
        public static final String ACTION_TAG_READ_SECTOR = "readTag"; 
        
        @Override
        public boolean execute(String action, JSONArray args, CallbackContext callbackContext) throws JSONException {
                try {
                        if (ACTION_TAG_READ_SECTOR.equals(action)) { 
                                readTag();
                                String str = Arrays.toString(mRawDump);
                                callbackContext.success(str);
                                return true;
                        }
                }catch(Exception e) {
                        System.err.println("Exception: " + e.getMessage());
                        callbackContext.error(e.getMessage());
                        return false;
                } 
                return true;
        }
        
        /**
        * Triggered by {@link #onActivityResult(int, int, Intent)}
        * this method starts a worker thread that first reads the tag and then
        * calls {@link #createTagDump(SparseArray)}.
        */
       private void readTag() {
           mRawDump=null;
           final MCReader reader = checkForTagAndCreateReader(this);
           if (reader == null) {
               return;
           }
           new Thread(new Runnable() {
               @Override
               public void run() {
                   // Get key map from glob. variable.
                   mRawDump = reader.readSector(0,"FFFFFFFFFFFF",false);

                   reader.close();
               }
           }).start();
       }
       
       /**
        * Create a connected {@link MCReader} if there is a present MIFARE Classic
        * tag. If there is no MIFARE Classic tag an error
        * message will be displayed to the user.
        * @param context The Context in which the error Toast will be shown.
        * @return A connected {@link MCReader} or "null" if no tag was present.
        */
       public MCReader checkForTagAndCreateReader(Context context) {
           MCReader reader;
           boolean tagLost = false;
           // Check for tag.
           if (mTag != null && (reader = MCReader.get(mTag)) != null) {
               try {
                   reader.connect();
               } catch (Exception e) {
                   tagLost = true;
               }
               if (!tagLost && !reader.isConnected()) {
                   reader.close();
                   tagLost = true;
               }
               if (!tagLost) {
                   return reader;
               }
           }

           // Error. The tag is gone.
           Toast.makeText(context, R.string.info_no_tag_found,
                   Toast.LENGTH_LONG).show();
           return null;
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
