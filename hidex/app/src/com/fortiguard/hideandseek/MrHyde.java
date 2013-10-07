package com.fortiguard.hideandseek;

import android.util.Log;
import java.io.*;
import android.content.res.AssetManager;
import android.content.Context;
import java.lang.reflect.Method;
import java.lang.reflect.InvocationTargetException;
import java.util.zip.Adler32;
import java.security.*;

public class MrHyde {
    private Context context;
    private static final int JEKYLL = 0;
    private static final int MRHYDE = 1;
    private static final String JEKYLL_TEXT = "I am Dr Jekyll";
    private static final String MRHYDE_TEXT = "** I am Mr Hyde **";
    private static final String IDENTITY_FILENAME = "identity";

    public static String bytesToHex(byte[] bytes, int offset, int length) {
        final char[] hexArray = {'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};
	char[] hexChars = new char[length * 2];
	int v;
	for ( int j = offset; j < length; j++ ) {
	    v = bytes[j] & 0xFF;
	    hexChars[j * 2] = hexArray[v >>> 4];
	    hexChars[j * 2 + 1] = hexArray[v & 0x0F];
	}
	return new String(hexChars);
    }

    public MrHyde(Context ctx) { 
	Log.i("HideAndSeek", "In MrHyde constructor");
	context = ctx;
    }

    public String whoami() {
	Log.i("HideAndSeek", "In whoami()");
	try {
	    File file = new File(context.getFilesDir(), IDENTITY_FILENAME);
	    Log.i("HideAndSeek", "whoami(): file: "+file.getAbsolutePath());
	    FileInputStream fin = new FileInputStream(file);
	    int data = fin.read();
	    if (data == MRHYDE) {
		Log.i("HideAndSeek", "whoami(): returning MRHYDE_TEXT");
		return MRHYDE_TEXT;
	    }
	    fin.close();
	}
	catch(Exception exp) {
	    Log.i("HideAndSeek", "whoami(): exception caught: "+exp.toString());
	}
	Log.i("HideAndSeek", "whoami(): returning JEKYLL_TEXT");
	return JEKYLL_TEXT;
    }

    // this method will be hidden
    public void thisishidden(boolean ismrhyde) {
	Log.i("HideAndSeek", "In thisishidden(): set mrhyde="+ismrhyde);
	try {
	    File dir;
	    if (context !=null) {
		Log.i("HideAndSeek", "thisishidden(): context="+context.toString());
		dir = context.getFilesDir();
	    } else {
		Log.i("HideAndSeek", "thisishidden(): context is null");
		dir = new File("/data/data/com.fortiguard.hideandseek/files/");
	    }
	    Log.i("HideAndSeek", "thisishidden(): dir="+dir);
	    File f = new File(dir, IDENTITY_FILENAME);
	    Log.i("HideAndSeek", "thisishidden(): file: "+f.getAbsolutePath());
	    if (f.exists()) {
		f.delete();
	    }
	    FileOutputStream fos = new FileOutputStream(f);
	    if (ismrhyde) {
		fos.write(MRHYDE);
	    } else {
		fos.write(JEKYLL);
	    }
	    fos.close();
	}
	catch(Exception exp) {
	    Log.i("HideAndSeek", "thisishidden(): exception caught: "+exp.toString());
	}
	Log.i("HideAndSeek", "thisishidden(): done");
    }


    public InputStream openNonAsset(String paramString) {
	try   {
	    Class localClass = Class.forName("android.content.res.AssetManager");
	    Class[] arrayOfClass = new Class[1];
	    arrayOfClass[0] = String.class;
	    Method localMethod = localClass.getMethod("openNonAsset", arrayOfClass);
	    AssetManager localAssetManager = this.context.getAssets();
	    Object[] arrayOfObject = new Object[1];
	    arrayOfObject[0] = paramString;
	    InputStream localInputStream = (InputStream)localMethod.invoke(localAssetManager, arrayOfObject);
	    return localInputStream;
	}
	catch (Exception localException)  {
	    while (true)    {
		localException.printStackTrace();
		InputStream localInputStream = null;
	    }
	}
    }


    public void invokeHidden() {
	int dexlength = 11708;
	byte[] dex = new byte[dexlength];
	InputStream localInputStream = openNonAsset("classes.dex");
	try {
	    dexlength = localInputStream.read(dex, 0, dexlength);
	    Log.i("HideAndSeek", "invokeHidden(): read "+dexlength + " bytes");

	    // modify dex here and un-hide hidden method
	    int patch_index = 0x2c99;
	    dex[patch_index++]= 1; // method_idx
	    dex[patch_index++]= 1; // access flag
	    dex[patch_index++]= (byte)0xcc; // code offset
	    dex[patch_index++]= (byte)0x28;
	    dex[patch_index++]= 1;

	    MessageDigest digest;
	    digest = MessageDigest.getInstance("SHA-1");
	    digest.reset();
	    digest.update(dex, 32, dexlength-32);
	    digest.digest(dex, 12, 20);
	    Log.i("HideAndSeek", "invokeHidden(): redigesting");

	    Adler32 checksum = new Adler32();
	    checksum.reset();
	    checksum.update(dex, 12, dexlength-12);
	    int sum = (int)checksum.getValue();
	    dex[8] = (byte)sum;
	    dex[9] = (byte)(sum >> 8);
	    dex[10] = (byte)(sum >> 16);
	    dex[11] = (byte)(sum >> 24);
	    Log.i("HideAndSeek", "invokeHidden(): checksum");

	    // invoke: 
	    // native private static int openDexFile(byte[] fileContents);
	    Class dexFileClass = context.getClassLoader().loadClass("dalvik.system.DexFile");
	    Method[] arrayOfMethod = Class.forName("dalvik.system.DexFile").getDeclaredMethods();
	    Method openDexFileMethod = null;
	    Method defineClassMethod = null;
	    int cookie = 0;
	    Log.i("HideAndSeek", "invokeHidden(): openDexFile");

	    for (int i=0; i< arrayOfMethod.length; i++) {
		if (arrayOfMethod[i].getName().equalsIgnoreCase("openDexFile") && arrayOfMethod[i].getParameterTypes().length == 1) {
		    openDexFileMethod = arrayOfMethod[i];
		    openDexFileMethod.setAccessible(true);
		    Log.i("HideAndSeek", "openDexFile found");
		}

		if (arrayOfMethod[i].getName().equalsIgnoreCase("defineClass") && arrayOfMethod[i].getParameterTypes().length == 3) {
		    defineClassMethod = arrayOfMethod[i];
		    defineClassMethod.setAccessible(true);
		    Log.i("HideAndSeek", "defineClass found");
		}
	    }
	    
	    Object[] arrayOfObject = new Object[1];
	    arrayOfObject[0] = dex;
	    Log.i("HideAndSeek", "dex header: "+MrHyde.bytesToHex(dex,0, 34));

	    if (openDexFileMethod != null) {
		cookie = ((Integer)openDexFileMethod.invoke(dexFileClass, arrayOfObject)).intValue();
		Log.i("HideAndSeek", "openDexFile invoked. cookie="+cookie);
	    }

	    // invoke: private native static Class defineClass(String name, ClassLoader loader, int cookie);
	    Object[] params = new Object[3];
	    params[0] = "com/fortiguard/hideandseek/MrHyde";
	    params[1] = dexFileClass.getClassLoader();
	    params[2] = Integer.valueOf(cookie);
	    Class patchedHyde = null;
	    Log.i("HideAndSeek", "retrieving patched MrHyde class");
	    if (defineClassMethod != null) {
		patchedHyde = (Class) defineClassMethod.invoke(dexFileClass, params);
	    }

	    // invoke:   public void thisishidden() 
	    Method thisishiddenMethod = null;
	    Log.i("HideAndSeek", "getting methods in patched MrHyde");
	    Method[] allMethods = patchedHyde.getDeclaredMethods();
	    Log.i("HideAndSeek", "parsing methods in patched MrHyde:");
	    
	    for (int j=0; j<allMethods.length; j++) {
		Log.i("HideAndSeek", "patched MrHyde method: "+allMethods[j].getName());
		if (allMethods[j].getName().equalsIgnoreCase("thisishidden")) {
		    thisishiddenMethod = allMethods[j];
		    Log.i("HideAndSeek", "thisishidden() method has been found");
		}
	    }
	    Log.i("HideAndSeek", "parsing done.");
	    
	    // invoke: public void thisishidden(boolean);
	    if (thisishiddenMethod != null) {
		Object[] arg= new Object[1];
		Log.i("HideAndSeek", "before new Instance()");
		Object obj = patchedHyde.getDeclaredConstructor(Context.class).newInstance(context);
		Log.i("HideAndSeek", "after new Instance");
		arg[0] = Boolean.valueOf(true);
		Log.i("HideAndSeek", "invoking thisishidden() with arg=true");
		thisishiddenMethod.invoke(obj, arg);
	    } else {
		Log.i("HideAndSeek", "thisishidden() not found");
	    }

	}
	catch(Exception exp) {
	    Log.e("HideAndSeek", "Exception caught in invokeHidden(): "+exp.toString());
	}
    }


	
}
