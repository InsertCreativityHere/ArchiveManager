
package com.insertcreativity.archive;

import java.awt.Dimension;
import java.awt.Toolkit;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.JFrame;

public class Main
{
    private static final Charset UTF_8 = StandardCharsets.UTF_8;
    private static final int fileBufferSize = 65536;
    private static final int filenamePaddingLength = 120;
    private static final long folderLength = 5723492852L;
    private static final MessageDigest hasher;
    private static final Cipher cipher;
    private static final Key key;
    static
    {
        MessageDigest md = null;
        Cipher c = null;
        try
        {
            md = MessageDigest.getInstance("SHA-256");
            c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        } catch(NoSuchAlgorithmException|NoSuchPaddingException cryptoInitException)
        {
            cryptoInitException.printStackTrace();
            System.exit(2);
        }
        hasher = md;
        cipher = c;
        
        String keyString = "InsertKeyHere";
        key = new SecretKeySpec(hasher.digest(keyString.getBytes(UTF_8)), "AES");
    }
    
    private static final byte[] getVectorFromSize(long size)
    {
        //Allocate an array for storing the size bytes
        byte[] sizeBytes = new byte[8];
        //Convert the long into bytes and store them
        for(int i = 0; i < 8; i++)
        {
            sizeBytes[i] = (byte)((size >> (i * 8)) & 0xff);
        }
        
        //Hash the bytes
        byte[] hashBytes = hasher.digest(sizeBytes);
        //Allocate an array for storing the initialization vector
        byte[] resultBytes = new byte[16];
        //Compute the vector bytes by adding together consecutive hash bytes
        for(int i = 0; i < 16; i++)
        {
            resultBytes[i] = (byte)(hashBytes[2 * i] + hashBytes[(2 * i) + 1]);
        }
        
        return resultBytes;
    }
    
    private static final byte[] getVectorFromName(String name)
    {
        //Hash the name string's bytes
        byte[] hashBytes = hasher.digest(name.getBytes(UTF_8));
        //Allocate an array for storing the initialization vector
        byte[] resultBytes = new byte[16];
        //Compute the vector bytes by adding together consecutive hash bytes
        for(int i = 0; i < 16; i++)
        {
            resultBytes[i] = (byte)(hashBytes[2 * i] + hashBytes[(2 * i) + 1]);
        }
        
        return resultBytes;
    }
    
    private static final void encrypt(File source, File dest) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException
    {
        //===Encrypt the file's name===//
        //Calculate the size of the file after encryption
        long size = ((source.isDirectory())? folderLength : ((source.length() / 16) + 1) * 16);
        //Initialize the cipher with a size-hash vector
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(getVectorFromSize(size)));
        //Pad the filename with '?' characters
        String paddedName = source.getName() + (new String(new char[filenamePaddingLength - source.getName().length()]).replaceAll("\0", "\\?"));
        //Encrypt the filename and convert it to a base64 string
        String name = Base64.getEncoder().encodeToString(cipher.doFinal(paddedName.getBytes(UTF_8))).replaceAll("/", "-");
        File encrypted = new File(dest, name);
        
        if(source.isDirectory())
        {
            //Create the encrypted folder
            if(!encrypted.mkdir())
            {
                throw new IOException("Failed to create encrypted folder.");
            }
            
            //===Encrypt the folder's content===//
            for(File file : source.listFiles())
            {
                encrypt(file, encrypted);
            }
        } else{
            //Create the encrypted file
            if(!encrypted.createNewFile())
            {
                throw new IOException("Failed to create encrypted file.");
            }
            
            //===Encrypt the file's content===//
            //Initialize the cipher with a name-hash vector
            cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(getVectorFromName(source.getName())));
            //Perform the encryption
            byte[] buffer = new byte[fileBufferSize];
            int count;
            try(CipherOutputStream cipherOutputStream = new CipherOutputStream(new FileOutputStream(encrypted), cipher))
            {
                try(FileInputStream fileInputStream = new FileInputStream(source))
                {
                    while((count = fileInputStream.read(buffer)) > 0)
                    {
                        cipherOutputStream.write(buffer, 0, count);
                    }
                }
            }
        }
    }
    
    private static final void decrypt(File source, File dest) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException
    {
        //===Decrypt the file's name===//
        //Calculate the size of the file
        long size = ((source.isDirectory())? folderLength : source.length());
        //Initialize the cipher with a size-hash vector
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(getVectorFromSize(size)));
        //Decrypt the file name and remove any padding
        String name = new String(cipher.doFinal(Base64.getDecoder().decode(source.getName().replaceAll("-", "/"))), UTF_8);
        File decrypted = new File(dest, name.replaceAll("\\?", ""));

        if(source.isDirectory())
        {
            //Create the decrypted folder
            if(!decrypted.mkdir())
            {
                throw new IOException("Failed to create encrypted folder.");
            }
            
            //===Decrypt the folder's content===//
            for(File file : source.listFiles())
            {
                decrypt(file, decrypted);
            }
        } else{
            //Create the decrypted file
            if(!decrypted.createNewFile())
            {
                throw new IOException("Failed to create encrypted file.");
            }
            
            //===Decrypt the file's content===//
            //Initialize the cipher with a name-hash vector
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(getVectorFromName(name)));
            //Perform the decryption
            byte[] buffer = new byte[fileBufferSize];
            int count;
            try(CipherOutputStream cipherOutputStream = new CipherOutputStream(new FileOutputStream(decrypted), cipher))
            {
                try(FileInputStream fileInputStream = new FileInputStream(source))
                {
                    while((count = fileInputStream.read(buffer)) > 0)
                    {
                        cipherOutputStream.write(buffer, 0, count);
                    }
                }
            }
        }
    }
}
