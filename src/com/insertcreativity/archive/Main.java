
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
    public static void main(String[] args)
    {
        switch(args[0])
        {
            case("init"):
                initializeArchive(args);
            break;
                
        }
    }
    
    private static final initializeArchive(String[] args)
    {
        
    }
    
    
    
    
    
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
            c = Cipher.getInstance("AES/CTR/NoPadding");
        } catch(NoSuchAlgorithmException|NoSuchPaddingException cryptoInitException)
        {
            cryptoInitException.printStackTrace();
            System.exit(2);
        }
        hasher = md;
        cipher = c;
        
        String keyString = "InsertKeyHere";
        key = new SecretKeySpec(keyString.getBytes(UTF_8), "AES");
    }
    
    /**
     * Derives an initialization vector from a file length.
     * @param length The length of the file to compute an IV for.
     * @return A byte array representation of the file's IV.
    **/
    private final byte[] getIvFromLength(long length)
    {
        //Allocate an array for storing the length as bytes
        byte[] lengthBytes = new byte[8];
        //Convert the long into bytes and store them
        for(int i = 0; i < 8; i++)
        {
            lengthBytes[i] = (byte)((length >> (i * 8)) & 0xff);
        }
        
        //Hash the bytes
        byte[] hashBytes = hasher.digest(lengthBytes);
        //Allocate an array for storing the initialization vector
        byte[] iv = new byte[16];
        //Compute the IV bytes by adding together consecutive hash bytes
        for(int i = 0; i < 16; i++)
        {
            iv[i] = (byte)(hashBytes[2 * i] + hashBytes[(2 * i) + 1]);
        }
        
        return iv;
    }
    
    /**
     * Derives an initialization vector from a file length.
     * @param name The name of the file to compute an IV for.
     * @return A byte array representation of the file's IV.
    **/
    private final byte[] getIvFromName(String name)
    {
        //Encode the filename and hash it's bytes
        byte[] hashBytes = hasher.digest(name.getBytes(UTF_8));
        //Allocate an array for storing the initialization vector
        byte[] iv = new byte[16];
        //Compute the IV bytes by adding together consecutive hash bytes
        for(int i = 0; i < 16; i++)
        {
            iv[i] = (byte)(hashBytes[2 * i] + hashBytes[(2 * i) + 1]);
        }
        
        return iv;
    }
    
    private static final void encrypt(File source, File dest) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException
    {
        //===Encrypt the file's name===//
        //Calculate the size of the file after encryption
        long size = ((source.isDirectory())? folderLength : ((source.length() / 16) + 1) * 16);
        //Initialize the cipher with a size-hash vector
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(getIvFromLength(size)));
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
            cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(getIvFromName(source.getName())));
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
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(getIvFromLength(size)));
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
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(getIvFromName(name)));
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

    private static void createGraphics()
    {
        Toolkit toolkit = Toolkit.getDefaultToolkit();
        Dimension screenSize = toolkit.getScreenSize();
        
        JFrame frame = new JFrame("Austin's Archive Manager");
        frame.setDefaultCloseOperation(JFrame.DO_NOTHING_ON_CLOSE);
        
        frame.setSize((screenSize.width * 3) / 4, (screenSize.height * 3) / 4);
        frame.setLocationRelativeTo(null);
        
        frame.setVisible(true);
    }
}
