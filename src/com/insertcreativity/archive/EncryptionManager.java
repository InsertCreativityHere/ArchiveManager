
package com.insertcreativity.archive;

import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.io.Serializable;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public final class EncryptionManager implements Serializable
{
    /**Prevent potential attackers from serializing this object by generating a random UID whenever this class is loaded.**/
    private static final long serialVersionUID;
    static{
        serialVersionUID = (new SecureRandom()).nextLong();
    }
    
    /**
     * Prevent potential attackers from cloning this object.
    **/
    public final Object clone() throws CloneNotSupportedException
    {
        throw new CloneNotSupportedException();
    }
    
    /**
     * Prevent potential attackers from serializing this object.
    **/
    private final void writeObject(ObjectOutputStream out) throws IOException
    {
        throw new IOException("Object cannot be serialized.");
    }
    
    /**
     * Prevent potential attackers from deserializing this object.
    **/
    private final void readObject(ObjectInputStream in) throws IOException
    {
        throw new IOException("Object cannot be serialized.");
    }
    
    /**The buffer size to use when encrypting data.**/
    private final int bufferSize = 65536;
    /**The initialization vector used by the encryption manager.**/
    private final BigInteger iv = new BigInteger(new byte[] {77, 97, 100, 105, 65, 117, 115, 116, 105, 110, 82, 97, 99, 104, 101, 108});
    /**Engine used for performing hash functions.**/
    private final MessageDigest hashEngine1;
    /**Engine used for performing hash functions.**/
    private final MessageDigest hashEngine2;
    /**Engine used for encrypting and decrypting data.**/
    private final Cipher encryptionEngine;
    /**Engine used for generating random variables.**/
    private final SecureRandom randomEngine;
    /**The character encoding scheme for the manager to use.**/
    private final Charset charset = StandardCharsets.UTF_16LE;
    
    /**
     * Creates a new encryption manager. Note that the provided key will be erased after the manager finishes initializing.
     * @param key Char array containing the secret key that the archive should use for encrypting/decrypting.
     * @return A new instance of an Encryption Manager initialized with the specified key. Or null if your system doesn't support the hash and encryption algorithms used internally.
    **/
    public static final EncryptionManager getInstance(char[] key)
    {
        try
        {
            return new EncryptionManager(key);
        } catch(NoSuchAlgorithmException|NoSuchPaddingException unsupportedCryptoException)
        {
            System.err.println("Your system doesn't provide support for either SHA-256 or AES-CTR.");
            unsupportedCryptoException.printStackTrace();
        } catch(InvalidKeyException|InvalidAlgorithmParameterException cryptoParameterException)
        {
            System.err.println("Parameter or Key provided was invalid!");
            cryptoParameterException.printStackTrace();
        }
        return null;
    }

    private EncryptionManager(char[] key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException
    {
        hashEngine1 = MessageDigest.getInstance("SHA-256");
        hashEngine2 = MessageDigest.getInstance("SHA-256");
        encryptionEngine = Cipher.getInstance("AES/CTR/NoPadding");
        
        CharBuffer cBuffer = CharBuffer.wrap(key);
        ByteBuffer bBuffer = charset.encode(cBuffer);
        encryptionEngine.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(hashEngine1.digest(bBuffer.array()), "AES"), new IvParameterSpec(iv.toByteArray()));
        Arrays.fill(bBuffer.array(), (byte)255);
        Arrays.fill(cBuffer.array(), '\255');
        
        randomEngine = SecureRandom.getInstanceStrong();
    }
    
    public final void seek(long offset)
    {
        
    }
    
    public final byte[] encryptStream(InputStream inputStream, OutputStream outputStream)
    {
        try
        {
            //Allocate arrays for holding the key and IV this stream will be encrypted with
            byte[] streamKey = new byte[32];
            byte[] streamIV = new byte[16];
            //Generate a random key and IV for the stream
            randomEngine.nextBytes(streamKey);
            randomEngine.nextBytes(streamIV);
            //Create a cipher for the stream and ensure the hash engines are flushed
            Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(streamKey, "AES"), new IvParameterSpec(streamIV));
            
            
            //===Encrypt the stream===//
        } catch(NoSuchAlgorithmException|NoSuchPaddingException unsupportedCryptoException)
        {
            System.err.println("Your system doesn't provide support for AES-CTR.");
            unsupportedCryptoException.printStackTrace();
        } catch(InvalidKeyException|InvalidAlgorithmParameterException cryptoParameterException)
        {
            System.err.println("Parameter or Key provided was invalid!");
            cryptoParameterException.printStackTrace();
        }
        return null;
    }
}
