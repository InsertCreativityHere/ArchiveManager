
package com.insertcreativity.archive;

import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.io.Serializable;
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
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

public final class EncryptionManager implements Serializable
{
    /**Engine used for generating random variables.**/
    private static final SecureRandom randomEngine;
    static{
        randomEngine = new SecureRandom();
    }

    /**Prevent potential attackers from serializing this object by generating a random UID whenever this class is loaded.**/
    private static final long serialVersionUID;
    static{
        serialVersionUID = randomEngine.nextLong();
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

    /**The internal counter used by the encryption manager.**/
    private final byte[] counter;
    /**The number of the block that the manager is currently over.**/
    private final long currentPosition;
    /**Engine used for performing hash functions.**/
    private final MessageDigest hashEngine1;
    /**Engine used for performing hash functions.**/
    private final MessageDigest hashEngine2;
    /**Engine used for encrypting and decrypting data.**/
    private final Cipher encryptionEngine;
    /**The character encoding scheme for the manager to use.**/
    private final Charset charset = StandardCharsets.UTF_16LE;

    /**
     * Creates a new encryption manager. Note that the provided key will be erased after the manager finishes initializing.
     * @param key Char array containing the secret key that the archive should use for encrypting/decrypting.
     * @param iv Byte array containing the initialization vector for the manager (starting value for the CTR counter). If null, the default IV is used.
     * @return A new instance of an Encryption Manager initialized with the specified key. Or null if the manager couldn't be initialized correctly.
    **/
    public static final EncryptionManager getInstance(char[] key, byte[] iv)
    {
        try
        {
            return new EncryptionManager(key, iv);
        } catch(NoSuchAlgorithmException|NoSuchPaddingException unsupportedCryptoException)
        {
            System.err.println("Your system doesn't provide support for either SHA-256 or AES256-ECB.");
            unsupportedCryptoException.printStackTrace();
        } catch(InvalidKeyException|InvalidAlgorithmParameterException cryptoParameterException)
        {
            System.err.println("The provided key or IV was invalid!");
            cryptoParameterException.printStackTrace();
        }
        return null;
    }

    /**
     * Creates a new encryption manager with a randomly generated key and iv.
     * @param data An array at least 48 bytes long that the new manager's key and IV copied into upon initialization.
     * @return A new instance of an Encryption Manager initialized with the specified key. Or null if the manager couldn't be initialized correctly.
    **/
    public final EncryptionManager getInstance(byte[] data)
    {
        try
        {
            return new EncryptionManager(data);
        } catch(NoSuchAlgorithmException|NoSuchPaddingException|InvalidKeyException unsupportedCryptoException)
        {
            System.err.println("Your system doesn't provide support for either SHA-256 or AES256-ECB.");
            unsupportedCryptoException.printStackTrace();
        }
        return null;
    }

    //TODO
    private EncryptionManager(char[] key, byte[] iv) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException
    {
        try
        {
            //Create the hash and encryption engines for the manager
            hashEngine1 = MessageDigest.getInstance("SHA-256");
            hashEngine2 = MessageDigest.getInstance("SHA-256");
            encryptionEngine = Cipher.getInstance("AES/ECB/NoPadding");

            //Initialize the cipher with a hash of the secret key
            CharBuffer cBuffer = CharBuffer.wrap(key);
            ByteBuffer bBuffer = charset.encode(cBuffer);
            encryptionEngine.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(hashEngine1.digest(bBuffer.array()), "AES"));
            //Overwrite any sensitive information stored in the buffers
            Arrays.fill(cBuffer.array(), '\255');
            Arrays.fill(bBuffer.array(), (byte)255);

            //Initialize a counter with the provided IV.
            currentPosition = 0;
            if(iv == null)
            {
                counter = new byte[] {77, 97, 100, 105, 65, 117, 115, 116, 105, 110, 82, 97, 99, 104, 101, 108};
            } else
            if(iv.length == 16){
                counter = iv;
            } else{
                throw new InvalidAlgorithmParameterException("IV must be exactly 16bytes in length.");
            }
        } finally{
            //Ensure that the provided data is erased
            Arrays.fill(key, '\255');
            Arrays.fill(iv, (byte)255);
        }
    }

    //TODO
    private EncryptionManager(byte[] data) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException
    {
        //Create all the engines for the manager.
        hashEngine1 = MessageDigest.getInstance("SHA-256");
        hashEngine2 = MessageDigest.getInstance("SHA-256");
        encryptionEngine = Cipher.getInstance("AES/ECB/NoPadding");
        currentPosition = 0;

        //Allocate arrays for holding the key and counter
        byte[] key = new byte[32];
        counter = new byte[16];
        //Generate a random key and IV for the counter
        randomEngine.nextBytes(key);
        randomEngine.nextBytes(counter);
        //Initialize the encryption engine
        encryptionEngine.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"));

        //Copy the manager's parameters into the data field
        if(data != null)
        {
            System.arraycopy(key, 0, data, 0, 32);
            System.arraycopy(counter, 0, data, 32, 16);
        }
    }

    /**
     * Moves the manager's counter to the specified position.
     * @param position The new position to move the counter to.
    **/
    public final void seek(long position)
    {
        seekRelative(position - currentPosition);
    }

    /**
     * Moves the manager's counter forwards or backwards by the specified amount.
     * @param offset The relative amount to offset the counter by.
    **/
    public final void seekRelative(long offset)
    {
        if(offset == 0)
        {
            return;
        } else
        if(offset == 1)
        {
            increment();
        } else
        if(offset == -1)
        {
            decrement();
        } else{
            //Convert the offset from a long to a byte array
            byte[] b = new byte[8];
            for(int i = 0; i < 8; i++)
            {
                b[i] = (byte)((offset >> (8 * i)) & 0xff);
            }

            if(offset > 0)
            {
                add(b);
            } else{
                subtract(b);
            }
        }
    }

    /**
     * Shifts the manager's counter forward by 1.
    **/
    private final void increment()
    {
        for(int i = 0; i < counter.length; i++)
        {
            if(counter[i] == -128)
            {
                counter[i] = 0;
            } else{
                counter[i] = (byte)((counter[i] & 0xff) + 1);
                break;
            }
        }
    }

    /**
     * Shifts the manager's counter forward.
     * @param b Byte array containing a base 256 number to shift the counter forward by. The length of this array must not be greater than 16 (length of the counter array).
    **/
    private final void add(byte[] b)
    {
        boolean carry = false;
        int temp;

        for(int i = 0; i < b.length; i++)
        {
            temp = (counter[i] & 0xff) + (b[i] & 0xff) + (carry? 1 : 0);
            carry = (temp > 255);
            counter[i] = (byte)(temp % 256);
        }
    }

    /**
     * Shifts the manager's counter backwards by 1.
    **/
    private final void decrement()
    {
        for(int i = 0; i < counter.length; i++)
        {
            if(counter[i] == 0)
            {
                counter[i] = -128;
            } else{
                counter[i] = (byte)((counter[i] & 0xff) - 1);
                break;
            }
        }
    }

    /**
     * Shifts the manager's counter backwards.
     * @param b Byte array containing a base 256 number to shift the counter backwards by. The length of this array must not be greater than 16 (length of the counter array).
    **/
    private final void subtract(byte[] b)
    {
        boolean carry = false;
        int temp;

        for(int i = 0; i < b.length; i++)
        {
            temp = (counter[i] & 0xff) - (b[i] & 0xff) - (carry? 1 : 0);
            carry = (temp < 0);
            counter[i] = (byte)(temp % 256);
        }
    }

    //TODO
    public final void process(byte[] b) throws IllegalBlockSizeException, BadPaddingException
    {
        byte[] keyStream = null;
        for(int i = 0; i < b.length; i++)
        {
            if((i % 16) == 0)
            {
                keyStream = encryptionEngine.doFinal(counter);
                increment();
            }
            b[i] ^= keyStream[i];
        }
    }

    //TODO
    public final void process(InputStream inputStream, OutputStream outputStream, int bufferSize) throws IllegalBlockSizeException, BadPaddingException, IOException
    {
        byte[] buffer = new byte[(bufferSize / 16) * 16];
        int count;
        while((count = inputStream.read(buffer)) != -1)
        {
            process(buffer);
            outputStream.write(buffer, 0, count);
        }
    }

    //TODO
    public final byte[][] processWithAuthenticate(byte[] b) throws IllegalBlockSizeException, BadPaddingException
    {
        //Reset the hash engine
        hashEngine1.reset();
        //Digest the plain-text
        byte[] plainHash = hashEngine1.digest(b);

        process(b);

        //Reset the hash engine
        hashEngine1.reset();
        //Digest the cipher-text and return it with the plain hash
        return new byte[][] {plainHash, hashEngine1.digest(b)};
    }

    //TODO
    public final byte[][] processWithAuthenticate(InputStream inputStream, OutputStream outputStream, int bufferSize) throws IllegalBlockSizeException, BadPaddingException, IOException
    {
        //Reset the hash engines
        hashEngine1.reset();
        hashEngine2.reset();

        byte[] buffer = new byte[(bufferSize / 16) * 16];
        int count;
        while((count = inputStream.read(buffer)) != -1)
        {
            hashEngine1.update(buffer);
            process(buffer);
            hashEngine2.update(buffer);
            outputStream.write(buffer, 0, count);
        }

        //Digest the plain-text and cipher-text and return them
        return new byte[][] {hashEngine1.digest(), hashEngine2.digest()};
    }

    //TODO
    public final byte[] generateRandom(int length)
    {
        byte[] b = new byte[length];
        randomEngine.nextBytes(b);
        return b;
    }
}
