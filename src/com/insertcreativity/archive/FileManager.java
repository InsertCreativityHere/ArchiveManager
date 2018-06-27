
package com.insertcreativity.archive;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

//TODO check that AES/ECB/NoPadding is alright before initialization ends
//TODO add safety checks to make sure add/sub of longs works with sign bit, and no over-overflow happens (-1 should be abs max!) <<< shouldn't because there's only Long.MAX_VALUE/4 blocks as long as seek is checked well.
//TODO check the position is valid!!!
//TODO check that the operation is allowed (can't write to read-only sorta thing)

/**
 * Class for encapsulating reading and writing to encrypted archive files. It contains an internal encryption engine utilizing 256bit AES-CTR, and an interface to the actual file.
 * It's primarily used for reading data files, and to provide a framework for reading specialized archive file-trypes.
**/
class FileManager
{
    /**Reference to the file that this is managing.**/
    private final AbstractFile file;
    /**Engine used for encrypting and decrypting data.**/
    private final Cipher cryptoEngine;
    /**Internal counter used by the encryption engine.**/
    private final byte[] counter;
    /**The key-stream values for the current block.**/
    private final byte[] keyStream;
    /**The current offset being read within the file (in bytes).**/
    private long currentPosition;

    /**
     * Creates a new manager for interacting with the file.
     * @param abstractFile Reference to the actual file.
     * @param key The key used to encrypt the file.
     * @param iv The initialization vector to start the counter at. Must be at least 16 bytes long, any iv's longer than 16 bytes will only have the first 16 bytes used.
     * @throws InvalidKeyException If the provided key isn't valid.
    **/
    FileManager(AbstractFile abstractFile, byte[] key, byte[] iv) throws InvalidKeyException
    {
        try
        {
            //Initialize the crypto engine, and erase the key.
            cryptoEngine = Cipher.getInstance("AES/ECB/NoPadding");
            cryptoEngine.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(HashEnginePool.digest(key), "AES"));
            Arrays.fill(key, (byte)255);

            //Initialize the counter with the provided IV, and erase the IV.
            counter = new byte[16];
            System.arraycopy(iv, 0, counter, 0, 16);
            Arrays.fill(iv, (byte)255);

            file = abstractFile;
            keyStream = new byte[16];
            currentPosition = 0;
        } catch(NoSuchAlgorithmException|NoSuchPaddingException cipherException)
        {
            throw new IllegalStateException("Platform doesn't support AES/ECB/NoPadding", cipherException);
        } finally{
            //Ensure that the provided key and IV were erased.
            Arrays.fill(key, (byte)255);
            Arrays.fill(iv, (byte)255);
        }
    }

    /**
     * Encrypts or decrypts a single byte of data.
     * @param data The byte to be processed.
     * @return The value of the byte after processing.
    **/
    final byte process(byte data)
    {
        //XOR the byte with the key-stream.
        data ^= keyStream[(int)(currentPosition++ % 16)];
        //Calculate the next key-stream block if the current one has been used up.
        if(currentPosition % 16 == 0)
        {
            incrementCounter();
        }
        return data;
    }

    /**
     * Encrypts or decrypts the provided data.
     * @param data Array of bytes to be processed. Note that the new values are directly written back into the provided array.
     * @return The number of bytes successfully processed.
    **/
    final int process(byte[] data)
    {
        return process(data, 0, data.length);
    }

    /**
     * Encrypts or decrypts the provided section of data.
     * @param data Array of bytes to be processed. Note that the new values are directly written back into the provided array.
     * @param offset The offset to begin processing within the data array.
     * @param length The number of bytes to process from the array.
     * @return The number of bytes successfully processed.
    **/
    final int process(byte[] data, int offset, int length)
    {
        int count = 0;
        for(;count < length; count++)
        {
            //XOR the byte with the key-stream.
            data[count + offset] ^= keyStream[(int)(currentPosition++ % 16)];

            //Calculate the next key-stream block if the current one has been used up.
            if(currentPosition % 16 == 0)
            {
                incrementCounter();
            }
        }
        return count;
    }

    /**
     * Shifts the counter forward or backwards by the specified amount.
     * @param offset The amount to shift the counter by relatively, positive for forwards, negative for backwards.
    **/
    private final void shiftCounter(long offset)
    {
        if(offset == 1)
        {
            //Increment the counter.
            incrementCounter();
        } else{
            //Convert the offset from a long to a byte array.
            byte[] b = new byte[8];
            for(int i = 0; i < 8; i++)
            {
                b[i] = (byte)((offset >> (8 * i)) & 0xff);
            }
            //Ignore the sign bit.
            b[7] &= 0b01111111;

            //Shift the counter.
            if(offset > 0)
            {
                add(b);
            } else{
                subtract(b);
            }
        }
    }

    /**
     * Shifts the counter forward by the specified amount.
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

        //Calculate and store the key-stream for the new counter position.
        calculateKeystream();
    }

    /**
     * Shifts the counter backwards by the specified amount.
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

        //Calculate and store the key-stream for the new counter position.
        calculateKeystream();
    }

    /**
     * Shifts the internal counter forward by one block, and recomputes the key-stream for the next block.
    **/
    private final void incrementCounter()
    {
        //Move the counter forward by 1.
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

        //Calculate and store the key-stream for the new counter position.
        calculateKeystream();
    }

    /**
     * Calculates the key-stream for the current counter position.
    **/
    private final void calculateKeystream()
    {
        try
        {
            System.arraycopy(cryptoEngine.doFinal(counter), 0, keyStream, 0, 16);
        } catch(IllegalBlockSizeException|BadPaddingException blockException)
        {
            throw new IllegalStateException("Illegal counter size!", blockException);
        }
    }

    /**
     * Returns the file-pointer's current position in the file.
     * @return The current position the manager is at in the file.
    **/
    final long getPosition()
    {
        return currentPosition;
    }

    /**
     * Moves the manager to the specified position(in bytes).
     * @param position The new position to move to in the file. Positive positions are measured from the start of the file, and negative positions are measured from the end.
     * @throws IOException If the operation fails unexpectedly or is unsupported.
    **/
    final void seek(long position) throws IOException
    {
        if(position < 0)
        {
            position = file.length() - position;
        }
        seekRelative(position - currentPosition);
    }

    /**
     * Moves the manager forwards or backwards by the specified amount of bytes.
     * @param offset The relative amount to offset the manager by in the file.
     * @throws IOException If the operation fails unexpectedly or is unsupported.
    **/
    final void seekRelative(long offset) throws IOException
    {
        file.seek(currentPosition + offset);
        //Reposition the counter to the new offset.
        shiftCounter(((offset + currentPosition) / 16) - (currentPosition / 16));
        //Seek to the specified position in the file.
        currentPosition += offset;
    }

    /**
     * Reads a single byte from the file at the current position and decrypts it.
     * @return The decrypted byte.
     * @throws IOException If the operation fails unexpectedly or is unsupported.
    **/
    final byte readByte() throws IOException
    {
        return process(file.readByte());
    }

    /**
     * Reads data from the file at the current position into the provided buffer and decrypts it.
     * @param buffer The buffer to read data into.
     * @return The number of bytes successfully read from the file, or -1 if the file is at EOF.
     * @throws IOException If the operation fails unexpectedly or is unsupported.
    **/
    final int readBytes(byte[] buffer) throws IOException
    {
        return readBytes(buffer, 0, buffer.length);
    }

    /**
     * Reads data from the file at the current position into the provided buffer and decrypts it.
     * @param buffer The buffer to read data into.
     * @param offset The offset to start reading into in the buffer.
     * @param length The number of bytes to read from the file, or -1 if the file is at EOF.
     * @return The number of bytes successfully read from the file.
     * @throws IOException If the operation fails unexpectedly or is unsupported.
    **/
    final int readBytes(byte[] buffer, int offset, int length) throws IOException
    {
        //Read data from the file into the buffer.
        int count = file.readBytes(buffer, offset, length);
        //Decrypt the data.
        process(buffer, 0, count);
        return count;

    }

    /**
     * Writes a single byte into the file at the current position, encrypting it first.
     * @param data The byte to write into the file.
     * @return The number of bytes successfully written to the file, in this case either 0 for failure, or 1 for success.
     * @throws IOException If the operation fails unexpectedly or is unsupported.
    **/
    final int writeByte(byte data) throws IOException
    {
        return file.writeByte(process(data));
    }

    /**
     * Writes an array of bytes into the file at the current position, encrypting it first.
     * @param data Array of bytes to write into the file. Note that encryption takes place in the provided array, so after the method returns the array will of been encrypted.
     * @return The number of bytes successfully written to the file.
     * @throws IOException If the operation fails unexpectedly or is unsupported.
    **/
    final int writeBytes(byte[] data) throws IOException
    {
        return writeBytes(data, 0, data.length);
    }

    /**
     * Writes a section of bytes into the file at the current position, encrypting them first.
     * @param data Array of bytes to write into the file. Note that encryption takes place in the provided array, so after the method returns the array will of been encrypted.
     * @param offset The offset to start writing from in the data array.
     * @param length The number of bytes to write into the file.
     * @return The number of bytes successfully written to the file.
     * @throws IOException If the operation fails unexpectedly or is unsupported.
    **/
    final int writeBytes(byte[] data, int offset, int length) throws IOException
    {
        //Encrypt the data.
        int count = process(data, offset, length);
        //Write the data to the file.
        return file.writeBytes(data, offset, count);
    }

    /**
     * Computes a hash of the plain and cipher text of the file.
     * @return An array of hashes. The first hash is the file's unprocessed data, the second is the data after processing.
     * @throws IOException If the operation fails or is unsupported.
    **/
    final byte[][] hash() throws IOException
    {
        //Reserve hash engines for the plain and cipher text of the file.
        int hash1 = HashEnginePool.reserveEngine(true);
        int hash2 = HashEnginePool.reserveEngine(true);

        try
        {
            //Move to the start of the file.
            seek(hashStart());

            byte[] buffer = new byte[65536];
            int count;
            while(file.hasNext())
            {
                //Read in the file's data.
                count = file.readBytes(buffer);
                //Hash the cipher text.
                HashEnginePool.update(hash1, buffer, 0, count);
                //Decrypt the data.
                process(buffer, 0, count);
                //Hash the plain text.
                HashEnginePool.update(hash2, buffer, 0, count);
            }

            return new byte[][] {HashEnginePool.digest(hash1), HashEnginePool.digest(hash2)};
        } finally{
            HashEnginePool.releaseEngine(hash1);
            HashEnginePool.releaseEngine(hash2);
        }
    }

    /**
     * Returns the position to start hashing a file from, used by file manager extensions to skip unhashable data.
     * @return The position to start hashing a file at.
    **/
    long hashStart()
    {
        return 0;
    }
}
