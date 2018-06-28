
package com.insertcreativity.archive;

import java.io.EOFException;
import java.io.IOException;
import java.security.InvalidKeyException;

/**
 * Class for reading and updating metadata of various archive files. Metadata files are formatted as a list of key value pairs.
 * Each pair has the following structure:
 *      - 1 byte for the length of the key
 *      - 2 bytes for the length of the value
 *      - The key, stored as a UTF-16 string
 *      - The value
 * Metadata files store no data about themselves.
**/
final class MetadataFileManager extends FileManager
{
    /**The byte offset of the metadata entry currently being accessed.**/
    private long entryOffset;
    /**The length of the entry's key. Keys can be anywhere between 0 and 255 bytes long.**/
    private int keyLength;
    /**The length of the entry's value. Values can be anywhere between 0 and 65535 bytes long.**/
    private int valueLength;

    /**
     * Creates a new manager for interacting with metadata files.
     * @param abstractFile Reference to the actual file.
     * @param key The key used to encrypt the file.
     * @param iv The initialization vector to start the counter at. Must be at least 16 bytes long, any iv's longer than 16 bytes will only have the first 16 bytes used.
     * @throws InvalidKeyException If the provided key isn't valid
    **/
    MetadataFileManager(AbstractFile abstractFile, byte[] key, byte[] iv) throws InvalidKeyException
    {
        super(abstractFile, key, iv);
    }

    /**
     * Searches the metadata file for the provided metadata key, and seek's to to the corresponding metadata value if it's present.
     * @param key The metadata key to search for.
     * @return True if the key was found, false if EOF was reached.
     * @throws IOException If the operation fails unexpectedly or is unsupported.
    **/
    private final boolean seekKey(byte[] key) throws IOException
    {
        //Seek to the start of the file.
        seek(0);

        //Allocate a buffer for reading keys.
        byte[] buffer = new byte[256];
        int i;

        try
        {
            while(true)
            {
                entryOffset = getPosition();
                //Read the entry lengths.
                keyLength = readByte() & 0xff;
                valueLength = ((readByte() & 0xff) << 8) | (readByte() & 0xff);

                //If the length of the keys don't match, skip the entry.
                if(keyLength != key.length)
                {
                    seekRelative(keyLength + valueLength);
                }

                //If the whole key couldn't be read in, terminate the search.
                if(readBytes(buffer, 0, keyLength) != keyLength)
                {
                    break;
                }

                //Compare the key's values.
                for(i = 0; i < keyLength; i++)
                {
                    if(buffer[i] != key[i])
                    {
                        //Skip reading the value if the keys don't match
                        seekRelative(valueLength);
                        break;
                    }
                }
                //If the keys matched.
                if(i == 12)
                {
                    return true;
                }
            }
        } catch(EOFException eofException){}

        return false;
    }

    /**
     * Gets the metadata value for a specified key.
     * @param key The key for the metadata to retrieve.
     * @return The corresponding metadata value, or null if the key couldn't be found.
     * @throws IOException If the operation fails unexpectedly or is unsupported.
    **/
    final byte[] getMetadata(byte[] key) throws IOException
    {
        if(seekKey(key))
        {
            //Read and return the value.
            byte[] value = new byte[valueLength];
            if(readBytes(value) != valueLength)
            {
                throw new IOException("Failed to read in value completely.");
            }
            return value;
        }

        return null;
    }

    /**
     * Updates the metadata value for a specified key, or appends a new entry into the file if it isn't listed already.
     * @param key The metadata key to update the value of.
     * @param value The value of the metadata.
     * @return The previous value of the metadata, or null if there wasn't previously an entry.
     * @throws IOException If the operation fails unexpectedly or is unsupported.
    **/
    final byte[] updateMetadata(byte[] key, byte[] value) throws IOException
    {
        if(key.length > 255)
        {
            throw new IllegalArgumentException("Metadata keys cannot be larger than 255 bytes in length!");
        }
        if(value.length > 65535)
        {
            throw new IllegalArgumentException("Metadata values cannot be larger than 65535 bytes in length!");
        }

        //Get the previous value for the key.
        byte[] previousValue = getMetadata(key);
        if(previousValue == null)
        {
            //Append the entry at EOF if there isn't an entry for it already.
            seek(-1);
            writeByte((byte)key.length);
            writeByte((byte)value.length);
            writeByte((byte)(value.length >> 8));
            writeBytes(key);
            writeBytes(value);
        } else{
            //Overwrite the value and it's length in the entry.
            seek(entryOffset + 1);
            writeByte((byte)value.length);
            writeByte((byte)(value.length >> 8));
            seekRelative(key.length);
            writeBytes(value);
        }

        return previousValue;
    }

    /**
     * Metadata contains no unhashable data, so returns the start of the file.
     * @return The position to start hashing the metadata file at.
    **/
    final long hashStart()
    {
        return 0;
    }
}
