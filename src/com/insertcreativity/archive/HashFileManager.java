
package com.insertcreativity.archive;

import java.io.IOException;
import java.security.InvalidKeyException;

/**
 * Class for reading and updating hash tables of various archive files. Hash files are formatted as a list of hash entries.
 * Each entry has the following structure:
 *      - 12 bytes containing the generated archive file identifier for the file
 *      - 16 bytes containing a hash of the file's plain text
 *      - 16 bytes containing a hash of the file's cipher text
 * The first entry of the file is just the hash values and not the identifier, these are the hashes of the hash file itself, computed by hashing all other entries.
**/
final class HashFileManager extends FileManager
{
    /**
     * Creates a new manager for interacting with hash files.
     * @param abstractFile Reference to the actual file.
     * @param key The key used to encrypt the file.
     * @param iv The initialization vector to start the counter at. Must be at least 16 bytes long, any iv's longer than 16 bytes will only have the first 16 bytes used.
     * @throws InvalidKeyException If the provided key isn't valid
    **/
    HashFileManager(AbstractFile abstractFile, byte[] key, byte[] iv) throws InvalidKeyException
    {
        super(abstractFile, key, iv);
    }

    /**
     * Searches the hash file for the provided identifier, and seeks to the byte directly after it if it's present.
     * @param identifier The identifier to search for, must be at least 12 bytes, if more then only the first 12 bytes are used.
     * @return True if the identifier was found, false if EOF was reached.
     * @throws IOException If the operation fails unexpectedly or is unsupported.
    **/
    private final boolean seekIdentifier(byte[] identifier) throws IOException
    {
        return seekIdentifier(identifier, 0);
    }

    /**
     * Searches the hash file for the provided identifier, and seeks to the byte directly after it if it's present.
     * @param identifier Byte array containing the identifier to search for. Only the first 12 bytes after offset are used for comparison.
     * @param offset The offset to start reading the identifier from the array at.
     * @return True if the identifier was found, false if EOF was reached.
     * @throws IOException If the operation fails unexpectedly or is unsupported.
    **/
    private final boolean seekIdentifier(byte[] identifier, int offset) throws IOException
    {
        //Seek to where the hash entries begin
        seek(32);

        //Allocate a buffer for reading identifiers in
        byte[] buffer = new byte[12];
        int i;

        //Start reading through identifiers.
        while(readBytes(buffer) == 12)
        {
            //Compare the identifiers.
            for(i = 0; i < 12; i++)
            {
                if(buffer[i] != identifier[i + offset])
                {
                    //Skip reading the hash values if the identifiers don't match.
                    seekRelative(32);
                    break;
                }
            }
            //If the identifiers matched.
            if(i == 12)
            {
                return true;
            }
        }

        return false;
    }

    /**
     * Gets the hashes for a specified archive file.
     * @param identifier The identifier of the file to retrieve hashes for.
     * @return The plain text hash and cipher text hash, stored together in a single array, or null if no hash entry exists for the specified identifier.
     * @throws IOException If the operation unexpectedly failed or is unsupported.
    **/
    final byte[][] getHash(byte[] identifier) throws IOException
    {
        //If the identifier was found in the file.
        if(seekIdentifier(identifier))
        {
            //Read and return the hashes.
            byte[] plainHash = new byte[12];
            byte[] cipherHash = new byte[12];
            if((readBytes(plainHash) != 12) || (readBytes(cipherHash) != 12))
            {
                throw new IOException("Failed to read in hash values completely.");
            }
            return new byte[][] {plainHash, cipherHash};
        }

        return null;
    }

    /**
     * Updates the hash values for an archive file, or adds it's hashes into the file if it isn't currently listed.
     * @param identifier The identifier of the file to update the hashes of.
     * @param hashes Array of the file's plain and cipher text hashes in that order.
     * @return An array of the previous hash values (plain and cipher in order), or null if there wasn't previously an entry for the file.
     * @throws IOException If the operation unexpectedly failed or is unsupported.
    **/
    final byte[][] updateHash(byte[] identifier, byte[][] hashes) throws IOException
    {
        //Get the previous hashes for the identifier.
        byte[][] previousHashes = getHash(identifier);
        //Append the identifier at EOF if there isn't an entry for it already.
        if(previousHashes == null)
        {
            seek(-1);
            writeBytes(identifier);
        }
        //Write the hashes into the entry.
        writeBytes(hashes[0]);
        writeBytes(hashes[1]);

        return previousHashes;
    }

    /**
     * Returns the position directly after the hash file's own entry to avoid self-referencing hashing loops.
     * @return The position to start hashing the hash file at.
    **/
    final long hashStart()
    {
        return 32;
    }
}
