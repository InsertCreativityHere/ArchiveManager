
package com.insertcreativity.archive;

import java.security.InvalidKeyException;

final class HashFileManager extends FileManager
{
    HashFileManager(AbstractFile abstractFile, byte[] key, byte[] iv) throws InvalidKeyException
    {
        super(abstractFile, key, iv);
    }
}
