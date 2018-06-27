
package com.insertcreativity.archive;

import java.security.InvalidKeyException;

final class IndexFileManager extends FileManager
{
    IndexFileManager(AbstractFile abstractFile, byte[] key, byte[] iv) throws InvalidKeyException
    {
        super(abstractFile, key, iv);
    }
}
