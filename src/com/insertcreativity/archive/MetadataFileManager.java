
package com.insertcreativity.archive;

import java.security.InvalidKeyException;

final class MetadataFileManager extends FileManager
{
    MetadataFileManager(AbstractFile abstractFile, byte[] key, byte[] iv) throws InvalidKeyException
    {
        super(abstractFile, key, iv);
    }
}
