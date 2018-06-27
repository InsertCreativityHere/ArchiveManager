
package com.insertcreativity.archive;

import java.security.InvalidKeyException;

final class LogFileManager extends FileManager
{
    LogFileManager(AbstractFile abstractFile, byte[] key, byte[] iv) throws InvalidKeyException
    {
        super(abstractFile, key, iv);
    }
}
