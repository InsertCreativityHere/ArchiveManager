
package com.insertcreativity.archive;

import java.io.IOException;

/**
 * Base class containing all the required functionality of a file the archive manager requires. Classes that inherit from this one allow one to interface with archives stored within the media they implement.
**/
public abstract class AbstractFile
{
    /**
     * Resolves the file object at the specified address.
     * @param address String encoding of the file's address.
     * @return The file at the specified address, or null if it doesn't exist.
     * @throws IOException If an exception occurs while resolving the address.
    **/
    public static AbstractFile resolve(String address) throws IOException
    {
        throw new UnsupportedOperationException("Only implementations of AbstractFile can resolve addresses.");
    }

    /**
     * Returns whether or not there is more data to read from the file.
     * @return False if the file-pointer is at the end of the file, true otherwise.
     * @throws IOException If the operation fails or is unsupported.
    **/
    public abstract boolean hasNext() throws IOException;

    /**
     * Returns whether or not this file is a directory.
     * @return True if the file is a directory.
     * @throws IOException If the operation fails or is unsupported.
    **/
    public abstract boolean isDirectory() throws IOException;

    /**
     * Gets the directory that contains this file.
     * @return The parent containing this file, if none exists (like if this is a root), returns null.
     * @throws IOException If the operation fails or is unsupported.
    **/
    public abstract AbstractFile getParent() throws IOException;

    /**
     * Gets the file in this directory matching the provided name.
     * @param name The name of the file to find in this directory.
     * @return The requested child file, or null if it doesn't exist.
     * @throws IOException If the operation fails or is unsupported.
     */
    public abstract AbstractFile getChild(String name) throws IOException;

    /**
     * Returns the name of the file.
     * @return The name of the file.
     * @throws IOException If the operation fails or is unsupported.
    **/
    public abstract String getName() throws IOException;

    /**
     * Returns the absolute address of the file.
     * @return The absolute address of the file.
     * @throws IOException If the operation fails or is unsupported.
    **/
    public abstract String getAddress() throws IOException;

    /**
     * Gets the current size of the file, in bytes.
     * @return The total number of bytes currently in the file.
     * @throws IOException If the operation fails or is unsupported.
    **/
    public abstract long length() throws IOException;

    /**
     * Returns the current position of the file-pointer.
     * @return The current position of the file-pointer.
     * @throws IOException If the operation fails or is unsupported.
    **/
    public abstract long getPosition() throws IOException;

    /**
     * Moves the file-pointer to the specified position.
     * @param position The position to move the file-pointer to in the file, measured from the start of the file.
     * @throws IOException If the operation fails or is unsupported.
    **/
    public abstract void seek(long position) throws IOException;

    /**
     * Reads a single byte from the file at the file-pointer's current position (and shifts the pointer forward by 1).
     * @return The value of the byte read from the file.
     * @throws IOException If the operation fails or is unsupported.
    **/
    public abstract byte readByte() throws IOException;

    /**
     * Reads a consecutive series of bytes from the file into the buffer starting from the current file-pointer position.
     * @param buffer The array to read bytes into. Bytes are stored started at index 0, and read in order.
     * @return The number of bytes successfully read from the file, or -1 if EOF has been reached.
     * @throws IOException If the operation fails or is unsupported.
    **/
    public int readBytes(byte[] buffer) throws IOException
    {
        return readBytes(buffer, 0, buffer.length);
    }

    /**
     * Reads a consecutive series of bytes from the file into the buffer starting from the current file-pointer position.
     * @param buffer The array to read bytes into.
     * @param offset The index offset to start storing bytes in the buffer at.
     * @param length The number of bytes that should be read into the buffer.
     * @return The actual number of bytes s successfully read from the file, or -1 if EOF has been reached.
     * @throws IOException If the operation fails or is unsupported.
    **/
    public abstract int readBytes(byte[] buffer, int offset, int length) throws IOException;

    /**
     * Writes a single byte into the file at the file-pointer's current position (and shifts the pointer forward by 1). If the file-pointer is at EOF, the byte is appended to the end of the file, otherwise the byte currently at that position is overwritten.
     * @param data The byte to write into the file.
     * @return The number of bytes successfully written to the file, in this case 0 indicates a failed write, 1 indicates success.
     * @throws IOException If the operation fails or is unsupported.
    **/
    public abstract int writeByte(byte data) throws IOException;

    /**
     * Writes an array of bytes into the file in order starting at the file-pointer's current position.
     * @param data The bytes to write into the file.
     * @return The number of bytes successfully written into the file.
     * @throws IOException If the operation fails or is unsupported.
    **/
    public int writeBytes(byte[] data) throws IOException
    {
        return writeBytes(data, 0, data.length);
    }

    /**
     * Writes an array of bytes into the file in order starting at the file-pointer's current position.
     * @param data The array to write bytes from.
     * @param offset The index offset to starting writing bytes from the buffer at.
     * @param length The number of bytes that should be written into the file.
     * @return The number of bytes successfully written into the file.
     * @throws IOException If the operation fails or is unsupported.
    **/
    public abstract int writeBytes(byte[] data, int offset, int length) throws IOException;

    /**
     * Closes the file, flushing and saving any changes made to it, and releasing any resources it was using.
     * @throws IOException If the file encountered an error while closing.
    **/
    public abstract void close() throws IOException;

    /**
     * Ensure that the file gets closed before it's garbage collected.
    **/
    protected void finalize()
    {
        try
        {
            close();
        } catch(Exception exception)
        {
            exception.printStackTrace();
        }
    }
}
