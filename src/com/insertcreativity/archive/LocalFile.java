package com.insertcreativity.archive;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.RandomAccessFile;

/**
 * Class for interfacing with archives stored in a local file system.
**/
public class LocalFile extends AbstractFile
{
    /**Reference to the underlying file.**/
    private final File file;
    /**Object for accessing the file's contents.**/
    private final RandomAccessFile raf;

    /**
     * Resolves the file object at the specified address.
     * @param address String encoding of the file's address.
     * @return The file at the specified address.
     * @throws FileNotFoundException If the specified file can't be found locally.
    **/
    public static AbstractFile resolve(String address) throws FileNotFoundException
    {
        return new LocalFile(address);
    }

    /**
     * Creates a new file interface to a local file with read and write capabilities.
     * @param address The local address of the file.
     * @throws FileNotFoundException If the specified file can't be found locally.
    **/
    public LocalFile(String address) throws FileNotFoundException
    {
        this(address, "rws");
    }

    /**
     * Creates a new file interface to a local file with read and write capabilities.
     * @param address Object reference to the file.
     * @throws FileNotFoundException If the specified file can't be found locally.
    **/
    public LocalFile(File address) throws FileNotFoundException
    {
        this(address, "rws");
    }

    /**
     * Creates a new file interface to a local file.
     * @param address The local address of the file.
     * @param mode The mode to open the file in. (see https://docs.oracle.com/javase/7/docs/api/java/io/RandomAccessFile.html#mode)
     * @throws FileNotFoundException If the specified file can't be found locally.
    **/
    public LocalFile(String address, String mode) throws FileNotFoundException
    {
        this(new File(address), mode);
    }

    /**
     * Creates a new file interface to a local file.
     * @param address Object reference to the file.
     * @param mode  The mode to open the file in. (see https://docs.oracle.com/javase/7/docs/api/java/io/RandomAccessFile.html#mode)
     * @throws FileNotFoundException If the specified file can't be found locally.
    **/
    public LocalFile(File address, String mode) throws FileNotFoundException
    {
        file = address;
        if(file.isDirectory())
        {
            raf = new RandomAccessFile(file, mode);
        } else{
            raf = null;
        }
    }

    /**
     * Returns whether or not there is more data to read from the file.
     * @return False if the file-pointer is at the end of the file, true otherwise.
     * @throws IOException If the operation fails or is unsupported.
    **/
    public boolean hasNext() throws IOException
    {
        if(file.isDirectory())
        {
            return false;
        }
        return (raf.getFilePointer() != raf.length());
    }

    /**
     * Returns whether or not this file is a directory.
     * @return True if the file is a directory.
    **/
    public boolean isDirectory()
    {
        return file.isDirectory();
    }

    /**
     * Gets the directory that contains this file.
     * @return The parent containing this file, if none exists (like if this is a root), returns null.
     * @throws IOException If the operation fails or is unsupported.
    **/
    public AbstractFile getParent() throws IOException
    {
        return new LocalFile(file.getParentFile());
    }

    /**
     * Gets the file in this directory matching the provided name.
     * @param name The name of the file to find in this directory.
     * @return The requested child file, or null if it doesn't exist.
     * @throws IOException If the operation fails or is unsupported.
    **/
    public AbstractFile getChild(String name) throws IOException
    {
        return new LocalFile(new File(file, name));
    }

    /**
     * Returns the name of the file.
     * @return The name of the file.
    **/
    public String getName()
    {
        return file.getName();
    }

    /**
     * Returns the absolute address of the file.
     * @return The absolute address of the file.
    **/
    public String getAddress()
    {
        return file.getAbsolutePath();
    }

    /**
     * Gets the current size of the file, in bytes.
     * @return The total number of bytes currently in the file.
     * @throws IOException If the operation fails or is unsupported.
    **/
    public long length() throws IOException
    {
        return raf.length();
    }

    /**
     * Returns the current position of the file-pointer.
     * @return The current position of the file-pointer.
     * @throws IOException If the operation fails or is unsupported.
    **/
    public long getPosition() throws IOException
    {
        return raf.getFilePointer();
    }

    /**
     * Moves the file-pointer to the specified position.
     * @param position The position to move the file-pointer to in the file, measured from the start of the file.
     * @throws IOException If the operation fails or is unsupported.
    **/
    public void seek(long position) throws IOException
    {
        raf.seek(position);
    }

    /**
     * Reads a single byte from the file at the file-pointer's current position (and shifts the pointer forward by 1).
     * @return The value of the byte read from the file.
     * @throws EOFException If EOF has been reached.
     * @throws IOException If the operation fails or is unsupported.
    **/
    public byte readByte() throws IOException
    {
        return raf.readByte();
    }

    /**
     * Reads a consecutive series of bytes from the file into the buffer starting from the current file-pointer position.
     * @param buffer The array to read bytes into.
     * @param offset The index offset to start storing bytes in the buffer at.
     * @param length The number of bytes that should be read into the buffer.
     * @return The actual number of bytes s successfully read from the file, Buffer.length many bytes are attempted to be read, or -1 if EOF has been reached.
     * @throws IOException If the operation fails or is unsupported.
    **/
    public int readBytes(byte[] buffer, int offset, int length) throws IOException
    {
        return raf.read(buffer, offset, length);
    }

    /**
     * Writes a single byte into the file at the file-pointer's current position (and shifts the pointer forward by 1). If the file-pointer is at EOF, the byte is appended to the end of the file, otherwise the byte currently at that position is overwritten.
     * @param data The byte to write into the file.
     * @return The number of bytes successfully written to the file.
     * @throws IOException If the operation fails or is unsupported.
    **/
    public int writeByte(byte data) throws IOException
    {
        raf.write(data);
        return 1;
    }

    /**
     * Writes an array of bytes into the file in order starting at the file-pointer's current position.
     * @param data The array to write bytes from.
     * @param offset The index offset to starting writing bytes from the buffer at.
     * @param length The number of bytes that should be written into the file.
     * @return The number of bytes successfully written into the file.
     * @throws IOException If the operation fails or is unsupported.
    **/
    public int writeBytes(byte[] data, int offset, int length) throws IOException
    {
        raf.write(data, offset, length);
        return length;
    }

    /**
     * Closes the file, flushing and saving any changes made to it, and releasing any resources it was using.
     * @throws IOException If the file encountered an error while closing.
    **/
    public void close() throws IOException
    {
        raf.close();
    }
}
