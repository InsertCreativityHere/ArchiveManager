
package com.insertcreativity.archive;

import java.security.DigestException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Class for managing hash operations, which keeps a pre-allocated stock of hash engines that can reserved for use by other instances. This helps parallelize file authentication and processing.
**/
final class HashEnginePool
{
    /**Create one message digest for every processor available.**/
    private static final MessageDigest[] hashPool;
    /**Stores the availability of each hash engine.**/
    private static final boolean[] available;

    /**
     * Initialize the hash manager.
     * @throws IllegalStateException If the platform doesn't support 256bit SHA algorithms.
    **/
    static
    {
        try
        {
            //Allocate one hash engine for each available processor
            hashPool = new MessageDigest[Runtime.getRuntime().availableProcessors()];
            available = new boolean[hashPool.length];
            //Initialize the engines
            for(int i = 0; i < hashPool.length; i++)
            {
                //Create a new SHA256 engine and set it as available
                hashPool[i] = MessageDigest.getInstance("SHA-256");
                available[i] = true;
            }
        } catch(NoSuchAlgorithmException noSuchAlgorithmException)
        {
            throw new IllegalStateException("256bit SHA not supported on this platform", noSuchAlgorithmException);
        }
    }

    /**
     * Reserves an engine from the manager.
     * @param shouldWait Flag for whether the method should wait for an engine to become available if one isn't currently.
     * @return The index of the engine now reserved, or -1 if no engine was available and waiting was disabled.
    **/
    static final int reserveEngine(boolean shouldWait)
    {
        synchronized(hashPool)
        {
            while(true)
            {
                for(int i = 0; i < hashPool.length; i++)
                {
                    if(available[i] == true)
                    {
                        available[i] = false;
                        return i;
                    }
                }
                if(shouldWait)
                {
                    try
                    {
                        hashPool.wait();
                    }catch(InterruptedException e){}
                } else{
                    return -1;
                }
            }
        }
    }

    /**
     * Releases a previously reserved engine.
     * @param engine The index of the engine to release.
     * @throws IllegalStateException If the specified index doesn't correspond to a reserved engine.
    **/
    static final void releaseEngine(int engine) throws IllegalStateException
    {
        synchronized(hashPool)
        {
            if(available[engine])
            {
                available[engine] = false;
                hashPool[engine].reset();
            } else{
                throw new IllegalStateException("The specified engine is already available.");
            }
        }
    }

    /**
     * Resets the specified engine to it's originally initialized state.
     * @param engine The engine index to reset.
    **/
    static final void reset(int engine)
    {
        hashPool[engine].reset();
    }

    /**
     * Updates the specified engine with the supplied data.
     * @param engine The index of the engine to update.
     * @param data Array of bytes to update the engine with.
    **/
    static final void update(int engine, byte[] data)
    {
        update(engine, data, 0, data.length);
    }

    /**
     * Updates the specified engine with the supplied data, starting at the specified offset.
     * @param engine The index of the engine to update.
     * @param data Array of bytes to update the engine with.
     * @param offset The offset to start reading from the data at.
     * @param length How many bytes to read from the data, starting at the offset.
    **/
    static final void update(int engine, byte[] data, int offset, int length)
    {
        hashPool[engine].update(data, offset, length);
    }

    /**
     * Completes the hash computation and resets the engine.
     * @param engine The index of the engine to finalize.
     * @return The result of the hash computation.
    **/
    static final byte[] digest(int engine)
    {
        try
        {
            return hashPool[engine].digest();
        } finally{
            releaseEngine(engine);
        }
    }

    /**
     * Completes the hash computation after updating with the specified data, then resets the engine.
     * @param engine The index of the engine to finalize.
     * @param data Array of bytes to update the engine with.
     * @return The result of the hash computation.
    **/
    static final byte[] digest(int engine, byte[] data)
    {
        try
        {
            return hashPool[engine].digest(data);
        } finally{
            releaseEngine(engine);
        }
    }

    /**
     * Hashes the provided data.
     * @param data Array of bytes to compute the hash of.
     * @return The result of the hash computation.
    **/
    static final byte[] digest(byte[] data)
    {
        int engine = reserveEngine(true);
        try
        {
            return digest(engine, data);
        } finally{
            releaseEngine(engine);
        }
    }

    /**
     * Completes the hash computation and writes the result into the provided byte array, at the specified offset.
     * @param engine The index of the engine to finalize.
     * @param buffer Byte array that the results will be written into.
     * @param offset The offset to start writing the result at.
     * @param length The number of bytes alloted for writing the result into. SHA256 always yields a 32 byte result.
     * @return The number of bytes successfully written into the buffer.
     * @throws DigestException If an error occurs.
     */
    static final int digest(int engine, byte[] buffer, int offset, int length) throws DigestException
    {
        try
        {
            return hashPool[engine].digest(buffer, offset, length);
        } finally{
            releaseEngine(engine);
        }
    }
}
