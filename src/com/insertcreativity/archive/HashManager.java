
package com.insertcreativity.archive;

import java.security.DigestException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

final class HashManager
{
    //Create one message digest for every processor available
    private final MessageDigest[] hashPool;
    //Stores the availability of each hash engine
    private final boolean[] available;

    /**
     * Creates a new hash manager, which keeps a pre-allocated stock of hash engines that can reserved for use by processes.
     * This helps parallelize file authentication and processing.
     * @throws NoSuchAlgorithmException If the platform doesn't support 256bit SHA algorithms.
    **/
    HashManager() throws NoSuchAlgorithmException
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
    }

    /**
     * Reserves an engine from the manager.
     * @param shouldWait Flag for whether the method should wait for an engine to become available if one isn't currently.
     * @return The index of the engine now reserved, or -1 if no engine was available and waiting was disabled.
    **/
    final synchronized int reserveEngine(boolean shouldWait)
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
                    wait();
                }catch(InterruptedException e){}
            } else{
                return -1;
            }
        }
    }

    /**
     * Releases a previously reserved engine.
     * @param engine The index of the engine to release.
     * @throws IllegalStateException If the specified index doesn't correspond to a reserved engine.
    **/
    final synchronized void releaseEngine(int engine) throws IllegalStateException
    {
        if(available[engine])
        {
            available[engine] = false;
        } else{
            throw new IllegalStateException("The specified engine is already available.");
        }
    }

    /**
     * Resets the specified engine to it's originally initialized state.
     * @param engine The engine index to reset.
    **/
    final void reset(int engine)
    {
        hashPool[engine].reset();
    }

    /**
     * Updates the specified engine with the supplied data.
     * @param engine The index of the engine to update.
     * @param data Array of bytes to update the engine with.
    **/
    final void update(int engine, byte[] data)
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
    final void update(int engine, byte[] data, int offset, int length)
    {
        hashPool[engine].update(data, offset, length);
    }

    /**
     * Completes the hash computation and resets the engine.
     * @param engine The index of the engine to finalize.
     * @return The result of the hash computation.
    **/
    final byte[] digest(int engine)
    {
        return hashPool[engine].digest();
    }

    /**
     * Completes the hash computation after updating with the specified data, then resets the engine.
     * @param engine The index of the engine to finalize.
     * @param data Array of bytes to update the engine with.
     * @return The result of the hash computation.
    **/
    final byte[] digest(int engine, byte[] data)
    {
        return hashPool[engine].digest(data);
    }

    /**
     * Completes the hash computation and writes the result into the provided byte array, at the specified offset
     * @param engine The index of the engine to finalize.
     * @param buffer Byte array that the results will be written into.
     * @param offset The offset to start writing the result at.
     * @param length The number of bytes alloted for writing the result into. SHA256 always yields a 32 byte result.
     * @return The number of bytes successfully written into the buffer.
     * @throws DigestException If an error occurs.
     */
    final int digest(int engine, byte[] buffer, int offset, int length) throws DigestException
    {
        return hashPool[engine].digest(buffer, offset, length);
    }
}
