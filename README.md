# pasten

We have got a cache of the following form:
    hash, 6 entries 

Each entry is a pair of encoding type, and data, stored continouosly in memory, with no
separators.
Whenever we insert a new entry, the entries: plain, decode, and encode are stored.
The code is as follows:
 ```for ( i = 0LL; i <= 5 && (*cache_entries)[i]; ++i )
  {
    encoding_len_2 = strlen(encoding);
    result = memcmp(mallocd, (*cache_entries)[i], encoding_len_2 + data_len);
    if ( !result )
      return result;
  }
  result = (int)mallocd;
  (*cache_entries)[i] = mallocd;
  return result;```
  we have a vulnerability here! If the entries are full, we override the next hash in the cache.    
  However, we have only 3 types on encodings, so we can't just fill the cache. Can we?
  In order to do that, we need to find a decoding that decodes different streams into the same
  output stream. Plain doesn't do that, neither hex. What about a85?

  a85 performs checks to validate the input, that is, 
  that the output is of length 4*(in/5)-3 at least, and that the chars are valid.
  However, that means we can put the padding wherever we want (not only at the end),
  and the same output will be reproduced.
  Thus, we can generate many encoded streams that are decoded into the same stream,
  allowing us to fill the cache.
  
  So we filled the cache. Now we override the hash. Since the hash is overriden with the stream
  ```<encoding><data>```, we need to make sure this stream is a hash that is controlled by us.
  The only valid stream for that is a85 (its chars are valid base16 digits),
  thus, we find a hash that starts with a85, (that is simple and done with a naive bruteforce),
  then we trunc the a85, and send the rest (since a85 is concatenated at the end)
  then, after we have overriden the hash
  we send:
  ```plain plain seed```
  where seed is the stream that generated the hash (simply 00Wf in our case).
  Since the ctf flag is in the cache, the server will fetch it instead of adding the seed,
  since the seed has the same hash of the flag (since we have overriden its stored hash),
  so the flag will be printed to the screen:
  ```CTF{nonc4nonical_3ncod1ngs_g00d_for_stego_g00d_for_pwn}```
