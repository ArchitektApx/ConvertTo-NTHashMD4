Calculate MD4 Hashes based on the work of Larry Song.
(https://github.com/LarrysGIT/MD4-powershell)

##Fixes

The original can't properly handle UTF16-LE input 
and strings that result in a message size of more than 55 bytes.
(Problems started to unfold at 28 characters utf16 and more)
    
A string in Powershell uses the String Class of .Net,
therefore it is encoded as UTF16-LE.
https://docs.microsoft.com/en-us/dotnet/standard/base-types/character-encoding-introduction#utf-16-code-units
    
Due to the little endianness of UTF16-LE, the original way of making 
an byte array from the input string resulted in it beeing treated as 
ASCII/UTF8 for ascii chars (lost 8 Bit of zeros) and strange results 
for non-ascii chars.

# Original Method 
```powershell    
    $Array = [byte[]]@()
    if($String)
    {
        $Array = [byte[]]@($String.ToCharArray() | %{[int]$_})
    }
```
    
Now the function treats input as UTF16-LE as expected and gives the 
option for other encodings via parameters (for MD4).

# NT HASH/NTLM
This also means that the ouput is a valid NT Hash/NTLM Hash 
for any given UTF16-LE input as NT Hash = md4(utf16-le(passphrase))

# SecureStrings
You can pass a SecureStrings and the Script tries its best to keep the
string as plaintext for as short as possible.

https://get-powershellblog.blogspot.com/2017/06/how-safe-are-your-strings.html


# Reference
https://tools.ietf.org/html/rfc1320