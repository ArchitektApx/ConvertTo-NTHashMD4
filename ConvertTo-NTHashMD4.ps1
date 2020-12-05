function ConvertTo-NTHashMD4 {
<#
.SYNOPSIS
    Calculate MD4/NTHash/NTLM Hashes in Powershell 
.DESCRIPTION
    Calculate MD4/NTHash/NTLM Hashes in Powershell 
    based on the work of Larry Song.
    (https://github.com/LarrysGIT/MD4-powershell)

    Fixes:

    The original can't properly handle UTF16-LE input 
    and strings that result in a message size of more than 55 bytes
    since there was an error in padding.
    (Problems started to unfold at 28 characters utf16 and more)
    
    A string in Powershell uses the String Class of .Net,
    therefore it is encoded as UTF16-LE.
    https://docs.microsoft.com/en-us/dotnet/standard/base-types/character-encoding-introduction#utf-16-code-units
    
    Due to the little endianness of UTF16-LE, the original way of making 
    an byte array from the input string resulted in it beeing treated as 
    ASCII/UTF8 for ascii chars (lost 8 Bit of zeros) and strange results 
    for non-ascii chars.

    Original Method: 
    $Array = [byte[]]@()
    if($String)
    {
        $Array = [byte[]]@($String.ToCharArray() | %{[int]$_})
    }

    Now the function treats input as UTF16-LE as expected and gives the 
    option for other encodings via parameters (for MD4).

    NT HASH/NTLM:
    This also means that the ouput is a valid NT Hash/NTLM Hash 
    for any given UTF16-LE input as NT Hash = md4(utf16-le(passphrase)).

    SecureStrings and Impact on performance:
    If you pass a SecureString the script tries to keep it kinda 'secure' by 
    trying to flush the plaintext from memory as soon as possible.
    https://get-powershellblog.blogspot.com/2017/06/how-safe-are-your-strings.html
    
    This has a quite noticable effect on performance but this is not really important 
    for most use-cases where you specificly choose SecureStrings.

    Example: 
    Measure-Command { 1..100 | % {ConvertTo-NTHashMD4 -SecureString $Creds.password} }
    Seconds           : 9
    Milliseconds      : 384
    Ticks             : 93846611
    Measure-Command { 1..100 | % {ConvertTo-NTHashMD4 -String 'password1'} }
    Seconds           : 0
    Milliseconds      : 795
    Ticks             : 7950702


    Reference:
    https://tools.ietf.org/html/rfc1320
.PARAMETER String
    A String on which the Hash should be calculated 
.PARAMETER SecureString
    A SecureString on which the Hash should be calculated
.PARAMETER Encoding 
    The encoding in which the string should be as
    'Real' Default is UTF16-LE
    Besides that allowed values are:
    ASCII
    UTF32 
    UTF8
    UTF7
    BigEndianUnicode  (aka UTF16-BE) 
    Latin1      (Only Powershell Core on Linux - replacement for Windows 1252)
    SysDefault  Windows1252/ISO-8869-1 for most Windows Installations (EU/USA)
                and UTF8 on Linux (and I guess MacOS?)
.PARAMETER bArray
    A byte array on which the Hash should be calculated
.PARAMETER Uppercase
    Output the string in all uppercase
.EXAMPLE
    Calculate the NTHash of a String
    "Password1" | ConvertTo-NTHashMD4 
    Calculate the NTHash of a SecureString
    [PSCredential]$CredObj.password | ConvertTo-NTHash 
.EXAMPLE 
    Calculate the NTHash of a pre-existing byte array
    ConvertTo-NTHashMD4 -bArray $bArray
.EXAMPLE 
    Choose different encodings for strings 
    (This does work on SecureStrings too, although I'm not sure why one would need that)
    ConvertTo-NTHashMD4 -String $UTF8String -Encoding UTF8
    ConvertTo-NTHashMD4 -SecureString $CredObj.password -Encoding ASCII
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false,
        ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [String]
        $String,

        [Parameter(Mandatory=$false,
        ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [SecureString]
        $SecureString,

        [Parameter(Mandatory=$false)]
        [ValidateSet('ASCII','UTF32','UTF8','BigEndianUnicode','UTF7','Latin1','SysDefault')]
        [String]
        $Encoding,

        [Parameter(Mandatory=$false,
        ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [Byte[]]
        $bArray,

        [Parameter(Mandatory=$false)]
        [Switch]
        $UpperCase
    )
    begin {
        switch ($Encoding) {
            'ASCII' {
                $Decoder = [System.Text.Encoding]::ASCII
            }
            'UTF32' {
                $Decoder = [System.Text.Encoding]::UTF32
            }
            'UTF8'{
                $Decoder = [System.Text.Encoding]::UTF8
            }
            'UTF7'{
                $Decoder = [System.Text.Encoding]::UTF7
            }
            'BigEndianUnicode' {
                $Decoder = [System.Text.Encoding]::BigEndianUnicode
            }
            'SysDefault' {
                $Decoder = [System.Text.Encoding]::Default
            }
            'Latin1'{
                if($PSVersionTable.PSVersion.Major -ge 6) {
                    if($isLinux -or $IsMacOS) {
                        $Decoder = [System.Text.Encoding]::Latin1
                    } else {
                        throw 'Latin1 is not supported on Windows'
                    }
                } else {
                    throw 'Latin1 is not supported on Windows'
                }
            }
            Default {
                $Decoder = [System.Text.Encoding]::Unicode
            }
        }
    }
    process {

        $Array = [byte[]]@()

        if($SecureString) {
            $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
            $SecStringPlain = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
            $Array = $Decoder.GetBytes($SecStringPlain)

            $SecStringPlain = $null
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
            [System.GC]::Collect()
        }
        if($String) { $Array = $Decoder.GetBytes($String) }
        if($bArray) { $Array = $bArray }

        # Copy the InputArray to an ArrayList for easy Additions
        $M = [System.Collections.ArrayList]@()
        for ($i = 0; $i -le ($Array.count -1); $i++) {
            $null = $M.Add($Array[$i])
        } 
        ## RFC 1320 3.1 Append Padding bits
        <# 
            "... a single "1" bit is appended to the message
            and then "0" bits are appended ...." 
            0x80 = 128 = 1000 0000
        #>
        $null = $M.Add(0x80)
        <#
            "... so that the length in bits of the padded 
            message becomes congruent to 448, modulo 512."
            448 % 512 = 448 Bit
        #>
        while ($M.count % 64 -ne 56) { $null = $M.Add(0) }
        <#
            "In all, at least one bit and at most 512 bits are appended."
            448 Bit + 64 Bit = 512 Bit
        #>
        for ($i = 1; $i -le 8; $i++) { $null = $M.Add([int]0) }
        
        # Convert the ArrayList into a ByteArray
        [Byte[]]$M = $M 
        <#
            3.2 Append Length 
            "A 64-bit representation of b (the length of the message before the
            padding bits were added) is appended to the result of the previous
            step"
            "At this point the resulting message (after padding with bits and with
            b) has a length that is an exact multiple of 512 bits"
        #>
        # Replace last 8 Padding Bytes from with b 
        @([BitConverter]::GetBytes($Array.Count * 8)).CopyTo($M, $M.Count - 8)

        # flush Inputarray if it came from a SecureString
        if($SecureString) {
            $Array = $Null
            [System.GC]::Collect()
        }

        # message digest buffer (A,B,C,D)
        $A = [Convert]::ToUInt32('0x67452301', 16)
        $B = [Convert]::ToUInt32('0xefcdab89', 16)
        $C = [Convert]::ToUInt32('0x98badcfe', 16)
        $D = [Convert]::ToUInt32('0x10325476', 16)
        
        # There is no unsigned number shift in C#, have to define one.
Add-Type -TypeDefinition @'
    public class Shift
    {
    public static uint Left(uint a, int b)
        {
            return ((a << b) | (((a >> 1) & 0x7fffffff) >> (32 - b - 1)));
        }
    }
'@ | Out-Null

        # define 3 auxiliary functions
        function FF([uint32]$X, [uint32]$Y, [uint32]$Z) {
            (($X -band $Y) -bor ((-bnot $X) -band $Z))
        }
        function GG([uint32]$X, [uint32]$Y, [uint32]$Z) {
            (($X -band $Y) -bor ($X -band $Z) -bor ($Y -band $Z))
        }
        function HH([uint32]$X, [uint32]$Y, [uint32]$Z) {
            ($X -bxor $Y -bxor $Z)
        }
        # processing message in one-word blocks
        for($i = 0; $i -lt $M.Count; $i += 64) {
            # Save a copy of A/B/C/D
            $AA = $A
            $BB = $B
            $CC = $C
            $DD = $D

            # Round 1 start
            $A = [Shift]::Left(($A + (FF -X $B -Y $C -Z $D) + [BitConverter]::ToUInt32($M[($i + 0)..($i + 3)], 0)) -band [uint32]::MaxValue, 3)
            $D = [Shift]::Left(($D + (FF -X $A -Y $B -Z $C) + [BitConverter]::ToUInt32($M[($i + 4)..($i + 7)], 0)) -band [uint32]::MaxValue, 7)
            $C = [Shift]::Left(($C + (FF -X $D -Y $A -Z $B) + [BitConverter]::ToUInt32($M[($i + 8)..($i + 11)], 0)) -band [uint32]::MaxValue, 11)
            $B = [Shift]::Left(($B + (FF -X $C -Y $D -Z $A) + [BitConverter]::ToUInt32($M[($i + 12)..($i + 15)], 0)) -band [uint32]::MaxValue, 19)

            $A = [Shift]::Left(($A + (FF -X $B -Y $C -Z $D) + [BitConverter]::ToUInt32($M[($i + 16)..($i + 19)], 0)) -band [uint32]::MaxValue, 3)
            $D = [Shift]::Left(($D + (FF -X $A -Y $B -Z $C) + [BitConverter]::ToUInt32($M[($i + 20)..($i + 23)], 0)) -band [uint32]::MaxValue, 7)
            $C = [Shift]::Left(($C + (FF -X $D -Y $A -Z $B) + [BitConverter]::ToUInt32($M[($i + 24)..($i + 27)], 0)) -band [uint32]::MaxValue, 11)
            $B = [Shift]::Left(($B + (FF -X $C -Y $D -Z $A) + [BitConverter]::ToUInt32($M[($i + 28)..($i + 31)], 0)) -band [uint32]::MaxValue, 19)

            $A = [Shift]::Left(($A + (FF -X $B -Y $C -Z $D) + [BitConverter]::ToUInt32($M[($i + 32)..($i + 35)], 0)) -band [uint32]::MaxValue, 3)
            $D = [Shift]::Left(($D + (FF -X $A -Y $B -Z $C) + [BitConverter]::ToUInt32($M[($i + 36)..($i + 39)], 0)) -band [uint32]::MaxValue, 7)
            $C = [Shift]::Left(($C + (FF -X $D -Y $A -Z $B) + [BitConverter]::ToUInt32($M[($i + 40)..($i + 43)], 0)) -band [uint32]::MaxValue, 11)
            $B = [Shift]::Left(($B + (FF -X $C -Y $D -Z $A) + [BitConverter]::ToUInt32($M[($i + 44)..($i + 47)], 0)) -band [uint32]::MaxValue, 19)

            $A = [Shift]::Left(($A + (FF -X $B -Y $C -Z $D) + [BitConverter]::ToUInt32($M[($i + 48)..($i + 51)], 0)) -band [uint32]::MaxValue, 3)
            $D = [Shift]::Left(($D + (FF -X $A -Y $B -Z $C) + [BitConverter]::ToUInt32($M[($i + 52)..($i + 55)], 0)) -band [uint32]::MaxValue, 7)
            $C = [Shift]::Left(($C + (FF -X $D -Y $A -Z $B) + [BitConverter]::ToUInt32($M[($i + 56)..($i + 59)], 0)) -band [uint32]::MaxValue, 11)
            $B = [Shift]::Left(($B + (FF -X $C -Y $D -Z $A) + [BitConverter]::ToUInt32($M[($i + 60)..($i + 63)], 0)) -band [uint32]::MaxValue, 19)
            # Round 1 end
            # Round 2 start
            $A = [Shift]::Left(($A + (GG -X $B -Y $C -Z $D) + [BitConverter]::ToUInt32($M[($i + 0)..($i + 3)], 0) + 0x5A827999) -band [uint32]::MaxValue, 3)
            $D = [Shift]::Left(($D + (GG -X $A -Y $B -Z $C) + [BitConverter]::ToUInt32($M[($i + 16)..($i + 19)], 0) + 0x5A827999) -band [uint32]::MaxValue, 5)
            $C = [Shift]::Left(($C + (GG -X $D -Y $A -Z $B) + [BitConverter]::ToUInt32($M[($i + 32)..($i + 35)], 0) + 0x5A827999) -band [uint32]::MaxValue, 9)
            $B = [Shift]::Left(($B + (GG -X $C -Y $D -Z $A) + [BitConverter]::ToUInt32($M[($i + 48)..($i + 51)], 0) + 0x5A827999) -band [uint32]::MaxValue, 13)

            $A = [Shift]::Left(($A + (GG -X $B -Y $C -Z $D) + [BitConverter]::ToUInt32($M[($i + 4)..($i + 7)], 0) + 0x5A827999) -band [uint32]::MaxValue, 3)
            $D = [Shift]::Left(($D + (GG -X $A -Y $B -Z $C) + [BitConverter]::ToUInt32($M[($i + 20)..($i + 23)], 0) + 0x5A827999) -band [uint32]::MaxValue, 5)
            $C = [Shift]::Left(($C + (GG -X $D -Y $A -Z $B) + [BitConverter]::ToUInt32($M[($i + 36)..($i + 39)], 0) + 0x5A827999) -band [uint32]::MaxValue, 9)
            $B = [Shift]::Left(($B + (GG -X $C -Y $D -Z $A) + [BitConverter]::ToUInt32($M[($i + 52)..($i + 55)], 0) + 0x5A827999) -band [uint32]::MaxValue, 13)

            $A = [Shift]::Left(($A + (GG -X $B -Y $C -Z $D) + [BitConverter]::ToUInt32($M[($i + 8)..($i + 11)], 0) + 0x5A827999) -band [uint32]::MaxValue, 3)
            $D = [Shift]::Left(($D + (GG -X $A -Y $B -Z $C) + [BitConverter]::ToUInt32($M[($i + 24)..($i + 27)], 0) + 0x5A827999) -band [uint32]::MaxValue, 5)
            $C = [Shift]::Left(($C + (GG -X $D -Y $A -Z $B) + [BitConverter]::ToUInt32($M[($i + 40)..($i + 43)], 0) + 0x5A827999) -band [uint32]::MaxValue, 9)
            $B = [Shift]::Left(($B + (GG -X $C -Y $D -Z $A) + [BitConverter]::ToUInt32($M[($i + 56)..($i + 59)], 0) + 0x5A827999) -band [uint32]::MaxValue, 13)

            $A = [Shift]::Left(($A + (GG -X $B -Y $C -Z $D) + [BitConverter]::ToUInt32($M[($i + 12)..($i + 15)], 0) + 0x5A827999) -band [uint32]::MaxValue, 3)
            $D = [Shift]::Left(($D + (GG -X $A -Y $B -Z $C) + [BitConverter]::ToUInt32($M[($i + 28)..($i + 31)], 0) + 0x5A827999) -band [uint32]::MaxValue, 5)
            $C = [Shift]::Left(($C + (GG -X $D -Y $A -Z $B) + [BitConverter]::ToUInt32($M[($i + 44)..($i + 47)], 0) + 0x5A827999) -band [uint32]::MaxValue, 9)
            $B = [Shift]::Left(($B + (GG -X $C -Y $D -Z $A) + [BitConverter]::ToUInt32($M[($i + 60)..($i + 63)], 0) + 0x5A827999) -band [uint32]::MaxValue, 13)
            # Round 2 end
            # Round 3 start
            $A = [Shift]::Left(($A + (HH -X $B -Y $C -Z $D) + [BitConverter]::ToUInt32($M[($i + 0)..($i + 3)], 0) + 0x6ED9EBA1) -band [uint32]::MaxValue, 3)
            $D = [Shift]::Left(($D + (HH -X $A -Y $B -Z $C) + [BitConverter]::ToUInt32($M[($i + 32)..($i + 35)], 0) + 0x6ED9EBA1) -band [uint32]::MaxValue, 9)
            $C = [Shift]::Left(($C + (HH -X $D -Y $A -Z $B) + [BitConverter]::ToUInt32($M[($i + 16)..($i + 19)], 0) + 0x6ED9EBA1) -band [uint32]::MaxValue, 11)
            $B = [Shift]::Left(($B + (HH -X $C -Y $D -Z $A) + [BitConverter]::ToUInt32($M[($i + 48)..($i + 51)], 0) + 0x6ED9EBA1) -band [uint32]::MaxValue, 15)

            $A = [Shift]::Left(($A + (HH -X $B -Y $C -Z $D) + [BitConverter]::ToUInt32($M[($i + 8)..($i + 11)], 0) + 0x6ED9EBA1) -band [uint32]::MaxValue, 3)
            $D = [Shift]::Left(($D + (HH -X $A -Y $B -Z $C) + [BitConverter]::ToUInt32($M[($i + 40)..($i + 43)], 0) + 0x6ED9EBA1) -band [uint32]::MaxValue, 9)
            $C = [Shift]::Left(($C + (HH -X $D -Y $A -Z $B) + [BitConverter]::ToUInt32($M[($i + 24)..($i + 27)], 0) + 0x6ED9EBA1) -band [uint32]::MaxValue, 11)
            $B = [Shift]::Left(($B + (HH -X $C -Y $D -Z $A) + [BitConverter]::ToUInt32($M[($i + 56)..($i + 59)], 0) + 0x6ED9EBA1) -band [uint32]::MaxValue, 15)

            $A = [Shift]::Left(($A + (HH -X $B -Y $C -Z $D) + [BitConverter]::ToUInt32($M[($i + 4)..($i + 7)], 0) + 0x6ED9EBA1) -band [uint32]::MaxValue, 3)
            $D = [Shift]::Left(($D + (HH -X $A -Y $B -Z $C) + [BitConverter]::ToUInt32($M[($i + 36)..($i + 39)], 0) + 0x6ED9EBA1) -band [uint32]::MaxValue, 9)
            $C = [Shift]::Left(($C + (HH -X $D -Y $A -Z $B) + [BitConverter]::ToUInt32($M[($i + 20)..($i + 23)], 0) + 0x6ED9EBA1) -band [uint32]::MaxValue, 11)
            $B = [Shift]::Left(($B + (HH -X $C -Y $D -Z $A) + [BitConverter]::ToUInt32($M[($i + 52)..($i + 55)], 0) + 0x6ED9EBA1) -band [uint32]::MaxValue, 15)

            $A = [Shift]::Left(($A + (HH -X $B -Y $C -Z $D) + [BitConverter]::ToUInt32($M[($i + 12)..($i + 15)], 0) + 0x6ED9EBA1) -band [uint32]::MaxValue, 3)
            $D = [Shift]::Left(($D + (HH -X $A -Y $B -Z $C) + [BitConverter]::ToUInt32($M[($i + 44)..($i + 47)], 0) + 0x6ED9EBA1) -band [uint32]::MaxValue, 9)
            $C = [Shift]::Left(($C + (HH -X $D -Y $A -Z $B) + [BitConverter]::ToUInt32($M[($i + 28)..($i + 31)], 0) + 0x6ED9EBA1) -band [uint32]::MaxValue, 11)
            $B = [Shift]::Left(($B + (HH -X $C -Y $D -Z $A) + [BitConverter]::ToUInt32($M[($i + 60)..($i + 63)], 0) + 0x6ED9EBA1) -band [uint32]::MaxValue, 15)
            # Round 3 end
            # Increment start
            $A = ($A + $AA) -band [uint32]::MaxValue
            $B = ($B + $BB) -band [uint32]::MaxValue
            $C = ($C + $CC) -band [uint32]::MaxValue
            $D = ($D + $DD) -band [uint32]::MaxValue
            # Increment end
        }

        # flush everything thats left of $M if it came from a SecureString
        if ($SecureString) {
            $M = $null
            [System.GC]::Collect()
        }

        # Output start
        $A = ('{0:x8}' -f $A) -ireplace '^(\w{2})(\w{2})(\w{2})(\w{2})$', '$4$3$2$1'
        $B = ('{0:x8}' -f $B) -ireplace '^(\w{2})(\w{2})(\w{2})(\w{2})$', '$4$3$2$1'
        $C = ('{0:x8}' -f $C) -ireplace '^(\w{2})(\w{2})(\w{2})(\w{2})$', '$4$3$2$1'
        $D = ('{0:x8}' -f $D) -ireplace '^(\w{2})(\w{2})(\w{2})(\w{2})$', '$4$3$2$1'
        # Output end

        # Output the Hash
        if($UpperCase) { "$A$B$C$D".ToUpper() }
        else { "$A$B$C$D" }
    }
}
