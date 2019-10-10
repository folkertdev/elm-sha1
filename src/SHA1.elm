module SHA1 exposing
    ( Digest
    , fromString
    , toHex, toBase64
    , fromByteValues
    , fromBytes, toBytes
    )

{-| [SHA-1] is a [cryptographic hash function].
Although it is no longer considered cryptographically secure (as collisions can
be found faster than brute force), it is still very suitable for a broad range
of uses, and is a lot stronger than MD5.

[SHA-1]: https://en.wikipedia.org/wiki/SHA-1
[cryptographic hash function]: https://en.wikipedia.org/wiki/Cryptographic_hash_function

This package provides a way of creating SHA-1 digests from `String`s and `List
Int`s (where each `Int` is between 0 and 255, and represents a byte). It can
also take those `Digest`s and format them in [hexadecimal] or [base64] notation.
Alternatively, you can get the binary digest, using a `List  Int` to represent
the bytes.

[hexadecimal]: https://en.wikipedia.org/wiki/Hexadecimal
[base64]: https://en.wikipedia.org/wiki/Base64

**Note:** Currently, the package can only create digests for around 200kb of
data. If there is any interest in using this package for hashing >200kb, or for
hashing [elm/bytes], [let me know][issues]!

[elm/bytes]: https://github.com/elm/bytes
[issues]: https://github.com/TSFoster/elm-sha1/issues

@docs Digest


# Creating digests

@docs fromString


# Formatting digests

@docs toHex, toBase64


# Binary data

@docs fromByteValues, toByteValues
@docs fromBytes, toBytes

-}

import Array exposing (Array)
import Bitwise exposing (and, complement, or, shiftLeftBy, shiftRightZfBy)
import Bytes exposing (Bytes, Endianness(..))
import Bytes.Decode as Decode exposing (Decoder, Step(..))
import Bytes.Encode as Encode
import Hex



-- TYPES


{-| The code uses a 5-tuple of integers in several different ways. They are sometimes converted between, but we don't want to mix them up!

On the other hand, the conversions are not really needed so we'd rather not pay the performance cost of that conversion.
Enter phantom types; we distinguish the values at the type level, but they are the same value. Thus, the type checker will
help us get the logic right, but there is no runtime cost.

-}
type DigestT a
    = Digest Int Int Int Int Int


type DigestS
    = DigestS


type StateS
    = StateS


type DeltaStateS
    = DeltaStateS


{-| A type to represent a message digest. `SHA1.Digest`s are equatable, and you may
want to consider keeping any digests you need in your `Model` as `Digest`s, not
as `String`s created by [`toHex`](#toHex) or [`toBase64`](#toBase64).
-}
type alias Digest =
    DigestT DigestS


type alias DigestState =
    DigestT StateS


createDigestState : Int -> Int -> Int -> Int -> Int -> DigestState
createDigestState =
    Digest


type alias DeltaState =
    DigestT DeltaStateS


createDeltaState : Int -> Int -> Int -> Int -> Int -> DeltaState
createDeltaState =
    Digest



-- CONSTANTS


blockSize =
    64


numberOfWords =
    16



-- CALCULATING


{-| Create a digest from a `String`.

    "hello world" |> SHA1.fromString |> SHA1.toHex
    --> "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed"

-}
fromString : String -> Digest
fromString input =
    hashBytesValue (Encode.encode (Encode.string input))


{-| Sometimes you have binary data that's not representable in a string. Create
a digest from the raw "bytes", i.e. a `List` of `Int`s. Any items not between 0
and 255 are discarded.

    SHA1.fromBytes [72, 105, 33, 32, 240, 159, 152, 132]
    --> SHA1.fromString "Hi! 😄"

    [0x00, 0xFF, 0x34, 0xA5] |> SHA1.fromBytes |> SHA1.toBase64
    --> "sVQuFckyE6K3fsdLmLHmq8+J738="

-}
fromByteValues : List Int -> Digest
fromByteValues =
    hashBytesValue << Encode.encode << Encode.sequence << List.map Encode.unsignedInt8


{-| Create a digest from `Bytes`

This function is the most efficient of the three digest creation functions.

-}
fromBytes : Bytes -> Digest
fromBytes =
    hashBytesValue


hashBytesValue : Bytes -> Digest
hashBytesValue bytes =
    let
        byteCount =
            Bytes.width bytes

        -- The full message (message + 1 byte for message end flag (0x80) + 8 bytes for message length)
        -- has to be a multiple of 64 bytes (i.e. of 512 bits).
        -- The 4 is because the bitCountInBytes is supposed to be 8 long, but it's only 4 (8 - 4 = 4)
        zeroBytesToAppend =
            4 + modBy 64 (56 - modBy 64 (byteCount + 1))

        message =
            Encode.encode
                (Encode.sequence
                    [ Encode.bytes bytes
                    , Encode.unsignedInt8 0x80
                    , Encode.sequence (List.repeat zeroBytesToAppend (Encode.unsignedInt8 0))

                    -- The 3s are to convert byte count to bit count (2^3 = 8)
                    , byteCount |> shiftRightZfBy (0x18 - 3) |> and 0xFF |> Encode.unsignedInt8
                    , byteCount |> shiftRightZfBy (0x10 - 3) |> and 0xFF |> Encode.unsignedInt8
                    , byteCount |> shiftRightZfBy (0x08 - 3) |> and 0xFF |> Encode.unsignedInt8
                    , byteCount |> shiftLeftBy 3 |> and 0xFF |> Encode.unsignedInt8
                    ]
                )

        decodeChunk ( n, state ) =
            if n > 0 then
                reduceBytesMessage state
                    |> Decode.map (\new -> Loop ( n - 1, new ))

            else
                Decode.succeed (Done state)

        numberOfChunks =
            Bytes.width message // 64

        hashState =
            Decode.loop ( numberOfChunks, init ) decodeChunk
    in
    case Decode.decode hashState message of
        Just digest ->
            finalDigest digest

        Nothing ->
            -- impossible case
            finalDigest init


finalDigest : DigestState -> Digest
finalDigest (Digest h0 h1 h2 h3 h4) =
    Digest h0 h1 h2 h3 h4


reduceBytesMessage : DigestState -> Decoder DigestState
reduceBytesMessage state =
    Decode.succeed (addDeltas state)
        |> andMap (Decode.unsignedInt32 BE)
        |> andMap (Decode.unsignedInt32 BE)
        |> andMap (Decode.unsignedInt32 BE)
        |> andMap (Decode.unsignedInt32 BE)
        |> andMap (Decode.unsignedInt32 BE)
        |> andMap (Decode.unsignedInt32 BE)
        |> andMap (Decode.unsignedInt32 BE)
        |> andMap (Decode.unsignedInt32 BE)
        |> andMap (Decode.unsignedInt32 BE)
        |> andMap (Decode.unsignedInt32 BE)
        |> andMap (Decode.unsignedInt32 BE)
        |> andMap (Decode.unsignedInt32 BE)
        |> andMap (Decode.unsignedInt32 BE)
        |> andMap (Decode.unsignedInt32 BE)
        |> andMap (Decode.unsignedInt32 BE)
        |> andMap (Decode.unsignedInt32 BE)


addDeltas state b16 b15 b14 b13 b12 b11 b10 b9 b8 b7 b6 b5 b4 b3 b2 b1 =
    let
        words =
            [ b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12, b13, b14, b15, b16 ]
                |> Array.fromList

        (Digest h0 h1 h2 h3 h4) =
            state

        initialDeltaState =
            createDeltaState h0 h1 h2 h3 h4
                |> calculateDigestDeltas 0 b1
                |> calculateDigestDeltas 1 b2
                |> calculateDigestDeltas 2 b3
                |> calculateDigestDeltas 3 b4
                |> calculateDigestDeltas 4 b5
                |> calculateDigestDeltas 5 b6
                |> calculateDigestDeltas 6 b7
                |> calculateDigestDeltas 7 b8
                |> calculateDigestDeltas 8 b9
                |> calculateDigestDeltas 9 b10
                |> calculateDigestDeltas 10 b11
                |> calculateDigestDeltas 11 b12
                |> calculateDigestDeltas 12 b13
                |> calculateDigestDeltas 13 b14
                |> calculateDigestDeltas 14 b15
                |> calculateDigestDeltas 15 b16

        (Digest a b c d e) =
            reduceWordsHelp 0 initialDeltaState b1 b2 b3 b4 b5 b6 b7 b8 b9 b10 b11 b12 b13 b14 b15 b16
    in
    createDigestState (trim (h0 + a)) (trim (h1 + b)) (trim (h2 + c)) (trim (h3 + d)) (trim (h4 + e))


andMap =
    Decode.map2 (|>)



{-
   reduceBytesMessage : DigestState -> Decoder DigestState
   reduceBytesMessage state =
       Decode.succeed (addDeltas state)
           |> andMap (Decode.unsignedInt32 BE)
           |> andMap (Decode.unsignedInt32 BE)
           |> andMap (Decode.unsignedInt32 BE)
           |> andMap (Decode.unsignedInt32 BE)
           |> andMap (Decode.unsignedInt32 BE)
           |> andMap (Decode.unsignedInt32 BE)
           |> andMap (Decode.unsignedInt32 BE)
           |> andMap (Decode.unsignedInt32 BE)
           |> andMap (Decode.unsignedInt32 BE)
           |> andMap (Decode.unsignedInt32 BE)
           |> andMap (Decode.unsignedInt32 BE)
           |> andMap (Decode.unsignedInt32 BE)
           |> andMap (Decode.unsignedInt32 BE)
           |> andMap (Decode.unsignedInt32 BE)
           |> andMap (Decode.unsignedInt32 BE)
           |> andMap (Decode.unsignedInt32 BE)



   -- addDeltas state b16 b15 b14 b13 b12 b11 b10 b9 b8 b7 b6 b5 b4 b3 b2 b1 =


   addDeltas state b1 b2 b3 b4 b5 b6 b7 b8 b9 b10 b11 b12 b13 b14 b15 b16 =
       let
           (Digest h0 h1 h2 h3 h4) =
               state

           initialDeltaState =
               createDeltaState h0 h1 h2 h3 h4
                   |> calculateDigestDeltas 0 b16
                   |> calculateDigestDeltas 1 b15
                   |> calculateDigestDeltas 2 b14
                   |> calculateDigestDeltas 3 b13
                   |> calculateDigestDeltas 4 b12
                   |> calculateDigestDeltas 5 b11
                   |> calculateDigestDeltas 6 b10
                   |> calculateDigestDeltas 7 b9
                   |> calculateDigestDeltas 8 b8
                   |> calculateDigestDeltas 9 b7
                   |> calculateDigestDeltas 10 b6
                   |> calculateDigestDeltas 11 b5
                   |> calculateDigestDeltas 12 b4
                   |> calculateDigestDeltas 13 b3
                   |> calculateDigestDeltas 14 b2
                   |> calculateDigestDeltas 15 b1

           (Digest a b c d e) =
               reduceWordsHelp 0 initialDeltaState b16 b15 b14 b13 b12 b11 b10 b9 b8 b7 b6 b5 b4 b3 b2 b1
       in
       createDigestState (trim (h0 + a)) (trim (h1 + b)) (trim (h2 + c)) (trim (h3 + d)) (trim (h4 + e))
-}


accumulateDeltas : Int -> Array Int -> DeltaState -> DeltaState
accumulateDeltas i state deltaState =
    if i < blockSize then
        let
            newElement =
                reduceWords (i + numberOfWords) state
        in
        accumulateDeltas (i + 1)
            (Array.push newElement state)
            (calculateDigestDeltas (i + numberOfWords) newElement deltaState)

    else
        deltaState


reduceWordsHelp i deltaState b16 b15 b14 b13 b12 b11 b10 b9 b8 b7 b6 b5 b4 b3 b2 b1 =
    if i < blockSize then
        let
            value =
                b3
                    |> Bitwise.xor b8
                    |> Bitwise.xor b14
                    |> Bitwise.xor b16
                    |> rotateLeftBy 1
        in
        reduceWordsHelp (i + 1) (calculateDigestDeltas (i + numberOfWords) value deltaState) b15 b14 b13 b12 b11 b10 b9 b8 b7 b6 b5 b4 b3 b2 b1 value

    else
        deltaState


calculateDigestDeltas : Int -> Int -> DeltaState -> DeltaState
calculateDigestDeltas index int (Digest a b c d e) =
    let
        f =
            if index < 20 then
                or (and b c) (and (trim (complement b)) d)

            else if index < 40 then
                Bitwise.xor b (Bitwise.xor c d)

            else if index < 60 then
                or (or (and b c) (and b d)) (and c d)

            else
                Bitwise.xor b (Bitwise.xor c d)

        k =
            if index < 20 then
                0x5A827999

            else if index < 40 then
                0x6ED9EBA1

            else if index < 60 then
                0x8F1BBCDC

            else
                0xCA62C1D6

        newA =
            rotateLeftBy 5 a
                |> (+) f
                |> Bitwise.and 0xFFFFFFFF
                |> (+) e
                |> Bitwise.and 0xFFFFFFFF
                |> (+) k
                |> Bitwise.and 0xFFFFFFFF
                |> (+) int
                |> Bitwise.and 0xFFFFFFFF
    in
    createDeltaState
        newA
        a
        (rotateLeftBy 30 b)
        c
        d


trim : Int -> Int
trim =
    and 0xFFFFFFFF


reduceWords : Int -> Array Int -> Int
reduceWords index words =
    let
        get i =
            case Array.get (index - i) words of
                Nothing ->
                    0

                Just v ->
                    v

        val =
            get 3
                |> Bitwise.xor (get 8)
                |> Bitwise.xor (get 14)
                |> Bitwise.xor (get 16)
                |> rotateLeftBy 1
    in
    val


rotateLeftBy : Int -> Int -> Int
rotateLeftBy amount i =
    trim <| shiftRightZfBy (32 - amount) i + trim (shiftLeftBy amount i)


init : DigestState
init =
    createDigestState 0x67452301 0xEFCDAB89 0x98BADCFE 0x10325476 0xC3D2E1F0



-- FORMATTING


{-| If you need the raw digest instead of the textual representation (for
example, if using SHA-1 as part of another algorithm), `toBytes` is what you're
looking for!

    "And the band begins to play"
        |> SHA1.fromString
        |> SHA1.toBytes
    --> [ 0xF3, 0x08, 0x73, 0x13
    --> , 0xD6, 0xBC, 0xE5, 0x5B
    --> , 0x60, 0x0C, 0x69, 0x2F
    --> , 0xE0, 0x92, 0xF4, 0x53
    --> , 0x87, 0x3F, 0xAE, 0x91
    --> ]

-}
toBytes : Digest -> List Int
toBytes (Digest a b c d e) =
    List.concatMap wordToBytes [ a, b, c, d, e ]


wordToBytes : Int -> List Int
wordToBytes int =
    [ int |> shiftRightZfBy 0x18 |> and 0xFF
    , int |> shiftRightZfBy 0x10 |> and 0xFF
    , int |> shiftRightZfBy 0x08 |> and 0xFF
    , int |> and 0xFF
    ]


{-| One of the two canonical ways of representing a SHA-1 digest is with 40
hexadecimal digits.

    "And our friends are all aboard"
        |> SHA1.fromString
        |> SHA1.toHex
    --> "f9a0c23ddcd40f6956b0cf59cd9b8800d71de73d"

-}
toHex : Digest -> String
toHex (Digest a b c d e) =
    wordToHex a ++ wordToHex b ++ wordToHex c ++ wordToHex d ++ wordToHex e


wordToHex : Int -> String
wordToHex int =
    let
        left =
            int |> shiftRightZfBy 0x10

        right =
            int |> and 0xFFFF
    in
    [ left, right ]
        |> List.map (Hex.toString >> String.padLeft 4 '0')
        |> String.concat



-- Base64 uses 1 character per 6 bits, which doesn't divide very nicely into our
-- 5 32-bit  integers! The  base64 digest  is 28  characters long,  although the
-- final character  is a '=',  which means it's  padded. Therefore, it  uses 162
-- bits  of entropy  to display  our 160  bit  digest, so  the digest  has 2  0s
-- appended.


{-| One of the two canonical ways of representing a SHA-1 digest is in a 20
digit long Base64 binary to ASCII text encoding.

    "Many more of them live next door"
        |> SHA1.fromString
        |> SHA1.toBase64
    --> "jfL0oVb5xakab6BMLplGe2XPbj8="

-}
toBase64 : Digest -> String
toBase64 (Digest a b c d e) =
    [ a |> shiftRightZfBy 8
    , (a |> and 0xFF |> shiftLeftBy 16) + (b |> shiftRightZfBy 16)
    , (b |> and 0xFFFF |> shiftLeftBy 8) + (c |> shiftRightZfBy 24)
    , c |> and 0x00FFFFFF
    , d |> shiftRightZfBy 8
    , (d |> and 0xFF |> shiftLeftBy 16) + (e |> shiftRightZfBy 16)
    , e |> and 0xFFFF |> shiftLeftBy 8
    ]
        |> List.map intToBase64
        |> String.concat
        |> String.dropRight 1
        |> (\s -> s ++ "=")



-- Converts the least-significant 24 bits to 4 base64 chars


intToBase64 : Int -> String
intToBase64 int =
    [ int |> shiftRightZfBy 18 |> and 0x3F
    , int |> shiftRightZfBy 12 |> and 0x3F
    , int |> shiftRightZfBy 6 |> and 0x3F
    , int |> and 0x3F
    ]
        |> List.map Array.get
        |> List.filterMap ((|>) base64Chars)
        |> String.fromList


base64Chars : Array Char
base64Chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        |> String.toList
        |> Array.fromList



-- HELPERS


array : Int -> Decoder a -> Decoder (Array a)
array n decoder =
    Decode.loop ( n, Array.empty ) (arrayHelp decoder)


arrayHelp decoder ( i, accum ) =
    if i > 0 then
        decoder
            |> Decode.map (\newValue -> Loop ( i - 1, Array.push newValue accum ))

    else
        Decode.succeed (Done accum)


arrayIndexedFoldl : (Int -> a -> b -> b) -> b -> Array a -> b
arrayIndexedFoldl step initial arr =
    let
        folder element ( i, state ) =
            ( i + 1, step i element state )
    in
    Array.foldl folder ( 0, initial ) arr
        |> Tuple.second
