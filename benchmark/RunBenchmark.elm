module RunBenchmark exposing (main)

import Benchmark exposing (..)
import Benchmark.Runner exposing (BenchmarkProgram, program)
import Bytes.Encode as Encode
import SHA1


main : BenchmarkProgram
main =
    program suite


input =
    "The quick brown fox jumps over the lazy dog"


inputBytes =
    Encode.encode (Encode.string input)


suite : Benchmark
suite =
    describe "Array.Hamt"
        [ Benchmark.compare "initialize"
            "string"
            (\_ -> SHA1.fromString input)
            "bytes"
            (\_ -> SHA1.hashBytesValue inputBytes)
        ]
