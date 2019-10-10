module Tests exposing (suite)

import Bytes.Encode as Encode
import Expect exposing (Expectation)
import Fuzz exposing (Fuzzer)
import Hex
import Random exposing (Generator)
import Regex exposing (Regex)
import Result exposing (Result)
import SHA1
import Test exposing (..)


type TestCase
    = TestCase Input String String


type Input
    = FromBytes (List Int)
    | FromString String


suite : Test
suite =
    if True then
        (fromWikipedia
            ++ unicode
            ++ fromDevRandom
            ++ fromBytes
            ++ weirdBytes
            |> List.map makeTest
        )
            |> describe "SHA-1"

    else
        foo


foo =
    test "using `Bytes`" <|
        \_ ->
            Encode.string "The quick brown fox jumps over the lazy dog"
                |> Encode.encode
                |> SHA1.fromBytes
                |> SHA1.toHex
                |> Expect.equal "foo"


fromWikipedia : List TestCase
fromWikipedia =
    [ TestCase (FromString "The quick brown fox jumps over the lazy dog") "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12" "L9ThxnotKPzthJ7hu3bnORuT6xI="
    , TestCase (FromString "The quick brown fox jumps over the lazy cog") "de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3" "3p8sf9JeGzr60+haC9F9mxANtLM="
    , TestCase (FromString "") "da39a3ee5e6b4b0d3255bfef95601890afd80709" "2jmj7l5rSw0yVb/vlWAYkK/YBwk="
    ]


unicode : List TestCase
unicode =
    [ TestCase (FromString "👍") "78654ffdf2db3ef8dd605074250103f770177eb6" "eGVP/fLbPvjdYFB0JQED93AXfrY="
    , TestCase (FromString "🏴\u{E0067}\u{E0062}\u{E0073}\u{E0063}\u{E0074}\u{E007F}") "55bcc651f90bf1c3d5e9fcac0b52500ec3229aa2" "VbzGUfkL8cPV6fysC1JQDsMimqI="
    ]


fromDevRandom : List TestCase
fromDevRandom =
    [ TestCase (FromString "9eM0Cv/GpoLdtOrRRcXFGhIcqSxiPwzwVjz5Qj9+EsAn2Rx6WH/DcnWgLA9tYtwIC91UvjpAIhgaPPGjzmCY9VLy/bZXU7dGS/Yp1jNetmsbgglNWRBGbzRnr8kkDUNNX3OKpqLAB2pooTbhYlFBGhWZ2j00opJUcuoyjW1LkeklT/PGQuyxYMbG4Msjf/XHziKtL251f0ZpV3RbfVpfOdlyWp6ebV+gQZwYuU25Z4QpRS1ANd7Ko17RgmqsfbfxEC5qFKCojBp4CFInqttee/PAES+E5I+4Kmn1shOYHmal8ASm61CGsGcnx/sKBqJVoafGqiuuy/vv+QlXoSeDbRG6kvOrABNpEVKSPcNKY8xgiVES1CM1ZsCgVT2YVDS2Ag8OOO/9W1r8638hbuWPrkd3HxR5ixM7r2T/Q07PWTo/q5YMTsIWs/ecw3hrW1/wCq78MbqkEBoERHlTO7fSGlzXU+L/SPV6Qt/LXalfoGnX77M5cuOfh8AuT1vvmoYqMttPwh2aFIAA3S7/4B8hlsU2BZV/019Qh/aRrl/li807qOMvVcUYk1VE8fx9JmPQKKEJYQTDuc3crZsEmEgzosKQ4MtUz024OmNI3gmw/AMGZxtde7BKtTcooNf+SWKvkKBq6z16qYvphISln6Xwzm7yl7NoNKJ6nUlfqtPPePZJcuNMdQNU70ZhEHQNyaRiQezok4OhELQZFE9/T9InBjgx/Qo=") "e67c0c12a5e85c3ca79e1ca862ee662d6497cca1" "5nwMEqXoXDynnhyoYu5mLWSXzKE="
    , TestCase (FromString "fHgSIfF8BJaOvRcmVOv+Va95N9xHWlLPMFVLWvtO7RtyA6C4wJW+532jpCP7GqoInd5CPNuMCxV3fYmtPBtTJPfD+snGX61JXuxQBNQnS/BSJ2H+a64x+dkzK5p4BpJsOAW8lrBhu3B0GCuOmr34elDW7dYEWEAEajRLZ0UStMbjL0F7KJuY36SRRxswAc43rMwpb314zdtIiI7rWgwEnuOJa+AMpGtEeR1l/k8zbSgAu4DR0YHzKrpUMv+h2Ljc2/Fj8FFHQPin/e9Zbbr2QFV3+XUiKEEVuXZIUCRhJB2Zr/YIAZz085MvxkEt1uDcpY63VhgkUg2KX9Vfc1dnE6rOTdA6IGtvZEmoFuUPtz6arFITXXIaiCzlvzhLPXT7Q133kn2u9NGRNFUVJY/qQPqJINmHbs88ynEOXHTYph+VMKN+2lELF+bqZrkkuo7t7Fa5jjTNgbMxuLCEoDgtGP+WEJJElDpdLSlLYpGZ42ioaOzqVyncjanD/2gJNg2sWT/EM+3BLEEpzAQx8W80vURSJ7HGWYOQjdhzxer2ifIW0Y3jjLUrKTd9SfcQ0IHOaDyddGVq+CmHAnJA/6nzK/jn5qvXgTdtACHwxjAEXUTwTaFvKPziMwrec29ePr7/ToCMQNzZWhDlhuYo8aZHjvuOcI+Nx0bjHtkMioM1kuFTzDX20kVeK0Vc0Zhpe1hGsbsw1d73vTvHJV5Wq7DjYdmVdJrg79dWKMljLNYlxXRTk7lnqYS3fFGZ3lInbT/T8EaxB46CyEUMHcgLFAnevTRXmbDat0ST1wWhSgS01hFBRWH8EqUVW8POnqki5ch5itMHDRiR1FyZlG785uXCFveTv/7hjjqkYZCEdRNe5hqOMIbqkihqSp5xr2xxUnrCE9E8nkvI3o+K/Ws5t2+s8XrYksqRF1DJ2CfMBJ+gQo8h5tgEfI1FeDr5J6oLDMm+z0ncV6mjZYotUgLfNWcLaRNNkOT262oCXY7ROXtm1WygOT3waQztkg1FjHYTPT63RKj8oUeffrKRA7F3lKX8Fb85PPTqxVvh5ei8QWcJCG3wz/lPIITM2lhmBtYzYZnf7xooldpf+tkqqvU0QZgjZ4SY+4UlkDP85n43rK4Ko1Sgfs2zEeLrqlOLTSOW+JbiAzL+ebJdos6BvCPU6ySRCFPCd/i4E5fSsOay/J81wk01F56Pq2WUzGt+EEJyO0V0TbYruWB5I20x33+77J4jjPn8dp7P6x4nbLQiQs1FNh4O4C/EWp5T6tslNN0oscmkRswTsYlyIdhb1LLSZwanIAaOJdfhBgSfCT4/wildfhA/lnpE0hkXeyMSatAqr6DR4zTmpNEWd+dnJ/4avSVrJCuFJEon/0vhgwnBq1bIh2H3ZYscq985Qiag73fpZtZsWocLkqXYVxMunkw4IYUiBNdrVWQ3mewEN1AR52CqUUczYDr8DWu2B0lyS5dAMF/HCPzxkbIahbqOt8tsyz6ii/Fn9y71psv2ywq3G6arbHciuj9KM9T9RatPT/l81SmrYN2M1KaDx7hbr+53rbsUsHIUCciL3me/tA91MjDinVRJl2soB8kMzbMwT5jXQ7Fny9yRi/4C2VqapFB+Ahmghmflsr4EvXeTuH9STev/n4r5KPxS6kTjVosEynCgUh0GZ4MRUdiXfu+KFKCStVc1sW0oE8sypkzDCzS5obwjt+jFnW4as5TFFfEgH1gsqx+XEIh6CX/e0mczK6PaTYkGUQCDF2VpruiIKeyMPwmm5PqhyAISpCmjRd4zDUPv0ZdBYilrp5FhFRp67DDpXe7MN0hPUX4sXqq93mfy34XkvcfafE6NvWIrPuo7VFGR8SEPzx1ht1zYhLMHl6kFQwshIipNdV7gv3SXzkbexQDX3rFD3OzqVqihOzGt+pv0xdV2VVC9XKrTvjccHqTSXveIbURrf6g3ZcBUJS2z/i/VU3j+b4hLQsSmB98IskUV3jf7TXLkWATXeycArchmR7XTDIpgl02y9PrZiuhOrsaYEl5m6O3kpZJJniI3iOMf57Ne/GQ7z0+66d8ifxSv1cvy/ygzEFf835e1xFnOTuIwZcZ3zjpUCRE6/nZ8U8Y+TL3HfdT2bE0tidiwhI8cC1f+Z0lrXHAx5ACFiQNrdCFL2CkJsL7XJMTj8SMrFNxdpQSSvIYqQ/djXtTytpq+ujlfgoMSyNFuwp2FiQZPcSQuGlj6rfH1GoQwzrGsDdP3w+Oz7GLiVtm2SHI857lJGVLsAnaEQ6zGebm9mFlV8Z5SGm3sYdbe3Qfxk9lf7KNvzHVM4A6JZD/YkVOfApJarTdKnQJ6AJg58Pmx90eLsqF5fCq5SapRRVidSlLPsus48KWVqYJJxilkxwLDtziUxR/SjERgCDPSL0gin4kkGFwLg3rT7SE/zmIXYMDsqExoTJbFgMwd2bSsTUx9w7xyk6LCaiwRSYAnBueAFE0zSM6DlLjJvT7wJjN5CRag76Z3Vy31kF837dsH5KuE+JFfQ+xS9U8xfHTMwdGt/FHANFtgO5WYAMwO+cnkBAwTUcypN5J7Xwj289Jdn9rMsPUOBPRQtGgQKSHcjVTwNW6NuqeNe6T6bE8aWtSYWeMEJmqCMs1dp38xONi6xZjDuCxm7GeqTR4ZZoMN9VIvlEGkkfifVAzMSq8dTyrdNAKT4EilaE/oYfGxpHX3T+sqo2DYplXq5i2xD3Y5+3BZcCzfC3G6gQS2AMAupwOP6yy3b55i4T7inil61+c1f8e0Rb0ybtEEFYEzq3QQ3VLSZjpNiOUunebLBwu7dQ5alZqLv4JDB5N4X9kwDUOCa/Ds0gsIKUE3U9G+dpAX3bUGC4QkDsNIWb+yQVQcGkhbI8a2cd6IqhmE9RgZeonNCzexXfyQB3+hDBOGOe2sNGIMT7ZWUD8tOx2CgUX68hmrCajaXcPeBCcK") "fbadba9aa61b6ea574b013e05593f9711118b228" "+626mqYbbqV0sBPgVZP5cREYsig="
    ]


fromBytes : List TestCase
fromBytes =
    [ TestCase (FromBytes (List.range 0 255)) "4916d6bdb7f78e6803698cab32d1586ea457dfc8" "SRbWvbf3jmgDaYyrMtFYbqRX38g="
    , TestCase (FromBytes (List.repeat 200000 184)) "707d33fe36b8bf5d21568058370ad9b70c5d1bfc" "cH0z/ja4v10hVoBYNwrZtwxdG/w="
    ]


weirdBytes : List TestCase
weirdBytes =
    [ TestCase (FromBytes (List.repeat 64 54 ++ List.repeat 310 46)) "08afccd24bce328ae74661653ca103df02cba690" "CK/M0kvOMornRmFlPKED3wLLppA="
    , TestCase (FromBytes (List.repeat 64 54 ++ List.repeat 311 46)) "bd8b2089549d57a05becbace5112c2c593b1af8b" "vYsgiVSdV6Bb7LrOURLCxZOxr4s="
    , TestCase (FromBytes (List.repeat 64 54 ++ List.repeat 312 46)) "c6045cfc2468675660d3ff788225229c6b7ab422" "xgRc/CRoZ1Zg0/94giUinGt6tCI="
    ]


makeTest : TestCase -> Test
makeTest (TestCase input hex base64) =
    let
        ( description, digest, encoder ) =
            case input of
                FromString str ->
                    ( "String: " ++ str, SHA1.fromString str, Encode.string str )

                FromBytes bytes ->
                    ( String.fromInt (List.length bytes) ++ " bytes", SHA1.fromByteValues bytes, Encode.sequence (List.map Encode.unsignedInt8 bytes) )
    in
    describe description
        [ test "Hex representation" <|
            \_ -> Expect.equal (SHA1.toHex digest) hex
        , test "Base64 representation" <|
            \_ -> Expect.equal (SHA1.toBase64 digest) base64
        , test "Raw bytes" <|
            \_ ->
                SHA1.toBytes digest
                    |> List.map (Hex.toString >> String.padLeft 2 '0')
                    |> String.concat
                    |> Expect.equal hex
        , test "using `Bytes`" <|
            \_ ->
                encoder
                    |> Encode.encode
                    |> SHA1.fromBytes
                    |> SHA1.toHex
                    |> Expect.equal hex
        ]
