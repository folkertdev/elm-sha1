from textwrap import wrap

"""
Generate SHA1 tests based on the CAVS test files
"""

module_template =  """module CAVS exposing (suite)

import Bitwise
import Expect
import SHA1
import Test exposing (describe, test)


suite =
    let
        toBytes =
            identity

        testSHA1 index hex bytes =
            test (String.fromInt index ++ " " ++ Debug.toString bytes) <|
                \_ ->
                    bytes 
                        |> SHA1.fromByte
                        |> SHA1.toHex
                        |> Expect.equal hex
    in
    describe "cavs test suite"
        [ describe "long" [{tests_long} ]
        , describe "short" [{tests_short} ]
        ]
"""

def formatHex(int32):
    return '0x' + int32


def formatHexes(int32s):
    return "[" + ", ".join(formatHex(v) for v in int32s) + "]"

def process_file(name):
    with open(name + ".rsp") as f:
        is_short = True 

        cut = 2 if is_short else 3

        content = f.read().split("\n\n")[cut:]

        tests = []

        for item in enumerate(v.split("\n") for v in content):
            if is_short:
                try:
                    (i, (length_, msg, md, *_)) = item
                except ValueError:
                    continue

                else:
                    length = int(length_[6:])

                    hexDigits = [ v.zfill(4) for v in wrap(msg[6:], 2) ][:length]

            else: 
                try:
                    (i, (msg, md, *_)) = item
                except ValueError:
                    continue
                else:
                    hexDigits = [ v.zfill(4) for v in wrap(msg[6:], 2) ]

            answer = md[5:] 
            template = """testSHA1 {}  "{}" (toBytes {}) """.format(i, answer, formatHexes(hexDigits))

            tests.append(template)
            
        return "\n    ,".join(tests)

if __name__ == '__main__':
    env = { "tests_long" : process_file("SHA1LongMsg"),  
            "tests_short" : process_file("SHA1ShortMsg") 
          }

    with open("CAVS.elm", "w+") as f:
        f.write(module_template.format(**env))
