module RunBenchmark exposing (main)

import Benchmark exposing (..)
import Benchmark.Runner exposing (BenchmarkProgram, program)
import Bytes.Encode as Encode
import SHA1


main : BenchmarkProgram
main =
    program suite


fox =
    "The quick brown fox jumps over the lazy dog"


input =
    kb


inputBytes =
    Encode.encode (Encode.string input)


suite : Benchmark
suite =
    describe "Array.Hamt"
        [ Benchmark.benchmark "bytes"
            (\_ -> SHA1.fromBytes inputBytes)
        ]


kb =
    String.slice 0 999 warAndPeace


warAndPeace =
    """
“Well, Prince, so Genoa and Lucca are now just family estates of the Buonapartes. But I warn you, if you don’t tell me that this means war, if you still try to defend the infamies and horrors perpetrated by that Antichrist—I really believe he is Antichrist—I will have nothing more to do with you and you are no longer my friend, no longer my ‘faithful slave,’ as you call yourself! But how do you do? I see I have frightened you—sit down and tell me all the news.”

It was in July, 1805, and the speaker was the well-known Anna Pávlovna Schérer, maid of honor and favorite of the Empress Márya Fëdorovna. With these words she greeted Prince Vasíli Kurágin, a man of high rank and importance, who was the first to arrive at her reception. Anna Pávlovna had had a cough for some days. She was, as she said, suffering from la grippe; grippe being then a new word in St. Petersburg, used only by the elite.

All her invitations without exception, written in French, and delivered by a scarlet-liveried footman that morning, ran as follows:

“If you have nothing better to do, Count (or Prince), and if the prospect of spending an evening with a poor invalid is not too terrible, I shall be very charmed to see you tonight between 7 and 10—Annette Schérer.”

“Heavens! what a virulent attack!” replied the prince, not in the least disconcerted by this reception. He had just entered, wearing an embroidered court uniform, knee breeches, and shoes, and had stars on his breast and a serene expression on his flat face. He spoke in that refined French in which our grandfathers not only spoke but thought, and with the gentle, patronizing intonation natural to a man of importance who had grown old in society and at court. He went up to Anna Pávlovna, kissed her hand, presenting to her his bald, scented, and shining head, and complacently seated himself on the sofa.

“First of all, dear friend, tell me how you are. Set your friend’s mind at rest,” said he without altering his tone, beneath the politeness and affected sympathy of which indifference and even irony could be discerned.

“Can one be well while suffering morally? Can one be calm in times like these if one has any feeling?” said Anna Pávlovna. “You are staying the whole evening, I hope?”

“And the fete at the English ambassador’s? Today is Wednesday. I must put in an appearance there,” said the prince. “My daughter is coming for me to take me there.”

"""
