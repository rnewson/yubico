-module(yubico).

-export([verify/3]).
-compile(export_all).

verify(OTP, _, _) when length(OTP) > 44 ->
    {error, bad_otp};
verify(OTP, _, _) when length(OTP) < 32 ->
    {error,bad_otp};
verify(OTP, HexKey, HexUID) when is_list(OTP), is_list(HexKey), is_list(HexUID) ->
    PublicID = lists:sublist(OTP, 1, length(OTP) - 32),
    Token = lists:sublist(OTP, length(OTP) - 31, 32),
    Key = hex_to_binary(HexKey),
    ExpectedUID = hex_to_binary(HexUID),
    Cipher = hex_to_binary(modhex_to_hex(Token)),
    Plain = decrypt(Key, Cipher),
    ActualCRC = crc16(Plain),
    <<ActualUID:6/binary, Counter:16/little, Low:16/little,
      High:8, Use:8/little, Random:16/little,
      CRC:16/little>> = Plain,
    case {ExpectedUID == ActualUID,
          ActualCRC == 16#f0b8} of
        {true, true} ->
            Props = [{plain, binary_to_list(Plain)},
                     {uid, ActualUID},
                     {counter, Counter band 16#7fff},
                     {low, Low},
                     {high, High},
                     {use, Use},
                     {random, Random},
                     {crc, CRC}],
            {ok, Props};
        _ ->
            {error, bad_otp}
    end.

modhex_to_hex(ModHex) when is_list(ModHex) ->
    [modhex_to_hex(C) || C <- ModHex];
modhex_to_hex($c) -> $0;
modhex_to_hex($b) -> $1;
modhex_to_hex($d) -> $2;
modhex_to_hex($e) -> $3;
modhex_to_hex($f) -> $4;
modhex_to_hex($g) -> $5;
modhex_to_hex($h) -> $6;
modhex_to_hex($i) -> $7;
modhex_to_hex($j) -> $8;
modhex_to_hex($k) -> $9;
modhex_to_hex($l) -> $a;
modhex_to_hex($n) -> $b;
modhex_to_hex($r) -> $c;
modhex_to_hex($t) -> $d;
modhex_to_hex($u) -> $e;
modhex_to_hex($v) -> $f.


hex_to_binary(Hex) when is_list(Hex) ->
    hex_to_binary(Hex, []).

hex_to_binary([], Acc) ->
    list_to_binary(lists:reverse(Acc));
hex_to_binary([32 | Rest], Acc) ->
    hex_to_binary(Rest, Acc);
hex_to_binary([A, B | Rest], Acc) ->
    hex_to_binary(Rest, [(hex_to_digit(A) * 16) + hex_to_digit(B) | Acc]).

hex_to_digit($0) -> 0;
hex_to_digit($1) -> 1;
hex_to_digit($2) -> 2;
hex_to_digit($3) -> 3;
hex_to_digit($4) -> 4;
hex_to_digit($5) -> 5;
hex_to_digit($6) -> 6;
hex_to_digit($7) -> 7;
hex_to_digit($8) -> 8;
hex_to_digit($9) -> 9;
hex_to_digit($a) -> 10;
hex_to_digit($b) -> 11;
hex_to_digit($c) -> 12;
hex_to_digit($d) -> 13;
hex_to_digit($e) -> 14;
hex_to_digit($f) -> 15;
hex_to_digit($A) -> 10;
hex_to_digit($B) -> 11;
hex_to_digit($C) -> 12;
hex_to_digit($D) -> 13;
hex_to_digit($E) -> 14;
hex_to_digit($F) -> 15.

crc16(Bin) when is_binary(Bin) ->
    crc16(binary_to_list(Bin));
crc16(List) when is_list(List) ->
    crc16(List, 16#ffff).

crc16([], Crc) ->
    Crc;
crc16([H | T], Crc) ->
    Crc1 = Crc bxor (H band 16#ff),
    crc16(T, shuffle(Crc1)).

shuffle(Crc) ->
    shuffle(8, Crc).

shuffle(0, Crc) ->
    Crc;
shuffle(N, Crc) ->
    Crc1 = Crc bsr 1,
    Crc2 = case (Crc band 1) of
        1 -> Crc1 bxor 16#8408;
        0 -> Crc1
    end,
    shuffle(N - 1, Crc2).

decrypt(Key, Data) ->
    IV = <<"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0">>,
    crypto:aes_cbc_128_decrypt(Key, IV, Data).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

crc16_1_test() ->
    ?assertEqual(62919, crc16([0, 1, 2, 3, 4])).

crc16_2_test() ->
    ?assertEqual(4470, crc16([16#fe])).

crc16_3_test() ->
    ?assertEqual(52149, crc16([16#55, 16#aa, 0, 16#ff])).

crc16_4_test() ->
    ?assertEqual(35339, crc16([16#1, 16#2, 16#3, 16#4, 16#5, 16#6,
        16#30, 16#75, 16#00, 16#09, 16#3d, 16#fa, 16#60, 16#ea])).

modhex_1_test() ->
    ?assertEqual(<<"test">>, hex_to_binary(modhex_to_hex("ifhgieif"))).

hex_1_test() ->
    ?assertEqual(<<"test">>, hex_to_binary("74657374")).

-endif.
