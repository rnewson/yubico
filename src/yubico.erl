-module(yubico).

-export([verify/3]).
-compile(export_all).

verify(OTP, _, _) when length(OTP) > 44 ->
    bad_otp;
verify(OTP, _, _) when length(OTP) < 32 ->
    bad_otp;
verify(OTP, Key, UID) when is_list(OTP), is_list(Key), is_list(UID) ->
    PublicID = lists:sublist(OTP, 1, length(OTP) - 32),
    Token = lists:sublist(OTP, length(OTP) - 31, 32),

    Encrypted = hex_to_binary(modhex_to_hex(Token)),
    Decrypted = crypto:aes_cbc_128_decrypt(
        hex_to_binary(Key), <<"0000000000000000">>, Encrypted),
    <<UID2:6/binary,
      Counter:2/binary,
      Low:2/binary,
      Hi:1/binary,
      Use:8/unsigned,
      Nonce:16/integer-unsigned,
      Crc:16/integer-unsigned>> = Decrypted,
    [{public_id, PublicID},
     {uid, hex_to_binary(UID)},
     {uid2, UID2},
     {counter, Counter},
     {low, Low},
     {hi, Hi},
     {use, Use},
     {nonce, Nonce},
     {actual_crc, Crc},
     {expected_crc, crc16("hello")},
     {decrypted, Decrypted}].

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
    hex_to_binary(Rest, [list_to_integer([A, B], 16) band 16#ff | Acc]).

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

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

crc16_test() ->
    ?assertEqual(62919, crc16([0, 1, 2, 3, 4])),
    ?assertEqual(4470, crc16([16#fe])),
    ?assertEqual(52149, crc16([16#55, 16#aa, 0, 16#ff])),
    ?assertEqual(35339, crc16([16#1, 16#2, 16#3, 16#4, 16#5, 16#6,
                               16#30, 16#75, 16#00, 16#09, 16#3d,
                               16#fa, 16#60, 16#ea])).

-endif.
