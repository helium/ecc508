%% Native Erlang CRC-16 IBM (?) Module
%%
%% @maintainer Helium
%% @updated 20 Jun 2018

-module(crc16).

-export([calc/1, rev/1]).

-spec calc(binary()) -> <<_:16>>.
calc(Bin) ->
	calc(Bin,16#0000).

-spec calc(binary(), non_neg_integer()) -> <<_:16>>.
calc(<<>>,CRC) ->
	rev(<<CRC:16>>);
calc(<<Value:8,Rest/binary>>,CRC) when Value =< 255 ->
	calc(Rest,calc_small(Value, 16#01, CRC)).

calc_small(Value, ShiftRegister, CRC) when ShiftRegister =< 128 ->
	DataBit = case not ((Value band ShiftRegister) == 0) of
		true -> 16#01;
		false -> 16#00
	end,
	CRCBit = CRC bsr 15,
	<<NewCRC:16/integer-unsigned-big>> = <<((CRC bsl 1) band 16#FFFF):16/integer-unsigned-big>>,
	case not ((DataBit bxor CRCBit) == 0) of
		true -> calc_small(Value, ShiftRegister bsl 1, NewCRC bxor 16#8005);
		false -> calc_small(Value, ShiftRegister bsl 1, NewCRC)
	end;
calc_small(_, ShiftRegister, CRC) when ShiftRegister > 128 ->
	CRC.

-spec rev(<<_:16>>) -> <<_:16>>.
rev(Binary) ->
	<<X:16/integer-little>> = Binary,
	<<X:16/integer-big>>.
