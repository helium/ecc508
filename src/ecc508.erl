-module(ecc508).

-include_lib("public_key/include/public_key.hrl").

%% API exports
-export([wake/1,
         genkey/4,
         nonce/3,
         digest_init/2, digest_update/3, digest_finalize/3,
         random/1, random/2,
         sign/3, verify/4,
         pause/2,
         write/3
        ]).
%% supporting functions
-export([encode_address/1,
         execute/2,
         command_spec/1, command/4
        ]).

-type address() :: {otp, Block::non_neg_integer(), Offset::non_neg_integer()} |
                   {config, Block::non_neg_integer(), Offset::non_neg_integer()} |
                   {data, Slot::non_neg_integer(), Block::non_neg_integer()} |
                   {data, Slot::non_neg_integer(), Block::non_neg_integer(), Offset::non_neg_integer()}.
-export_type([address/0]).

-define(CMDGRP_COUNT_MIN, 4).
-define(CMDGRP_COUNT_MAX, 155).

-record(command_spec, {
                       name :: atom(),
                       opcode :: non_neg_integer(),
                       timing_typ :: non_neg_integer(),
                       timing_max :: pos_integer(),
                       resp = 4 :: non_neg_integer()
                      }).

-record(command, {
                  spec :: #command_spec{},
                  param1 :: <<_:8>>,
                  param2 :: <<_:16>>,
                  data = <<>> :: binary()
                 }).

%%====================================================================
%% API functions
%%====================================================================

wake(Pid) ->
    execute(Pid, command(wake)).

genkey(Pid, private, KeyId, Opts=#{from_scratch := _FromScratch,
                                   should_store := _ShouldStore}) ->
    RetryCount = maps:get(retry_count, Opts, 0),
    case RetryCount of
        3 ->
            {error, ecc_genkey_failed};
        _ ->
            case execute(Pid, command({genkey, private, KeyId, Opts})) of
                {error, ecc_response_ecc_fault} ->
                    genkey(Pid, private, KeyId, Opts#{retry_count => RetryCount + 1});
                {error, Error} ->
                    {error, Error};
                {ok, Data} ->
                    {ok, Data}
            end
    end;
genkey(Pid, public, KeyId, Opts=#{from_scratch := _FromScratch,
                                  should_store := _ShouldStore,
                                  key_id := _OriginalKeyID}) ->
    execute(Pid, command({genkey, public, KeyId, Opts})).



nonce(Pid, passtrough, Data) ->
    execute(Pid, command({nonce, passthrough, Data}));
nonce(Pid, preseed, Data) ->
    execute(Pid, command({nonce, preseed, Data}));
nonce(Pid, random, Data) ->
    nonce(Pid, {random, false}, Data);
nonce(Pid, {random, UpdateSeed}, Data) when is_boolean(UpdateSeed) ->
    execute(Pid, command({nonce, {random, UpdateSeed}, Data})).


-spec pause(I2C::pid(), Selector::non_neg_integer()) -> ok | {error, term()}.
pause(Pid, Selector) ->
    execute(Pid, command({pause, Selector})).


-spec random(I2C::pid()) -> {ok, binary()} | {error, term()}.
random(Pid) ->
    random(Pid, 16#00).

-spec random(I2C::pid(), Seed::non_neg_integer()) -> {ok, binary()} | {error, term()}.
random(Pid, Seed) ->
    execute(Pid, command({random, Seed})).


-record(digest, {
                 kind :: sha | hmac
                }).

-spec digest_init(I2C::pid(), {hmac, Slot::non_neg_integer()} | sha)
                 -> {ok, #digest{}} | {error, term()}.
digest_init(Pid, Kind) ->
    case execute(Pid,command({digest, {init, Kind}})) of
        ok -> {ok, #digest{kind=Kind}};
        {error, Error} -> {error, Error}
    end.

-spec digest_update(I2C::pid(), State::#digest{},
                    {data, Data::binary()} | {public, Slot::non_neg_integer()})
                   -> {ok, #digest{}} | {error, term()}.
digest_update(_Pid, State=#digest{}, {data, <<>>}) ->
    {ok, State};
digest_update(Pid, State=#digest{}, {public, Slot}) ->
    case execute(Pid, command({digest, {public, Slot}})) of
        ok -> {ok, State};
        {error, Error} -> {error, Error}
    end;
digest_update(Pid, State=#digest{}, {data, Data}) ->
    case byte_size(Data) > 64 of
        true ->
            <<Part:64/binary, Rest/binary>> = Data,
            case execute(Pid, command({digest, {update, Part}})) of
                ok -> digest_update(Pid, State, {data, Rest});
                {error, Error} -> {error, Error}
            end;
        false ->
            case execute(Pid, command({digest, {update, Data}})) of
                ok -> {ok, State};
                {error, Error} -> {error, Error}
            end
    end.

-spec digest_finalize(I2C::pid(), State::#digest{}, FinalData::binary())
                     -> {ok, <<_:32>>} | {error, term()}.
digest_finalize(Pid, State, FinalData) when byte_size(FinalData) =< 63 ->
    execute(Pid, command({digest, {finalize, {State#digest.kind, FinalData}}})).




%% @doc
%% sign/external is the only signing implementation thus far
%% as the more complicated internal form necessitates reading
%% and communication with the configuration zone.
%%
%% los sciento :(
%% end
-spec sign(I2C::pid(), external, KeyId::non_neg_integer()) -> {ok, binary()} | {error, term()}.
sign(Pid, external, KeyId) ->
    execute(Pid, command({sign, {external, KeyId}})).


-spec verify(I2C::pid(), external, Signature::binary(), PubKey::public_key:ec_public_key())
            -> ok | {error, term()}.
verify(Pid, external, Signature, ECPubKey) ->
    execute(Pid, command({verify, {external, Signature, ECPubKey}})).


-spec write(I2C::pid(), Address::address(), Data::<<_:32>> | <<_:256>>) -> ok | {error, term()}.
write(Pid, Address, <<Data/binary>>) ->
    execute(Pid, command({write, Address, Data})).



%%
%% Internal
%%

-spec command_spec(atom()) -> #command_spec{}.
command_spec(N=checkmac)    -> #command_spec{name=N, opcode=16#28, timing_typ=5,  timing_max=13};
command_spec(N=counter)     -> #command_spec{name=N, opcode=16#24, timing_typ=5,  timing_max=20};
command_spec(N=derivekey)   -> #command_spec{name=N, opcode=16#24, timing_typ=2,  timing_max=50};
command_spec(N=ecdh)        -> #command_spec{name=N, opcode=16#43, timing_typ=38, timing_max=58};
command_spec(N=gendig)      -> #command_spec{name=N, opcode=16#15, timing_typ=5,  timing_max=11};
command_spec(N=genkey)      -> #command_spec{name=N, opcode=16#40, timing_typ=11, timing_max=115};
command_spec(N=hmac)        -> #command_spec{name=N, opcode=16#11, timing_typ=13, timing_max=23};
command_spec(N=info)        -> #command_spec{name=N, opcode=16#30, timing_typ=0,  timing_max=1};
command_spec(N=lock)        -> #command_spec{name=N, opcode=16#17, timing_typ=8,  timing_max=32};
command_spec(N=mac)         -> #command_spec{name=N, opcode=16#08, timing_typ=5,  timing_max=14};
command_spec(N=nonce)       -> #command_spec{name=N, opcode=16#16, timing_typ=0,  timing_max=7};
command_spec(N=pause)       -> #command_spec{name=N, opcode=16#01, timing_typ=0,  timing_max=3};
command_spec(N=privwrite)   -> #command_spec{name=N, opcode=16#46, timing_typ=1,  timing_max=48};
command_spec(N=random)      -> #command_spec{name=N, opcode=16#1B, timing_typ=1,  timing_max=23, resp=32};
command_spec(N=read)        -> #command_spec{name=N, opcode=16#02, timing_typ=0,  timing_max=1};
command_spec(N=sha)         -> #command_spec{name=N, opcode=16#47, timing_typ=42, timing_max=50};
command_spec(N=sign)        -> #command_spec{name=N, opcode=16#41, timing_typ=7,  timing_max=9};
command_spec(N=updateextra) -> #command_spec{name=N, opcode=16#20, timing_typ=8,  timing_max=10};
command_spec(N=verify)      -> #command_spec{name=N, opcode=16#45, timing_typ=38, timing_max=58};
command_spec(N=write)       -> #command_spec{name=N, opcode=16#12, timing_typ=7,  timing_max=26};
command_spec(N=wake)        -> #command_spec{name=N, opcode=16#00, timing_typ=0,  timing_max=1}. %% not in spec

%% @private
%% encode_address/config should not be used to write addresses at
%% offsets 0-16, and shouldn't be used with the Write command at
%% offsets 84-87, as per 508 Datasheet Section 9.1.4, page 59.
%% @end
-spec encode_address(Address::address()) -> binary ().
encode_address({Zone, Location}) ->
    encode_address({Zone, trunc(Location div 32), Location rem 32});
encode_address({otp, Block, Offset}) ->
    <<0:8, 0:4, Block:1, Offset:3>>;
encode_address({config, Block, Offset}) ->
    <<0:8, 0:3, Block:2, Offset:3>>;
encode_address({data, Slot, Block}) ->
    encode_address({data, Slot, Block, 0});
encode_address({data, Slot, Block, Offset}) when Slot < 8->
    <<0:7, Block:1, 0:1, Slot:4, Offset:3>>;
encode_address({data, Slot, Block, Offset}) when Slot == 8 ->
    <<0:4, Block:4, 0:1, Slot:4, Offset:3>>;
encode_address({data, Slot, Block, Offset}) when Slot > 8 ->
    <<0:6, Block:2, 0:1, Slot:4, Offset:3>>.

bool_to_bit(Val) ->
    case Val of
        true -> 1;
        false -> 0;
        _ -> throw({not_boolean, Val})
    end.

-spec command(Cmd::atom(), Param1::<<_:8>>, Param2::<<_:16>>, Data::binary()) -> #command{}.
command(Type, Param1, Param2, Data) ->
    Spec = command_spec(Type),
    #command{spec=Spec, param1=Param1, param2=Param2, data=Data}.

command(wake) ->
    command(wake, <<0:8>>, <<0:16>>, <<0:184>>);
command({genkey, private, KeyId, #{should_store := ShouldStore, from_scratch := FromScratch}}) ->
    Param1 = <<0:3, 1:1, (bool_to_bit(ShouldStore)):1, (bool_to_bit(FromScratch)):1, 0:2>>,
    command(genkey, Param1, <<KeyId:16/unsigned>>, <<>>);
command({genkey, public, KeyId, #{key_id := OriginalKeyId,
                                  should_store := ShouldStore,
                                  from_scratch := FromScratch}}) ->
    Data = <<0:4, (bool_to_bit(ShouldStore)):1, (bool_to_bit(FromScratch)):1, 0:2, OriginalKeyId:16>>,
    command(genkey, <<16#10:8>>, <<KeyId:16/unsigned>>, Data);
command({nonce, passthrough, Data}) ->
    command(nonce, <<16#03>>, <<0:16>>, <<Data:4/binary>>);
command({nonce, preseed, Data}) ->
    Param1 = <<16#00>>,
    Param2 = <<16#80, 16#00>>,
    command(nonce, Param1, Param2, <<Data:20/binary>>);
command({nonce, {random, UpdateSeed}, Data}) ->
    Param1 = <<(bool_to_bit(UpdateSeed)):8>>,
    Param2 = <<16#80, 16#00>>,
    command(nonce, Param1, Param2, <<Data:20/binary>>);
command({pause, Selector}) ->
    command(pause, <<Selector:8>>, <<0:16>>, <<>>);
command({random, SeedMode}) ->
    command(random, <<SeedMode:8>>, <<0:16>>, <<>>);
command({digest, {init, sha}}) ->
    command(sha, <<0:8>>, <<0:16>>, <<>>);
command({digest, {init, {hmac, Slot}}}) ->
    command(sha, <<16#04>>, <<Slot:16>>, <<>>);
command({digest, {update, Data}}) when byte_size(Data) =< 64->
    command(sha, <<16#01>>, <<(byte_size(Data)):16>>, Data);
command({digest, {public, Slot}}) ->
    command(sha, <<16#03>>, <<Slot:16>>, <<>>);
command({digest, {finalize, {sha, Data}}}) ->
    command(sha, <<16#02>>, <<(byte_size(Data)):16>>, Data);
command({digest, {finalize, {hmac, Data}}}) ->
    command(sha, <<16#05>>, <<(byte_size(Data)):16>>, Data);
command({sign, {external, KeyId}}) ->
    command(sign, <<16#80>>, <<KeyId:16>>, <<>>);
command({verify, {external, Signature, _ECPubKey={#'ECPoint'{point=PubPoint}, _}}}) ->
    << _:8, X:32/binary, Y:32/binary>> = PubPoint,
    SignatureLen = byte_size(Signature),
    {R, S} = split_binary(Signature, SignatureLen div 2),
    Data = <<R/binary, S/binary, X/binary, Y/binary>>,
    command(verify, <<16#02>>, <<16#00, 16#03>>, Data);
command({write, Address, Data}) ->
    ByteSizeBit = fun(D) when byte_size(D) == 4-> 0;
                     (D) when byte_size(D) == 32 -> 1;
                     (_) -> throw(ecc_write_size_invalid)
                  end,
    SectionValue = fun(config) -> 16#00;
                      (otp) -> 16#01;
                      (data) -> 16#02;
                      (_) ->  throw(ecc_write_section_invalid)
                   end,
    Param1 = <<(ByteSizeBit(Data)):1, 0:1, 0:4, (SectionValue(element(1, Address))):2>>,
    command(write, Param1, encode_address(Address), Data).

-spec wait_for_response(I2C::pid(), {WaitExtra::boolean(), WaitStartTime::pos_integer()}, Cmd::#command{})
                       -> {error, term()} | {ok, pos_integer()}.
wait_for_response(Pid, {Extra, StartTime}, Cmd=#command{spec=Spec}) ->
    case Extra of
        false -> timer:sleep(Spec#command_spec.timing_typ);
        true -> timer:sleep(Spec#command_spec.timing_max - (get_timestamp() - StartTime))
    end,
    case i2c:read(Pid, 1) of
        {error, i2c_read_failed} ->
            wait_for_response(Pid, {true, StartTime}, Cmd);
        <<16#FF:8>> when Extra == true ->
            {error, ecc_command_timeout};
        <<16#FF:8>> when Extra == false ->
            wait_for_response(Pid, {true, StartTime}, Cmd);
        <<First:8/integer>> when First < ?CMDGRP_COUNT_MIN ->
            {error, {ecc_command_too_small, First}};
        <<First:8/integer>> when First > ?CMDGRP_COUNT_MAX ->
            {error, {ecc_command_too_large, First}};
        <<Length:8/integer-unsigned>> ->
            {ok, Length - 1}
    end.

-spec read_response(I2C::pid(), Remaining::non_neg_integer(), Acc::binary())
                   -> {ok, binary()} | {error, term()}.
read_response(_Pid, 0, Acc) ->
    DataSize = byte_size(Acc) - 2,
    <<Data:DataSize/binary, CheckSum:16/bitstring>> = Acc,
    CheckVerify = crc16:calc(<<(DataSize + 3):8/unsigned-integer, Data/binary>>),
    case CheckSum == CheckVerify of
        true -> {ok, Data};
        false -> {error, ecc_checksum_failed}
    end;
read_response(Pid, Length, Acc) ->
    Bin = i2c:read(Pid, min(Length, 32)),
    read_response(Pid, Length - byte_size(Bin), <<Acc/binary, Bin/binary>>).

-spec execute(I2C::pid(), Cmd::#command{}) -> ok | {ok, awake} | {ok, binary()} | {error, term()}.
execute(Pid, Cmd)->
    CmdBin = package(command_to_binary(Cmd)),
    i2c:write(Pid, CmdBin),
    case wait_for_response(Pid, {false, get_timestamp()}, Cmd) of
        {error, Error} ->
            {error, Error};
        {ok, Length} ->
            case read_response(Pid, Length, <<>>) of
                {error, Error} ->
                    {error, Error};
                {ok, <<16#00>>} -> ok;
                {ok, <<16#01>>} -> {error, ecc_response_checkmac_verify_miscompare};
                {ok, <<16#03>>} -> {error, ecc_response_parse_error};
                {ok, <<16#05>>} -> {error, ecc_response_ecc_fault};
                {ok, <<16#0F>>} -> {error, ecc_response_exec_error};
                {ok, <<16#11>>} -> {ok, awake};
                {ok, <<16#EE>>} -> {error, ecc_response_watchdog_exp};
                {ok, <<16#FF>>} -> {error, ecc_response_comms_error};
                {ok, RespBin} -> {ok, RespBin}
            end
    end.

%% @private
%% command_to_binary ensures that ESL/Erlang_ALE treats the data
%% properly by preparing it as one binary, as any other format
%% prompts the i2c module to prepend data length which we
%% handle ourselves. (idk how to document pls2halp)
%% @end
-spec command_to_binary(#command{}) -> binary().
command_to_binary(Cmd) ->
    <<(Cmd#command.spec#command_spec.opcode):8,
      (Cmd#command.param1)/binary,
      (Cmd#command.param2)/binary,
      (Cmd#command.data)/binary>>.

-spec package_word(atom()) -> non_neg_integer().
%% package_word(reset)    -> 16#00;
%% package_word(sleep)    -> 16#01;
%% package_word(idle)     -> 16#02;
%% package_word(reserved) -> 16#04;
package_word(command)  -> 16#03.

-spec package(binary()) -> binary().
package(Bin) when byte_size(Bin) < ?CMDGRP_COUNT_MIN ->
    throw({ecc_command_too_small, byte_size(Bin)});
package(Bin) when byte_size(Bin) > ?CMDGRP_COUNT_MAX ->
    throw({ecc_command_too_large, byte_size(Bin)});
package(Bin) ->
    PackageLen = byte_size(Bin) + 3,
    LenBin = <<PackageLen, Bin/binary>>,
    CheckSum = crc16:calc(LenBin),
    <<(package_word(command)):8, LenBin/binary, CheckSum/binary>>.


get_timestamp() ->
  {Mega, Sec, Micro} = os:timestamp(),
  (Mega*1000000 + Sec)*1000 + round(Micro/1000).
