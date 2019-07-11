-module(ecc508).

-include_lib("public_key/include/public_key.hrl").

%% API exports
-export([start_link/0,
         wake/1,
         genkey/4,
         nonce/3,
         digest_init/2, digest_update/3, digest_finalize/3,
         random/1, random/2,
         sign/3, verify/4,
         pause/2,
         read/3,
         write/3,
         slot_config_address/1, get_slot_config/2, set_slot_config/3,
         slot_config_to_bin/1, slot_config_from_bin/1, write_config/2,
         key_config_address/1, get_key_config/2, set_key_config/3,
         key_config_to_bin/1, key_config_from_bin/1
        ]).
%% supporting functions
-export([encode_address/1,
         execute/2,
         command_spec/1, command/4,
         to_hex/1
        ]).

-type address() :: {otp, Block::non_neg_integer(), Offset::non_neg_integer()} |
                   {config, Block::0..3, Offset::non_neg_integer()} |
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


start_link() ->
    i2c:start_link("i2c-1", 16#60, 155).

%%====================================================================
%% API functions
%%====================================================================

wake(Pid) ->
    execute(Pid, command(wake)).

-spec slot_config_address(Slot::0..15) -> {config, Block::0..1, Offset::non_neg_integer()}.
slot_config_address(Slot) when Slot >= 0, Slot =< 15 ->
    {Block, Offset} = case Slot =< 5 of
                          true ->
                              {0, (20 + Slot * 2) bsr 2};
                          false ->
                              {1, ((Slot - 5) * 2) bsr 2}
                      end,
    {config, Block, Offset}.

-spec get_slot_config(pid(), 0..15) -> {ok, map()} | {error, term()}.
get_slot_config(Pid, Slot) ->
    case read(Pid, 4, slot_config_address(Slot)) of
        {ok, <<S0:16/bitstring, S1:16/bitstring>>} ->
            case Slot rem 2 of
                0 -> {ok, slot_config_from_bin(S0)};
                1 -> {ok, slot_config_from_bin(S1)}
            end;
        {error, Error} ->
            {error, Error}
    end.

-spec set_slot_config(pid(), 0..15, map()) -> ok | {error, term()}.
set_slot_config(Pid, Slot, Config) ->
    ConfigBin = slot_config_to_bin(Config),
    SlotAddress= slot_config_address(Slot),
    case read(Pid, 4, SlotAddress) of
        {ok, <<S0:16/bitstring, S1:16/bitstring>>} ->
            NewBytes = case Slot rem 2 of
                           0 -> <<ConfigBin:16/bitstring, S1:16/bitstring>>;
                           1 -> <<S0:16/bitstring, ConfigBin:16/bitstring>>
                       end,
            write(Pid, SlotAddress, NewBytes);
        {error, Error} ->
            {error, Error}
    end.


-spec slot_config_from_bin(<<_:16>>) -> map().
slot_config_from_bin(<<IsSecret:1,
                       EncryptRead:1,
                       LimitedUse:1,
                       NoMac:1,
                       ReadKey:4,
                       WriteConfig:4,
                       WriteKey:4>> = V) ->
    io:format("PARSING ~p, HEX ~p~n", [V, to_hex(V)]),
    #{write_config => WriteConfig,
      write_key => WriteKey,
      is_secret => bit_to_bool(IsSecret),
      encrypt_read => bit_to_bool(EncryptRead),
      limited_use => bit_to_bool(LimitedUse),
      no_mac => bit_to_bool(NoMac),
      read_key => ReadKey}.

-spec slot_config_to_bin(map()) -> <<_:16>>.
slot_config_to_bin(#{write_config := WriteConfig,
                     write_key := WriteKey,
                     is_secret := IsSecret,
                     encrypt_read := EncryptRead,
                     limited_use := LimitedUse,
                     no_mac := NoMac,
                     read_key := ReadKey}) ->
    <<(bool_to_bit(IsSecret)):1,
      (bool_to_bit(EncryptRead)):1,
      (bool_to_bit(LimitedUse)):1,
      (bool_to_bit(NoMac)):1,
      ReadKey:4,
      WriteConfig:4,
      WriteKey:4>>.


%% @doc Get write cofiguration from the write_config slot bits for a
%% given command. The interpretation of the write_config bits differs
%% based on the command used.
%%
%% For WRITE:
%%
%% always - Clear text writes are always permitted on this slot. Slots
%% set to alwaysshould never be used as key storage. Either 4 or 32
%% bytes may bewritten to this slot
%%
%% pub_invalid - If a validated public key is stored in the slot,
%% writes are prohibited. UseVerify(Invalidate) to invalidate prior to
%% writing. Do not use thismode unless the slot contains a public key.
%%
%% never - Writes are never permitted on this slot using the Write
%% command.Slots set to never can still be used as key storage.
%%
%% encrypt - Writes to this slot require a properly computed MAC, and the
%% inputdata must be encrypted by the system with WriteKey using
%% theencryption algorithm documented in the Write command
%% description(Section Write Command). 4 byte writes to this slot are
%% prohibited.
%%
%% For DERIVE_KEY:
%%
%% {roll, no_mac} - DeriveKey command can be run without authorizing
%% MAC.(Roll). Source Key: Target
%%
%% {roll, mac} - Authorizing MAC required for DeriveKey
%% command. (Roll). Source Key: Target
%%
%% {create, no_mac} - DeriveKey command can be run without authorizing
%% MAC.(Create). Source Key: Parent
%%
%% {create, mac} - Authorizing MAC required for DeriveKey
%% command. (Create). Source Key: Parent
%%
%% invalid - Slots with this write configutation can not be used as
%% the target of a DeriveKey.
%%
%% Note: he source key for the computation performed by the DeriveKey
%% command can either be thekey directly specified in Param2 (Target)
%% or the key at SlotConfig<Param2>.WriteKey (Parent).
%%
%% For GEN_KEY:
%%
%% valid - GenKey may not be used to write random keys into this slot.
%%
%% invalid - GenKey may be used to write random keys into this slot.
%%
%% For PRIV_WRITE:
%%
%% invalid - PrivWrite will return an error if the target key slot has
%% this value.
%%
%% encrypt - Writes to this slot require a properly computed MAC and
%% the inputdata must be encrypted by the system with
%% SlotConfig.WriteKey using the encryption algorithm documented with
%% PrivWrite.
-type write_config() :: always | pub_invalid | never | encrypt.
-type derive_key_config() :: {roll, mac | no_mac} | {create, mac, no_mac} | invalid.
-type gen_key_config() :: valid | invalid.
-type priv_write_config() :: invalid | encrypt.
-spec write_config(write | derive_key | gen_key, 0..15)
                  -> write_config() | derive_key_config() | gen_key_config() | priv_write_config().
write_config(write, 0) -> always;
write_config(write, 1) -> pub_invalid;
write_config(write, V)  when (V bsr 1) == 1 -> never;
write_config(write, V)  when (V bsr 2) == 2 -> never;
write_config(write, V)  when (V band 4) == 4 -> encrypt;
write_config(derive_key, V) ->
    case V band (bnot 4) of
        2 -> {roll, no_mac};
        10 -> {roll, mac};
        3 -> {create, no_mac};
        11 -> {create, mac};
        _ -> invalid
    end;
write_config(gen_key, V) ->
    case V band (bnot 13) of
        0 -> invalid;
        2 -> valid
    end;
write_config(priv_write, V) ->
    case V band (bnot 11) of
        0 -> invalid;
        1 -> encrypt
    end.


-spec key_config_address(Slot::0..15) -> {config, 3, non_neg_integer()}.
key_config_address(Slot) when Slot >= 0, Slot =< 15 ->
    Offset = (Slot * 2) bsr 2,
    {config, 3, Offset}.

-spec get_key_config(pid(), Slot::0..15) -> {ok, map()} | {error, term()}.
get_key_config(Pid, Slot) ->
    case read(Pid, 4, key_config_address(Slot)) of
        {ok, <<S0:16/bitstring, S1:16/bitstring>>} ->
            case Slot rem 2 of
                0 -> {ok, key_config_from_bin(S0)};
                1 -> {ok, key_config_from_bin(S1)}
            end;
        {error, Error} ->
            {error, Error}
    end.

-spec set_key_config(pid(), Slot::0..15, Config::map()) -> ok | {error, term()}.
set_key_config(Pid, Slot, Config) ->
    ConfigBin = key_config_to_bin(Config),
    Address = key_config_address(Slot),
    case read(Pid, 4, Address) of
        {ok, <<S0:16/bitstring, S1:16/bitstring>>} ->
            NewBytes = case Slot rem 2 of
                           0 -> <<ConfigBin:16/bitstring, S1:16/bitstring>>;
                           1 -> <<S0:16/bitstring, ConfigBin:16/bitstring>>
                       end,
            write(Pid, Address, NewBytes);
        {error, Error} ->
            {error, Error}
    end.

%% @doc Returns a map representing a KeyConfig as documented in Table 2-12
%% - KeyConfig Bits in the Data sheet.
%%
%% Note that the documentation has MSB first but the wire format
%% returned is LSB first.
-spec key_config_from_bin(KeyConfig::<<_:16>>) -> map().
key_config_from_bin(<<ReqAuth:1,
                      ReqRandom:1,
                      Lockable:1,
                      KeyTypeBits:3,
                      PubInfo:1,
                      Private:1,
                      X509Index:2,
                      0:1,
                      IntrusionDisable:1,
                      AuthKey:4
                    >>) ->
    #{x509_index => X509Index,
      intrusion_disable => bit_to_bool(IntrusionDisable),
      auth_key => AuthKey,
      req_auth => bit_to_bool(ReqAuth),
      req_random => bit_to_bool(ReqRandom),
      lockable => bit_to_bool(Lockable),
      key_type => case KeyTypeBits of
                      4 -> ecc_key;
                      7 -> not_ecc_key;
                      _ -> reserved
                  end,
      private => bit_to_bool(Private),
      pub_info => PubInfo
     }.

-spec key_config_to_bin(map()) -> <<_:16>>.
key_config_to_bin(#{x509_index := X509Index,
                    intrusion_disable := IntrusionDisable,
                    auth_key := AuthKey,
                    req_auth := ReqAuth,
                    req_random := ReqRandom,
                    lockable := Lockable,
                    key_type := KeyType,
                    private := Private,
                    pub_info := PubInfo
                   }) ->
    KeyTypeBits = case KeyType of
                      ecc_key -> 4;
                      not_ecc_key -> 7
                  end,
    <<(bool_to_bit(ReqAuth)):1,
      (bool_to_bit(ReqRandom)):1,
      (bool_to_bit(Lockable)):1,
      KeyTypeBits:3,
      PubInfo:1,
      (bool_to_bit(Private)):1,
      X509Index:2,
      0:1,
      (bool_to_bit(IntrusionDisable)):1,
      AuthKey:4
    >>.

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

-spec read(I2C::pid(), Size::4 | 32, Address::address()) -> {ok, binary()} | {error, term()}.
read(Pid, Size, Address) ->
    execute(Pid, command({read, Size, Address})).

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


-spec encode_address_zone(Address::address()) -> 0..2.
encode_address_zone({config, _, _}) -> 16#00;
encode_address_zone({otp, _, _}) -> 16#01;
encode_address_zone({data, _, _}) -> 16#02;
encode_address_zone({data, _, _, _}) -> 16#02;
encode_address_zone(_) ->  throw(ecc_zone_invalid).

%% @private
%% encode_address/config should not be used to write addresses at
%% offsets 0-16, and shouldn't be used with the Write command at
%% offsets 84-87, as per 508 Datasheet Section 9.1.4, page 59.
%%
%% Note that the address is in Param2 for all commands and is encoded
%% with LSB first, i.e. reversed from the documentation.
%%
%% @end
-spec encode_address(Address::address()) -> binary ().
encode_address({otp, Block, Offset}) when Block >= 0, Block =< 1->
    <<0:4, Block:1, Offset:3, 0:8>>;
encode_address({config, Block, Offset}) when Block >= 0, Block =< 3, Offset >= 0, Offset =< 7->
    <<0:3, Block:2, Offset:3, 0:8>>;
encode_address({data, Slot, Block}) ->
    encode_address({data, Slot, Block, 0});
encode_address({data, Slot, Block, Offset}) when Slot < 8->
    <<0:1, Slot:4, Offset:3, 0:7, Block:1>>;
encode_address({data, Slot, Block, Offset}) when Slot == 8 ->
    <<0:1, Slot:4, Offset:3, 0:4, Block:4>>;
encode_address({data, Slot, Block, Offset}) when Slot > 8 ->
    <<0:1, Slot:4, Offset:3, 0:6, Block:2>>.


encode_read_write_size(4) -> 0;
encode_read_write_size(32) -> 1;
encode_read_write_size(Val) ->  throw({ecc_size_invalid, Val}).

-spec bool_to_bit(true | false) -> 0 | 1.
bool_to_bit(true) -> 1;
bool_to_bit(false) -> 0;
bool_to_bit(Val) ->throw({not_boolean, Val}).

-spec bit_to_bool(0 | 1) -> true | false.
bit_to_bool(1) -> true;
bit_to_bool(0) -> false;
bit_to_bool(V) -> throw({not_boolean_bit, V}).

-spec command(Cmd::atom(), Param1::<<_:8>>, Param2::<<_:16>>, Data::binary()) -> #command{}.
command(Type, Param1, Param2, Data) ->
    Spec = command_spec(Type),
    #command{spec=Spec, param1=Param1, param2=Param2, data=Data}.

command(wake) ->
    command(wake, <<0:8>>, <<0:16>>, <<0:184>>);
command({genkey, private, KeyId, #{should_store := ShouldStore, from_scratch := FromScratch}}) ->
    Param1 = <<0:3, 1:1, (bool_to_bit(ShouldStore)):1, (bool_to_bit(FromScratch)):1, 0:2>>,
    command(genkey, Param1, <<KeyId:16/unsigned-little-integer>>, <<>>);
command({genkey, public, KeyId, #{key_id := OriginalKeyId,
                                  should_store := ShouldStore,
                                  from_scratch := FromScratch}}) ->
    Data = <<0:4, (bool_to_bit(ShouldStore)):1, (bool_to_bit(FromScratch)):1, 0:2, OriginalKeyId:16>>,
    command(genkey, <<16#10:8>>, <<KeyId:16/unsigned-little-integer>>, Data);
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
    command(sha, <<16#04>>, <<Slot:16/integer-unsigned-little>>, <<>>);
command({digest, {update, Data}}) when byte_size(Data) =< 64->
    command(sha, <<16#01>>, <<(byte_size(Data)):16/integer-unsigned-little>>, Data);
command({digest, {public, Slot}}) ->
    command(sha, <<16#03>>, <<Slot:16/integer-unsigned-little>>, <<>>);
command({digest, {finalize, {sha, Data}}}) ->
    command(sha, <<16#02>>, <<(byte_size(Data)):16/integer-unsigned-little>>, Data);
command({digest, {finalize, {hmac, Data}}}) ->
    command(sha, <<16#05>>, <<(byte_size(Data)):16/integer-unsigned-little>>, Data);
command({sign, {external, KeyId}}) ->
    command(sign, <<16#80>>, <<KeyId:16/integer-unsigned-little>>, <<>>);
command({verify, {external, Signature, _ECPubKey={#'ECPoint'{point=PubPoint}, _}}}) ->
    << _:8, X:32/binary, Y:32/binary>> = PubPoint,
    SignatureLen = byte_size(Signature),
    {R, S} = split_binary(Signature, SignatureLen div 2),
    Data = <<R/binary, S/binary, X/binary, Y/binary>>,
    command(verify, <<16#02>>, <<16#03, 16#00>>, Data);
command({read, Size, Address}) ->
    Param1 = <<(encode_read_write_size(Size)):1, 0:5, (encode_address_zone(Address)):2>>,
    command(read, Param1, encode_address(Address), <<>>);
command({write, Address, Data}) ->
    Param1 = <<(encode_read_write_size(byte_size(Data))):1, 0:5, (encode_address_zone(Address)):2>>,
    command(write, Param1, encode_address(Address), Data).


to_hex(Bin) ->
    << <<Y>> ||<<X:4>> <= Bin, Y <- integer_to_list(X,16)>>.

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
