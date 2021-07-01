-module(ecc508).

-include_lib("public_key/include/public_key.hrl").

%% API exports
-export([start_link/0, start_link/1, start_link/2, stop/1,
         wake/1, idle/1, sleep/1, reset/1,
         serial_num/1,
         lock/2, lock/3,
         genkey/3,
         ecdh/3,
         nonce/3,
         digest_init/2, digest_update/3, digest_finalize/3,
         random/1, random/2,
         sign/3, verify/4,
         slot_config_address/1, get_slot_config/2, set_slot_config/3,
         slot_config_to_bin/1, slot_config_from_bin/1,
         from_read_key/1, to_read_key/1,
         from_write_config/2, to_write_config/2,
         get_locked/2, get_slot_locked/2,
         key_config_address/1, get_key_config/2, set_key_config/3,
         key_config_to_bin/1, key_config_from_bin/1
        ]).
%% ecc key functions
-export([ecc_key_config/0, ecc_slot_config/0]).
%% supporting functions
-export([encode_address/1,
         read/3, write/3,
         execute/2, spec/1, command/1, command/4,
         to_hex/1
        ]).

-type address() :: {otp, Block::non_neg_integer(), Offset::non_neg_integer()} |
                   {config, Block::0..3, Offset::non_neg_integer()} |
                   {data, Slot::non_neg_integer(), Block::non_neg_integer()} |
                   {data, Slot::non_neg_integer(), Block::non_neg_integer(), Offset::non_neg_integer()}.
-export_type([address/0]).

-define(CMDGRP_COUNT_MIN, 4).
-define(CMDGRP_COUNT_MAX, 155).

-record(spec, {
               name :: atom(),
               opcode :: non_neg_integer(),
               timing_typ :: non_neg_integer(),
               timing_max :: pos_integer(),
               resp = 4 :: non_neg_integer()
              }).

-record(command, {
                  spec :: #spec{},
                  param1 :: <<_:8>>,
                  param2 :: <<_:16>>,
                  data = <<>> :: binary()
                 }).

%% @doc Start and link the ecc process with the default i2c bus,
%% address and default max count.
- spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
    start_link("i2c-1").

%% @doc Start and link the ecc process with a given devname i2c bus, the
%% default address and the default max count.
- spec start_link(string()) -> {ok, pid()} | {error, term()}.
start_link(DevName) ->
    start_link(DevName, 16#60).

%% @doc Start and link the ecc process with a given devname i2c bus, a
%% given address and the default max count.
- spec start_link(string(), integer()) -> {ok, pid()} | {error, term()}.
start_link(DevName, Address) ->
    i2c:start_link(DevName, Address, ?CMDGRP_COUNT_MAX).

%% @doc Stops the given ecc process.
stop(Pid) ->
    i2c:stop(Pid).

%%====================================================================
%% API functions
%%====================================================================

%% @doc Send a wake command to the ecc. This ensures that the ecc
%% wakes up form its default sleep mode
wake(Pid) ->
    execute(Pid, command(wake)).

%% @doc Sends an idle command to the ecc. This puts the ecc in idle
%% state, which disables the sleep watchdog .A subsequent wake/1 call
%% will re-enable the ecc for commands.
idle(Pid) ->
    execute(Pid, idle, command(idle)).

%% @doc Sends a sleep command to the ecc. This puts the ecc in low
%% power mode.
sleep(Pid) ->
    execute(Pid, sleep, command(sleep)).

%% @doc Sends a reset command to the ecc.
reset(Pid) ->
    execute(Pid, reset, command(reset)).

%% @doc Returns the 9 bytes that represent the serial number of the
%% ECC. Per section 2.2.6 of the Data Sheet the first two, and last
%% byte of the returned binary will always be `<<16#01, 16#23,
%% 16#EE>>'
serial_num(Pid) ->
    case read(Pid, 32, {config, 0, 0}) of
        {ok, <<B1:4/binary, _:4/binary, B2:5/binary, _/binary>>} ->
            {ok, <<B1/binary, B2/binary>>};
        {error, Error} ->
            {error, Error}
    end.

%% @doc Get a block and offset address for the configuration of a
%% slot.
-spec slot_config_address(Slot::0..15) -> {config, Block::0..1, Offset::non_neg_integer()}.
slot_config_address(Slot) when Slot >= 0, Slot =< 15 ->
    {Block, Offset} = case Slot =< 5 of
                          true ->
                              {0, (20 + Slot * 2) bsr 2};
                          false ->
                              {1, ((Slot - 5) * 2) bsr 2}
                      end,
    {config, Block, Offset}.

%% @doc Gets the configuraiton for a slot as defined in the
%% configuration zone.
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

%% @doc Sets the configuraiton for a given slot. The configuration is
%% given as a map.
-spec set_slot_config(pid(), 0..15, Config::map() | binary()) -> ok | {error, term()}.
set_slot_config(Pid, Slot, Config) when is_map(Config) ->
    set_slot_config(Pid, Slot, slot_config_to_bin(Config));
set_slot_config(Pid, Slot, Config) when is_binary(Config) ->
    SlotAddress= slot_config_address(Slot),
    case read(Pid, 4, SlotAddress) of
        {ok, <<S0:16/bitstring, S1:16/bitstring>>} ->
            NewBytes = case Slot rem 2 of
                           0 -> <<Config:16/bitstring, S1:16/bitstring>>;
                           1 -> <<S0:16/bitstring, Config:16/bitstring>>
                       end,
            write(Pid, SlotAddress, NewBytes);
        {error, Error} ->
            {error, Error}
    end.

%% @doc Converts a given 16 bit binary to a slot configuration map.
-spec slot_config_from_bin(<<_:16>>) -> map().
slot_config_from_bin(<<IsSecret:1,
                       EncryptRead:1,
                       LimitedUse:1,
                       NoMac:1,
                       ReadKey:4,
                       WriteConfig:4,
                       WriteKey:4>>) ->
    io:format("READ KEY ~p~n", [ReadKey]),
    #{write_config => WriteConfig,
                  write_key => WriteKey,
                  is_secret => bit_to_bool(IsSecret),
                  encrypt_read => bit_to_bool(EncryptRead),
                  limited_use => bit_to_bool(LimitedUse),
                  no_mac => bit_to_bool(NoMac),
                  read_key => to_read_key(ReadKey) }.

 %% @doc Converts a given slot configuration map to a binary. The
 %% resulting binary can be used in a `set_slot_config' call.
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
      (from_read_key(ReadKey)):4,
      WriteConfig:4,
      WriteKey:4>>.

%% @doc A convenience function to get a slot configuratoin set up to
%% generate and store ECDSA private keys.
ecc_slot_config() ->
    #{ write_config => from_write_config(genkey, valid),
       write_key => 0,
       is_secret => true,
       encrypt_read => false,
       limited_use => false,
       no_mac => true,
       read_key => [internal_signatures, external_signatures]
     }.

-type read_key() :: ecdh_write_slot | ecdh_operation | internal_signatures | external_signatures.
-spec to_read_key(non_neg_integer ()) -> [read_key ()].
to_read_key(V) ->
    to_read_key(V, [{2#1000, ecdh_write_slot},
                    {2#0100, ecdh_operation},
                    {2#0010, internal_signatures},
                    {2#0001, external_signatures}],
                []).

to_read_key(_, [], Acc) ->
    lists:reverse(Acc);
to_read_key(V, [{Mask, N} | Tail], Acc) ->
    case V band Mask == Mask of
        true -> to_read_key(V, Tail, [N | Acc]);
        false -> to_read_key(V, Tail, Acc)
    end.

-spec from_read_key([read_key()]) -> non_neg_integer().
from_read_key(Keys) ->
    from_read_key(Keys, 0).

from_read_key([], Acc) ->
    Acc;
from_read_key([ecdh_write_slot | Tail], Acc) ->
    from_read_key(Tail, Acc bor 2#1000);
from_read_key([ecdh_operation | Tail], Acc) ->
    from_read_key(Tail, Acc bor 2#0100);
from_read_key([internal_signatures | Tail], Acc) ->
    from_read_key(Tail, Acc bor 2#0010);
from_read_key([external_signatures | Tail], Acc) ->
    from_read_key(Tail, Acc bor 2#0001).


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
%% For GENKEY:
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
-type genkey_config() :: valid | invalid.
-type priv_write_config() :: invalid | encrypt.
-spec to_write_config(write | derive_key | genkey, 0..15)
                     -> write_config() |
                        derive_key_config() |
                        genkey_config() |
                        priv_write_config().
to_write_config(write, 0) -> always;
to_write_config(write, 1) -> pub_invalid;
to_write_config(write, V)  when (V bsr 1) == 1 -> never;
to_write_config(write, V)  when (V bsr 2) == 2 -> never;
to_write_config(write, V)  when (V band 4) == 4 -> encrypt;
to_write_config(derive_key, V) ->
    case V band 2#1011 of
        2 -> {roll, no_mac};
        10 -> {roll, mac};
        3 -> {create, no_mac};
        11 -> {create, mac};
        _ -> invalid
    end;
to_write_config(genkey, V) ->
    case V band 2#0010 of
        0 -> invalid;
        2 -> valid
    end;
to_write_config(priv_write, V) ->
    case V band 2#0100 of
        0 -> invalid;
        4 -> encrypt
    end.

%% @doc Converts a given write configuration tuple into it's
%% value. This can be used as a convenience function when constructing
%% slot configurations.
-spec from_write_config(write | derive_key | genkey | priv_write,
                        write_config() | derive_key_config() | genkey_config() | priv_write_config())
                       -> 0..15.
from_write_config(write, always) -> 0;
from_write_config(write, pub_invalid) -> 1;
from_write_config(write, never) -> 2;
from_write_config(write, encrypt) -> 4;
from_write_config(derive_key, {roll, no_mac}) -> 2;
from_write_config(derive_key, {roll, mac}) -> 10;
from_write_config(derive_key, {create, no_mac}) -> 3;
from_write_config(derive_key, {create, mac}) -> 11;
from_write_config(genkey, invalid) -> 0;
from_write_config(genkey, valid) -> 2;
from_write_config(priv_write, invalid) -> 0;
from_write_config(priv_write, encrypt) -> 4.


%% @doc Gets the lock status for the given zone.
-spec get_locked(pid(), config | data) -> {ok, boolean()} | {error, term()}.
get_locked(Pid, Zone) ->
    case read(Pid, 4, {config, 2, 5}) of
        {ok, <<_:16, LockData:8, LockConfig:8>>} ->
            case Zone of
                config -> {ok, LockConfig == 0};
                data -> {ok, LockData == 0}
            end;
        {error, Error} -> {error, Error}
    end.


%% @doc Returns whether a given slot is locked or not. Note that the
%% slot must have been configured as lockable and then locked
-spec get_slot_locked(pid(), Slot::0..15) -> boolean() | {error, term()}.
get_slot_locked(Pid, Slot) ->
    case read(Pid, 4, {config, 2, 6}) of
        {ok, <<LockBits:16/unsigned-integer-little, _/binary>>} ->
            LockBits band (1 bsl Slot) == 0;
        {error, Error} ->
            {error, Error}
    end.

%% @doc Get the configuration zone address for a given key
%% configuration slot. Note that this is a seprate area from the slot
%% configuration itself, and is used for key related configuration if
%% a slot is configured to hold key material.
-spec key_config_address(Slot::0..15) -> {config, 3, non_neg_integer()}.
key_config_address(Slot) when Slot >= 0, Slot =< 15 ->
    Offset = (Slot * 2) bsr 2,
    {config, 3, Offset}.

%% @doc Get the key configuraiton for a given slot.
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

%% @doc Set the key configuration for a given slot. The configuration
%% can be passed in either as a map or as a binary as generated by
%% key_config_to_bin/1.
-spec set_key_config(pid(), Slot::0..15, Config::map() | binary()) -> ok | {error, term()}.
set_key_config(Pid, Slot, Config) when is_map(Config)->
    set_key_config(Pid, Slot, key_config_to_bin(Config));
set_key_config(Pid, Slot, Config) when is_binary(Config)->
    Address = key_config_address(Slot),
    case read(Pid, 4, Address) of
        {ok, <<S0:16/bitstring, S1:16/bitstring>>} ->
            NewBytes = case Slot rem 2 of
                           0 -> <<Config:16/bitstring, S1:16/bitstring>>;
                           1 -> <<S0:16/bitstring, Config:16/bitstring>>
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
      pub_info => bit_to_bool(PubInfo)
     }.

%% @doc Returns a binary representing a given key configuration.
%%
%% Note that the documentation has MSB first but the wire format
%% returned is LSB first.
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
      (bool_to_bit(PubInfo)):1,
      (bool_to_bit(Private)):1,
      X509Index:2,
      0:1,
      (bool_to_bit(IntrusionDisable)):1,
      AuthKey:4
    >>.

%% @doc Returns a key configuration set up to store ECC key private
%% keys.
ecc_key_config() ->
    #{ auth_key => 0,
       req_auth => false,
       x509_index => 0,
       key_type => ecc_key,
       intrusion_disable => false,
       req_random => false,
       lockable => true,
       private => true,
       pub_info => true}.

%% @doc Locks the configuration zone, data zone, or individual
%% slot. Note that for lockign slots, the slot must be configured as
%% lockable, and the configuration zone must be locked
-spec lock(pid(), config | data | {slot, 0..15}) -> ok | {error, term()}.
lock(Pid, ZoneOrSlot) ->
    lock(Pid, ZoneOrSlot, <<16#00, 16#00>>).

%% @doc Locks the configuration zone, data zone, or individual
%% slot. Note that for lockign slots, the slot must be configured as
%% lockable, and the configuration zone must be locked. THis form of
%% lock expects thhe given CRC to match the CRC of the zone being
%% locked before the lock succeeds.
-spec lock(pid(), config | data | {slot, 0..15}, CRC::<<_:16>>) -> ok | {error, term()}.
lock(Pid, ZoneOrSlot, CRC) ->
    execute(Pid, command({lock, ZoneOrSlot, CRC})).

%% @doc Generates a key of a given type either into or from a given
%% slot. For private keys the given slot is expected to be configured
%% for private key use (see ecc_slot_config/0). The corresponding
%% public key is returned.
%%
%% For public keys the public key is generated from the private key in
%% the given slot and returned.
-spec genkey(I2C::pid(), Type::private | public, Slot::0..15)
            -> {ok, public_key:public_key()} | {error, term()}.
genkey(Pid, Type, KeyId) ->
    genkey(Pid, Type, KeyId, 0).

%% @private The datasheet indicates that generating keys has a small
%% statistical chance of failing. This funtin allows up to three
%% retries.
-spec genkey(I2C::pid(), private | public, Slot::non_neg_integer(), RetryCount::non_neg_integer())
            -> {ok, public_key:public_key()} | {error, term()}.
genkey(Pid, Type, KeyId, RetryCount) when Type == public orelse Type == private ->
    case RetryCount of
        3 ->
            {error, ecc_genkey_failed};
        _ ->
            case execute(Pid, command({genkey, Type, KeyId})) of
                {error, ecc_response_ecc_fault} ->
                    genkey(Pid, Type, KeyId, RetryCount + 1);
                {error, Error} ->
                    {error, Error};
                {ok, awake} ->
                    {error, ecc_asleep};
                {ok, Data} ->
                    PubPoint = <<4:8, Data/binary>>,
                    {ok, {#'ECPoint'{point=PubPoint}, {namedCurve, ?secp256r1}}}
            end
    end.

%% @doc Compputes a premaster secret from a given private keyslot and
%% a given public key. The computed key isreturned in the clear
ecdh(Pid, KeyId, {#'ECPoint'{point=PubPoint}, _}) ->
    << _:8, X:32/binary, Y:32/binary>> = PubPoint,
    execute(Pid, command({ecdh, KeyId, X, Y})).


%% @doc Generates a nonce and returns it, optionally updating the
%% random seed. For a `passthrough' nonce the given data is stored in
%% the given temporay storage area in SRAM. The passthrough method is
%% used for a number of security commands, including signing and
%% verifiyng.
-spec nonce(I2C::pid(),
            {passthrough, msg_digest | tempkey | altkey} | {random, UpdateSeed::boolean()},
            Data::binary()) -> ok | {error, term()}.
nonce(Pid, {passthrough, Target}, Data) ->
    case execute(Pid, command({nonce, {passthrough, Target}, Data})) of
        {ok, awake} -> {error, ecc_asleep};
        Other -> Other
    end;
nonce(Pid, {random, UpdateSeed}, Data) when is_boolean(UpdateSeed) ->
    case execute(Pid, command({nonce, {random, UpdateSeed}, Data})) of
        {ok, awake} -> {error, ecc_asleep};
        Other -> Other
    end.


%% @doc Generates a random series of bytes and update the seed. Note
%% that a standard test pattern is returned when the configuration
%% zone is not locked.
-spec random(I2C::pid()) -> {ok, binary()} | {error, term()}.
random(Pid) ->
    random(Pid, 16#00).

-spec random(I2C::pid(), Seed::non_neg_integer()) -> {ok, binary()} | {error, term()}.
random(Pid, Seed) ->
    case execute(Pid, command({random, Seed})) of
        {ok, awake} -> {error, ecc_asleep};
        Other -> Other
    end.


-record(digest, {
                 kind :: sha | hmac
                }).

-spec digest_init(I2C::pid(), {hmac, Slot::non_neg_integer()} | sha)
                 -> {ok, #digest{}} | {error, term()}.
digest_init(Pid, Kind) ->
    case execute(Pid,command({digest, {init, Kind}})) of
        ok -> {ok, #digest{kind=Kind}};
        {ok, awake} -> {error, ecc_asleep};
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
        {ok, awake} -> {error, ecc_asleep};
        {error, Error} -> {error, Error}
    end;
digest_update(Pid, State=#digest{}, {data, Data}) ->
    case byte_size(Data) > 64 of
        true ->
            <<Part:64/binary, Rest/binary>> = Data,
            case execute(Pid, command({digest, {update, Part}})) of
                ok -> digest_update(Pid, State, {data, Rest});
                {ok, awake} -> {error, ecc_asleep};
                {error, Error} -> {error, Error}
            end;
        false ->
            case execute(Pid, command({digest, {update, Data}})) of
                ok -> {ok, State};
                {ok, awake} -> {error, ecc_asleep};
                {error, Error} -> {error, Error}
            end
    end.

-spec digest_finalize(I2C::pid(), State::#digest{}, FinalData::binary())
                     -> {ok, <<_:32>>} | {error, term()}.
digest_finalize(Pid, State, FinalData) when byte_size(FinalData) =< 63 ->
    execute(Pid, command({digest, {finalize, {State#digest.kind, FinalData}}})).




%% @doc Signs a given binary with the private key in the given key
%% slot. The given data can be either a binary which will be sha256 or
%% a custom digest for which the digest tuple can be used to bypass
%% the sha method.
-spec sign(I2C::pid(), KeyId::non_neg_integer(), Data::binary() | {digest, binary()})
          -> {ok, binary()} | {error, term()}.
sign(Pid, KeyId, {digest, Digest}) ->
    case random(Pid) of
        {error, Error} ->
            {error, Error};
        {ok, _} ->
            case nonce(Pid, {passthrough, msg_digest}, Digest) of
                {error, Error} ->
                    {error, Error};
                ok ->
                    case execute(Pid, command({sign, {external, msg_digest, KeyId}})) of
                        {error, Error} ->
                            {error, Error};
                        {ok, awake} ->
                            {error, ecc_asleep};
                        {ok, <<R:256/unsigned-integer-big, S:256/unsigned-integer-big>>} ->
                            {ok, public_key:der_encode('ECDSA-Sig-Value', #'ECDSA-Sig-Value'{r=R, s=S})}
                    end
            end
    end;
sign(Pid, KeyId, Data) ->
    sign(Pid, KeyId, {digest, crypto:hash(sha256, Data)}).


%% @doc Verifiies a message or it's digest using a given signature and
%% public key.
-spec verify(I2C::pid(), Data::binary() | {digest, binary()},
             Signature::binary(), PubKey::public_key:public_key()) -> ok | {error, term()}.
verify(Pid, {digest, Digest}, Signature, _ECPubKey={#'ECPoint'{point=PubPoint}, _}) ->
    << _:8, X:32/binary, Y:32/binary>> = PubPoint,
    #'ECDSA-Sig-Value'{r=R, s=S} = public_key:der_decode('ECDSA-Sig-Value', Signature),
    case nonce(Pid, {passthrough, msg_digest}, Digest) of
        {error, Error} ->
            {error, Error};
        ok ->
            execute(Pid, command({verify, {external,
                                           msg_digest,
                                           <<R:256/unsigned-integer-big>>,
                                           <<S:256/unsigned-integer-big>>,
                                           X,
                                           Y}}))
    end;
verify(Pid, Data, Signature, ECPubKey) ->
    verify(Pid, {digest, crypto:hash(sha256, Data)}, Signature, ECPubKey).


%% @doc Read 4 or 32 bytes from a given zone and block. The address
%% can be passed in using the convenience tuples representing address
%% in either the config, data or otp zones.
-spec read(I2C::pid(), Size::4 | 32, Address::address()) -> {ok, binary()} | {error, term()}.
read(Pid, Size, Address) ->
    execute(Pid, command({read, Size, Address})).

%% @doc Writes a given binary to a given address. The address can be
%% passed in using the convenience tuples representing address in
%% either the config, data or otp zones.
-spec write(I2C::pid(), Address::address(), Data::<<_:32>> | <<_:256>>) -> ok | {error, term()}.
write(Pid, Address, <<Data/binary>>) ->
    execute(Pid, command({write, Address, Data})).



%%
%% Internal
%%

-spec spec(Name::atom()) -> #spec{}.
spec(N=checkmac)    -> #spec{name=N, opcode=16#28, timing_typ=5,  timing_max=13};
spec(N=counter)     -> #spec{name=N, opcode=16#24, timing_typ=5,  timing_max=20};
spec(N=derivekey)   -> #spec{name=N, opcode=16#24, timing_typ=2,  timing_max=50};
spec(N=ecdh)        -> #spec{name=N, opcode=16#43, timing_typ=38, timing_max=58};
spec(N=gendig)      -> #spec{name=N, opcode=16#15, timing_typ=5,  timing_max=11};
spec(N=genkey)      -> #spec{name=N, opcode=16#40, timing_typ=11, timing_max=115};
spec(N=hmac)        -> #spec{name=N, opcode=16#11, timing_typ=13, timing_max=23};
spec(N=info)        -> #spec{name=N, opcode=16#30, timing_typ=0,  timing_max=1};
spec(N=lock)        -> #spec{name=N, opcode=16#17, timing_typ=8,  timing_max=32};
spec(N=mac)         -> #spec{name=N, opcode=16#08, timing_typ=5,  timing_max=14};
spec(N=nonce)       -> #spec{name=N, opcode=16#16, timing_typ=0,  timing_max=7};
spec(N=privwrite)   -> #spec{name=N, opcode=16#46, timing_typ=1,  timing_max=48};
spec(N=random)      -> #spec{name=N, opcode=16#1B, timing_typ=1,  timing_max=23, resp=32};
spec(N=read)        -> #spec{name=N, opcode=16#02, timing_typ=0,  timing_max=1};
spec(N=sha)         -> #spec{name=N, opcode=16#47, timing_typ=42, timing_max=50};
spec(N=sign)        -> #spec{name=N, opcode=16#41, timing_typ=7,  timing_max=9};
spec(N=updateextra) -> #spec{name=N, opcode=16#20, timing_typ=8,  timing_max=10};
spec(N=verify)      -> #spec{name=N, opcode=16#45, timing_typ=38, timing_max=58};
spec(N=write)       -> #spec{name=N, opcode=16#12, timing_typ=7,  timing_max=26};
%% not in spec
spec(N=wake)        -> #spec{name=N, opcode=16#00, timing_typ=0,  timing_max=1};
spec(N=sleep)       -> #spec{name=N, opcode=16#00, timing_typ=0,  timing_max=1};
spec(N=idle)        -> #spec{name=N, opcode=16#00, timing_typ=0,  timing_max=1};
spec(N=reset)       -> #spec{name=N, opcode=16#00, timing_typ=0,  timing_max=1}.


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
bool_to_bit(false) -> 0.

-spec bit_to_bool(0 | 1) -> true | false.
bit_to_bool(1) -> true;
bit_to_bool(0) -> false.

nonce_target_bits(tempkey) -> 0;
nonce_target_bits(msg_digest) -> 1;
nonce_target_bits(altkey) -> 2.

nonce_size_bits(Data) when byte_size(Data) == 32 -> 0;
nonce_size_bits(Data) when byte_size(Data) == 64 -> 1.

sign_source_bits(tempkey) -> 0;
sign_source_bits(msg_digest) -> 1.

verify_source_bits(tempkey) -> 0;
verify_source_bits(msg_digest) -> 1.


-spec command(Cmd::atom(), Param1::<<_:8>>, Param2::<<_:16>>, Data::binary()) -> #command{}.
command(Type, Param1, Param2, Data) ->
    Spec = spec(Type),
    #command{spec=Spec, param1=Param1, param2=Param2, data=Data}.

command(wake) ->
    command(wake, <<0:8>>, <<0:16>>, <<0:184>>);
command(idle) ->
    command(idle, <<0:8>>, <<0:16>>, <<>>);
command(sleep) ->
    command(sleep, <<0:8>>, <<0:16>>, <<>>);
command(reset) ->
    command(reset, <<0:8>>, <<0:16>>, <<>>);
command({genkey, private, KeyId}) ->
    command(genkey, <<16#04:8>>, <<KeyId:16/unsigned-little-integer>>, <<>>);
command({genkey, public, KeyId}) ->
    command(genkey, <<16#00:8>>, <<KeyId:16/unsigned-little-integer>>, <<>>);
command({nonce, {passthrough, Target}, Data}) ->
    Param1 = <<(nonce_target_bits(Target)):2, (nonce_size_bits(Data)):1, 0:3, 16#03:2>>,
    DataSize = byte_size(Data),
    command(nonce, Param1, <<0:16>>, <<Data:DataSize/binary>>);
command({nonce, {random, UpdateSeed}, Data}) when byte_size(Data) == 20 ->
    Param1 = <<(bool_to_bit(not UpdateSeed)):8>>,
    command(nonce, Param1, <<0:16>>, <<Data:20/binary>>);
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
command({sign, {external, Source, KeyId}}) ->
    Param1 = <<2#10:2, (sign_source_bits(Source)):1, 2#00000:5>>,
    command(sign, Param1, <<KeyId:16/integer-unsigned-little>>, <<>>);
command({verify, {external, Source, R, S, X, Y}}) ->
    Param1 = <<2#00:2, (verify_source_bits(Source)):1, 2#00:2, 2#010:3>>,
    Data = <<R/binary, S/binary, X/binary, Y/binary>>,
    command(verify, Param1, <<16#04, 16#00>>, Data);
command({read, Size, Address}) ->
    Param1 = <<(encode_read_write_size(Size)):1, 0:5, (encode_address_zone(Address)):2>>,
    command(read, Param1, encode_address(Address), <<>>);
command({write, Address, Data}) ->
    Param1 = <<(encode_read_write_size(byte_size(Data))):1, 0:5, (encode_address_zone(Address)):2>>,
    command(write, Param1, encode_address(Address), Data);
command({lock, Zone, CRC}) ->
    {ZoneBits, SlotBits} = case Zone of
                   config -> {2#00, 0};
                   data -> {2#01, 0};
                   {slot, Slot} -> {2#10, Slot};
                   V -> throw({invalid_lock_zone, V})
               end,
    CRCBit = case CRC of
                 <<16#00, 16#00>> -> 1;
                 _ -> 0
             end,
    Param1 = <<CRCBit:1, 0:1, SlotBits:4, ZoneBits:2>>,
    command(lock, Param1, crc16:rev(CRC), <<>>);
command({ecdh, KeyId, X, Y}) ->
    command(ecdh, <<16#00>>, <<KeyId:16/unsigned-little-integer>>, <<X/binary, Y/binary>>).


to_hex(Bin) ->
    << <<Y>> ||<<X:4>> <= Bin, Y <- integer_to_list(X,16)>>.

-spec wait_for_response(I2C::pid(), {WaitExtra::boolean(), WaitStartTime::pos_integer()}, Cmd::#command{})
                       -> ok | {error, term()} | {ok, pos_integer()}.
wait_for_response(_Pid, _, #command{spec=#spec{name=reset}}) ->
    ok;
wait_for_response(_Pid, _, #command{spec=#spec{name=sleep}}) ->
    ok;
wait_for_response(Pid, {Extra, StartTime}, Cmd=#command{spec=Spec}) ->
    case Extra of
        false -> timer:sleep(Spec#spec.timing_typ);
        true -> timer:sleep(max(0, Spec#spec.timing_max - (get_timestamp() - StartTime)))
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
    case i2c:read(Pid, min(Length, 32)) of
        {error, Error} ->
            {error, Error};
        Bin ->
            read_response(Pid, Length - byte_size(Bin), <<Acc/binary, Bin/binary>>)
    end.

-spec execute(I2C::pid(), Cmd::#command{})
             -> ok | {ok, awake} | {ok, binary()} | {error, term()}.
execute(Pid, Cmd) ->
    execute(Pid, command, Cmd).

-spec execute(I2C::pid(), Word::reset | idle | command | sleep, Cmd::#command{})
             -> ok | {ok, awake} | {ok, binary()} | {error, term()}.
execute(Pid, Word, _) when Word == sleep; Word == idle ->
    BinWord = package_word(Word),
    i2c:write(Pid, <<BinWord:8/integer-unsigned>>),
    ok;
execute(Pid, Word, Cmd)->
    Data = <<(Cmd#command.spec#spec.opcode):8,
             (Cmd#command.param1)/binary,
             (Cmd#command.param2)/binary,
             (Cmd#command.data)/binary>>,
    Bin = package(Word, Data),
    i2c:write(Pid, Bin),
    case wait_for_response(Pid, {false, get_timestamp()}, Cmd) of
        {error, Error} ->
            {error, Error};
        ok ->
            ok;
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
                {ok, <<V:8/unsigned-integer>>}   -> {error, {ecc_unknown_response, V}};
                {ok, RespBin} -> {ok, RespBin}
            end
    end.

-spec package_word(atom()) -> non_neg_integer().
package_word(reset)    -> 16#00;
package_word(sleep)    -> 16#01;
package_word(idle)     -> 16#02;
package_word(command)  -> 16#03.

-spec package(Word::atom(), binary()) -> binary().
package(_Word, Bin) when byte_size(Bin) < ?CMDGRP_COUNT_MIN ->
    throw({ecc_command_too_small, byte_size(Bin)});
package(_Word, Bin) when byte_size(Bin) > ?CMDGRP_COUNT_MAX ->
    throw({ecc_command_too_large, byte_size(Bin)});
package(Word, Bin) ->
    PackageLen = byte_size(Bin) + 3,
    LenBin = <<PackageLen, Bin/binary>>,
    CheckSum = crc16:calc(LenBin),
    <<(package_word(Word)):8, LenBin/binary, CheckSum/binary>>.


get_timestamp() ->
  {Mega, Sec, Micro} = os:timestamp(),
  (Mega*1000000 + Sec)*1000 + round(Micro/1000).
