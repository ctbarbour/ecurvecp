-module(ecurvecp_codec_tests).
-compile(export_all).

-include_lib("proper/include/proper.hrl").
-include_lib("eunit/include/eunit.hrl").

encode_decode_test_() ->
  {timeout, 60, ?_assert(proper:quickcheck(prop_encode_decode(), [{to_file, user}]))}.

codec_test_() ->
  {timeout, 60,
   {setup,
    fun setup/0,
    fun cleanup/1, fun(_) ->
          ?_assert(proper:quickcheck(prop_codec(), [{to_file, user}]))
      end
   }}.

setup() ->
  {ok, _} = application:ensure_all_started(ecurvecp).

cleanup(_) ->
  ok = application:stop(ecurvecp).

keypair() ->
  #{public := PK, secret := SK} = enacl:box_keypair(),
  {PK, SK}.

extension() ->
  ecurvecp:extension().

server_codec(PK, SK, SE) ->
  ecurvecp_codec:generate_short_term_keypair(
    ecurvecp_codec:rotate_minute_keys(
      ecurvecp_codec:new_server_codec(PK, SK, SE))).

client_codec(CPK, CSK, CE, SPK, SE) ->
  ecurvecp_codec:generate_short_term_keypair(
    ecurvecp_codec:new_client_codec(CPK, CSK, CE, SPK, SE)).

codec_pair() ->
  SE = extension(),
  {SPK, SSK} = keypair(),
  {CPK, CSK} = keypair(),
  {client_codec(CPK, CSK, extension(), SPK, SE),
   server_codec(SPK, SSK, SE)}.

validate_codec_pair(ClientCodec, ServerCodec, Attrs) ->
  ecurvecp_codec:validate_codec_pair(ClientCodec, ServerCodec, Attrs).

keypair_valid(PK, SK) when is_binary(PK), is_binary(SK) ->
  PKBytes = enacl:box_public_key_bytes(),
  SKBytes = enacl:box_secret_key_bytes(),
  byte_size(PK) == PKBytes andalso byte_size(SK) == SKBytes;
keypair_valid(_, _) ->
  false.

prop_encode_decode() ->
  ?FORALL({PK, SK}, keypair(), keypair_valid(PK, SK)).

prop_codec() ->
  ?FORALL({ClientCodec, ServerCodec0}, codec_pair(),
          begin
            HelloPacket = ecurvecp_codec:encode_hello_packet(ClientCodec),
            ServerCodec = ecurvecp_codec:decode_curvecp_packet(HelloPacket, ServerCodec0),
            validate_codec_pair(ClientCodec, ServerCodec,
                               [client_extension, server_extension,
                               server_long_term_public_key,
                               client_short_term_public_key])
          end).
