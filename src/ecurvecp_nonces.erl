-module(ecurvecp_nonces).

-define(TAB, ?MODULE).

-export([short_term_nonce/1, long_term_nonce_counter/1,
         long_term_nonce_timestamp/0, nonce_string/2]).

short_term_nonce(Key) ->
  I = erlang:phash2(Key),
  F = fun(N) ->
      true = ets:insert(?TAB, {I, N}),
      <<N:64/unsigned-little-integer>>
  end,
  case ets:lookup(?TAB, I) of
    [{I, N0}] ->
      F(N0 + 1);
    [] ->
      F(1)
  end.

long_term_nonce_counter(Key) ->
  I = erlang:phash2(Key),
  F = fun(N) ->
      true = ets:insert(?TAB, {I, N}),
      <<N:64/unsigned-little-integer, (enacl:randombytes(8))/binary>>
  end,
  case ets:lookup(?TAB, I) of
    [{I, N0}] ->
      F(N0 + 1);
    [] ->
      F(1)
  end.

long_term_nonce_timestamp() ->
  {MegaSecs, Secs, MicroSecs} = erlang:now(),
  MicroSinceEpoch = (MegaSecs * 1000000 + Secs) * 1000000 + MicroSecs,
  N = <<MicroSinceEpoch:64/unsigned-little-integer, (enacl:randombytes(8))/binary>>,
  true = ets:insert(?TAB, {long_term_nonce_timestamp, N}),
  N.

nonce_string(hello, <<_:8/binary>> = Nonce) ->
  <<"CurveCP-client-H", Nonce/binary>>;
nonce_string(cookie, <<_:16/binary>> = Nonce) ->
  <<"CurveCPK", Nonce/binary>>;
nonce_string(vouch, <<_:16/binary>> = Nonce) ->
  <<"CurveCPV", Nonce/binary>>;
nonce_string(initiate, <<_:8/binary>> = Nonce) ->
  <<"CurveCP-client-I", Nonce/binary>>;
nonce_string(server_message, <<_:8/binary>> = Nonce) ->
  <<"CurveCP-server-M", Nonce/binary>>;
nonce_string(client_message, <<_:8/binary>> = Nonce) ->
  <<"CurveCP-client-M", Nonce/binary>>;
nonce_string(minute_key, <<_:16/binary>> = Nonce) ->
  <<"minute-k", Nonce/binary>>.
