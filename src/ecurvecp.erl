-module(ecurvecp).

-export([start_client/4, start_listener/4, stop_listener/1, extension/0]).
-export([get_prop_or_env/2, get_prop_or_env/3, get_env/2]).

start_client(Ip, Port, ServerExtension, ServerPublicKey) ->
  ecurvecp_client_sup:start_client(Ip, Port, ServerExtension, ServerPublicKey).

start_listener(Ref, NumListeners, TransOpts0, ProtoOpts0) ->
  ProtoOpts = lists:foldl(fun set_prop_default_or_env/2, ProtoOpts0, ecurvecp_protocol:default_options()),
  TransOpts = lists:foldl(fun set_prop_default_or_env/2, TransOpts0, default_listener_options()),

  ecurvecp_server_sup:start_listener(Ref, NumListeners, TransOpts, ProtoOpts).

stop_listener(Ref) ->
  ecurvecp_server_sup:stop_listener(Ref).

extension() ->
  druuid:v4().

default_listener_options() ->
  [{ip, {127,0,0,1}},
   {ip, {0,0,0,0,0,0,1}},
   {port, 46779}].

set_prop_default_or_env({Key, Default}, Props) ->
  set_prop_default_or_env(Key, Default, Props).

set_prop_default_or_env(Key, Default, Props) ->
  case lists:keymember(Key, 1, Props) of
    true ->
      Props;
    false ->
      [{Key, get_env(Key, Default)}|Props]
  end.

get_prop_or_env(Key, Props) ->
  get_prop_or_env(Key, Props, undefined).

get_prop_or_env(Key, Props, Default) ->
  case proplists:get_value(Key, Props) of
    undefined ->
      get_env(Key, Default);
    Value ->
      Value
  end.

get_env(Key, Default) ->
  application:get_env(?MODULE, Key, Default).
