-module(ecurvecp).

-export([get_prop_or_env/2, get_prop_or_env/3, get_env/2]).

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
