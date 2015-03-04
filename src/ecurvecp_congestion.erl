-module(ecurvecp_congestion).

-export([run/1]).
-export([new/0, adjust/2]).

-define(TIME_CONST, 2251799813685248).

-record(congestion, {
    tx_throttle     :: float(),
    tx_timeout      :: float(),
    rand            :: non_neg_integer(),
    rtt_average     :: float(),
    rtt_deviation   :: float(),
    rtt_mean_dev    :: float(),
    rtt_high        :: float(),
    rtt_low         :: float(),
    last_throttle   :: erlang:timestamp(),
    falling         :: boolean(),
    was_high        :: boolean(),
    was_low         :: boolean(),
    last_edge       :: erlang:timestamp(),
    last_double     :: erlang:timestamp()
  }).

-opaque congestion() :: #congestion{}.

-export_type([congestion/0]).

-spec new() -> congestion().
new() ->
  Rand = erlang:phash2(erlang:now()),
  #congestion{tx_throttle=1000.0, tx_timeout=1000.0, rand=Rand,
              falling=false}.

init(RTT, #congestion{} = C0) ->
  C0#congestion{tx_throttle=RTT, rtt_average=RTT, rtt_deviation=RTT/2,
                rtt_high=RTT, rtt_low=RTT, rtt_mean_dev=RTT,
                last_throttle=erlang:now()}.

-spec adjust(pos_integer(), congestion()) -> congestion().
adjust(RTT, #congestion{rtt_average=undefined} = C0) ->
  adjust(RTT, init(RTT, C0));
adjust(RTT, #congestion{} = C0) ->
  maybe_adjust_tx_throttle(
    adjust_top_and_bottom(RTT, adjust_tx_timeout(RTT, C0))).

-spec adjust_tx_timeout(pos_integer(), congestion()) -> congestion().
adjust_tx_timeout(RTT, #congestion{} = C0) ->
  #congestion{rtt_average=RTTAverage0, rtt_mean_dev=RTTMeanDev0,
              tx_throttle=TxThrottle0, rtt_deviation=RTTDeviation0} = C0,
  AverageDelta = RTT - RTTAverage0,
  MeanDevDelta = erlang:abs(AverageDelta) - RTTMeanDev0,
  RTTAverage = RTTAverage0 + (AverageDelta / 8),
  RTTMeanDev = RTTMeanDev0 + (MeanDevDelta / 4),
  TxTimeout = (RTTAverage + (4 * RTTDeviation0)) + (8 * TxThrottle0),

  C0#congestion{rtt_average=RTTAverage, rtt_mean_dev=RTTMeanDev,
                tx_timeout=TxTimeout}.

-spec adjust_top_and_bottom(pos_integer(), congestion()) -> congestion().
adjust_top_and_bottom(RTT, #congestion{} = C0) ->
  RTTHigh = (RTT - C0#congestion.rtt_high) / 1024,
  LowDelta = RTT - C0#congestion.rtt_low,
  RTTLow = if LowDelta > 0 ->
      LowDelta / 8192;
    true ->
      LowDelta / 256
  end,
  C0#congestion{rtt_high=RTTHigh, rtt_low=RTTLow}.

-spec maybe_adjust_tx_throttle(congestion()) -> congestion().
maybe_adjust_tx_throttle(#congestion{} = C0) ->
  #congestion{last_throttle=LastThrottle, tx_throttle=TxThrottle} = C0,
  % Duration between adjustments in milliseconds
  SinceAdjust = (timer:now_diff(erlang:now(), LastThrottle)) / 1000,
  % Adjust throttle every 16 intervals
  % No activity for >10s, do slow restart
  case {SinceAdjust >= 16 * TxThrottle, SinceAdjust > 10000} of
    {true, true} ->
      slow_start_throttle(C0);
    {true, false} ->
      adjust_tx_throttle(C0);
    {false, _} ->
      C0
  end.

-spec slow_start_throttle(congestion()) -> congestion().
slow_start_throttle(#congestion{} = C0) ->
  TxThrottle = 1000 + random:uniform(125),
  adjust_tx_throttle(C0#congestion{tx_throttle=TxThrottle}).

-spec adjust_tx_throttle(congestion()) -> congestion().
adjust_tx_throttle(#congestion{} = C0) ->
  #congestion{tx_throttle=TxThrottle0} = C0,
  LastThrottle = erlang:now(),

  % Greater Than 100 microseconds, Less Than 16 milliseconds
  TxThrottle = case {TxThrottle0 > 0.1, TxThrottle0 < 16} of
      {true, true} ->
        % N' = N - cN^3
        TxThrottle0 - (TxThrottle0 * TxThrottle0 * TxThrottle0 / ?TIME_CONST);
      {true, false} ->
        % N' = N /(1 + cN^2)
        TxThrottle0 / (1 + TxThrottle0 * TxThrottle0 / ?TIME_CONST);
      {false, _} ->
        TxThrottle0
    end,
  adjust_falling(C0#congestion{tx_throttle=TxThrottle, last_throttle=LastThrottle}).

-spec adjust_falling(congestion()) -> congestion().
adjust_falling(#congestion{} = C0) ->
  #congestion{falling=Failing, was_low=WasLow, was_high=WasHigh,
              tx_throttle=TxThrottle0} = C0,
  C1 = case {Failing, WasLow, WasHigh} of
    {true, true, _} ->
      C0#congestion{falling=false};
    {false, _, true} ->
      TxThrottle = TxThrottle0 + random:uniform(erlang:trunc(TxThrottle0/4)),
      C0#congestion{falling=true, last_edge=erlang:now(), tx_throttle=TxThrottle};
    _ ->
      C0
  end,
  adjust_was_high_low(C1).

-spec adjust_was_high_low(congestion()) -> congestion().
adjust_was_high_low(#congestion{} = C0) ->
  #congestion{rtt_average=RTTAverage, rtt_low=RTTLow, rtt_high=RTTHigh} = C0,
  WasLow = RTTAverage < RTTLow,
  WasHigh = RTTAverage > (RTTHigh + 5),
  C0#congestion{was_low=WasLow, was_high=WasHigh}.

run(Congestion) ->
  receive
    _ ->
      C1 = ecurvecp_congestion:adjust(1000, Congestion),
      ok = io:format("~p~n", [C1]),
      run(C1)
  after
    30000 ->
      ok
  end.
