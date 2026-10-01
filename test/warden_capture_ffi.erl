%% Capture every logger event and Warden/oidcc telemetry event during a test,
%% for secret-sentinel inspection.
-module(warden_capture_ffi).
-export([start/0, stop/0, contains/1, log/2, event/4]).

start() ->
    case ets:whereis(warden_capture) of
        undefined -> ets:new(warden_capture, [named_table, public, bag]);
        _ -> ets:delete_all_objects(warden_capture)
    end,
    _ = logger:remove_handler(warden_capture),
    ok = logger:add_handler(warden_capture, ?MODULE, #{level => all}),
    Events = [[warden, http, request] | [[oidcc, E, S] || E <- [request_token, refresh_token, client_credentials, introspect_token, userinfo, load_configuration, load_jwks], S <- [start, stop, exception]]],
    telemetry:detach(warden_capture),
    ok = telemetry:attach_many(warden_capture, Events, fun ?MODULE:event/4, nil),
    nil.

stop() ->
    _ = logger:remove_handler(warden_capture),
    telemetry:detach(warden_capture),
    nil.

log(Event, _Config) ->
    Text = iolist_to_binary(logger_formatter:format(Event, #{single_line => true, depth => unlimited, chars_limit => unlimited})),
    ets:insert(warden_capture, {log, Text}).

event(Name, Measurements, Meta, _) ->
    ets:insert(warden_capture, {telemetry, term_to_binary({Name, Measurements, Meta})}).

%% True when any captured log text or telemetry payload contains `Needle`.
contains(Needle) ->
    lists:any(
        fun({_, Bin}) -> binary:match(Bin, Needle) =/= nomatch end,
        ets:tab2list(warden_capture)
    ).
