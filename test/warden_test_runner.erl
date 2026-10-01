%% Suite-aware test entry point.
%%
%% WARDEN_SUITE=fast (default) runs every test module outside
%% test/integration/. WARDEN_SUITE=<provider> runs only the modules under
%% test/integration/<provider>/. A provider suite never falls back to the fast
%% suite, and an unreachable provider fails its tests rather than skipping them.
-module(warden_test_runner).

-export([main/0]).

main() ->
    Suite = os:getenv("WARDEN_SUITE", "fast"),
    Files = filelib:wildcard("**/*.{erl,gleam}", "test"),
    Selected = [F || F <- Files, selected(Suite, F)],
    Modules = [list_to_atom(module_name(F)) || F <- Selected],
    io:format("warden suite ~s: ~b modules~n", [Suite, length(Modules)]),
    Options = [verbose, no_tty, {report, {gleeunit_progress, [{colored, true}]}}, {scale_timeouts, 10}],
    Code =
        case eunit:test(Modules, Options) of
            ok -> 0;
            _ -> 1
        end,
    erlang:halt(Code).

selected("fast", File) ->
    not lists:prefix("integration/", File);
selected(Suite, File) ->
    lists:prefix("integration/" ++ Suite ++ "/", File).

module_name(File) ->
    case filename:extension(File) of
        ".gleam" -> lists:flatten(string:replace(filename:rootname(File), "/", "@", all));
        ".erl" -> filename:basename(File, ".erl")
    end.
