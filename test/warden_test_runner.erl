%% Suite selection is explicit and must contain tests.
-module(warden_test_runner).
-export([main/0, select/2]).

main() ->
    Suite = os:getenv("WARDEN_SUITE", "fast"),
    Files = filelib:wildcard("**/*.{erl,gleam}", "test"),
    case select(Suite, Files) of
        {error, Reason} ->
            io:format(standard_error, "warden suite selection failed: ~p~n", [Reason]),
            erlang:halt(1);
        {ok, Selected} ->
            Modules = lists:usort([list_to_atom(module_name(F)) || F <- Selected]),
            io:format("warden suite ~s: ~b modules~n", [Suite, length(Modules)]),
            Options = [verbose, no_tty, {report, {gleeunit_progress, [{colored, true}]}}, {scale_timeouts, 10}],
            Code = case eunit:test(Modules, Options) of ok -> 0; _ -> 1 end,
            erlang:halt(Code)
    end.

select(Suite, Files) ->
    case lists:member(Suite, ["fast", "node", "keycloak", "interop"]) of
        false -> {error, {unknown_suite, Suite}};
        true ->
            Selected = [F || F <- Files, selected(Suite, F)],
            case lists:any(fun has_tests/1, Selected) of
                false -> {error, {empty_suite, Suite}};
                true -> {ok, Selected}
            end
    end.

has_tests(File) -> lists:suffix("_test.erl", File) orelse lists:suffix("_test.gleam", File).

selected("fast", File) -> not lists:prefix("integration/", File);
selected(Suite, File) -> lists:prefix("integration/" ++ Suite ++ "/", File).

module_name(File) ->
    case filename:extension(File) of
        ".gleam" -> lists:flatten(string:replace(filename:rootname(File), "/", "@", all));
        ".erl" -> filename:basename(File, ".erl")
    end.
