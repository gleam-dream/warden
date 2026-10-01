%% Test support exposed to Gleam tests.
-module(warden_test_support_ffi).

-export([ca_pem/0, keycloak_login/3, authorize/2, visit/1, count_reset/0, count/1, handle/4, pki_file/1, spawn_collect/2]).

ca_pem() ->
    Dir = warden_test_server:pki_dir(),
    {ok, Pem} = file:read_file(filename:join(binary_to_list(Dir), "ca.pem")),
    Pem.

pki_file(Name) ->
    Dir = warden_test_server:pki_dir(),
    {ok, Bin} = file:read_file(filename:join(binary_to_list(Dir), binary_to_list(Name))),
    Bin.

keycloak_login(Url, User, Password) ->
    {Result, _} = warden_test_browser:login(warden_test_browser:new(), Url, binary_to_list(User), binary_to_list(Password)),
    to_gleam(Result).

authorize(Url, ProviderPrefix) ->
    {Result, _} = warden_test_browser:authorize(warden_test_browser:new(), Url, ProviderPrefix),
    to_gleam(Result).

%% One GET without login; used for prompt=none denials.
visit(Url) ->
    {ok, _} = application:ensure_all_started([inets, ssl]),
    {{Status, Headers, _}, _} = warden_test_browser:get(warden_test_browser:new(), Url),
    case Status of
        S when S >= 300, S < 400 ->
            case uri_string:parse(proplists:get_value("location", Headers)) of
                #{query := Q} -> {ok, {query, list_to_binary(Q)}};
                _ -> {error, nil}
            end;
        _ ->
            {error, nil}
    end.

to_gleam({query, Q}) -> {ok, {query, Q}};
to_gleam({form_post, B}) -> {ok, {form_post, B}};
to_gleam(_) -> {error, nil}.

%% Count Warden transport requests per URL path via telemetry.
count_reset() ->
    case ets:whereis(warden_test_counts) of
        undefined -> ets:new(warden_test_counts, [named_table, public, set]);
        _ -> ets:delete_all_objects(warden_test_counts)
    end,
    telemetry:detach(warden_test_counter),
    ok = telemetry:attach(warden_test_counter, [warden, http, request], fun ?MODULE:handle/4, nil),
    nil.

handle(_Event, _Measurements, Meta, _Config) ->
    Path = maps:get(path, Meta, <<>>),
    ets:update_counter(warden_test_counts, Path, 1, {Path, 0}).

count(Suffix) ->
    case ets:whereis(warden_test_counts) of
        undefined -> 0;
        _ ->
            lists:sum([N || {Path, N} <- ets:tab2list(warden_test_counts), is_suffix(Suffix, Path)])
    end.

is_suffix(Suffix, Path) ->
    byte_size(Path) >= byte_size(Suffix) andalso
        binary:part(Path, byte_size(Path) - byte_size(Suffix), byte_size(Suffix)) =:= Suffix.

%% Run each function in its own process, released together, and collect
%% results in order.
spawn_collect(Funs, TimeoutMs) ->
    Parent = self(),
    Go = make_ref(),
    Pids = [spawn(fun() -> receive Go -> ok end, Parent ! {self(), F()} end) || F <- Funs],
    [P ! Go || P <- Pids],
    [receive {P, R} -> R after TimeoutMs -> timeout end || P <- Pids].
