%% Test support exposed to Gleam tests.
-module(warden_test_support_ffi).

-export([client_private_jwk/0, adapter_request/2, server_start/2, server_url/2, server_requests/1, server_stop/1, ca_der/0, worker_kill/1, worker_alive/1, atom_count/0, process_count/0, form_login/3, print/1, node_reset/0, node_next/2, node_log/0, keycloak_logout/1, clock_new/1, clock_set/2, clock_read/1, provider_start/1, kill_named/1, ca_pem/0, keycloak_login/3, authorize/2, visit/1, count_reset/0, count/1, handle/4, pki_file/1, spawn_collect/2]).

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

%% Fake clock shared across processes.
clock_new(Start) ->
    Ref = atomics:new(1, [{signed, true}]),
    atomics:put(Ref, 1, Start),
    Ref.
clock_set(Ref, Value) -> atomics:put(Ref, 1, Value), nil.
clock_read(Ref) -> atomics:get(Ref, 1).

provider_start(Variant) ->
    warden_test_provider:start(overrides(Variant)).

overrides(standard) -> #{};
overrides(no_s256) -> #{<<"code_challenge_methods_supported">> => [<<"plain">>]};
overrides(unadvertised_pkce) -> #{<<"code_challenge_methods_supported">> => delete};
overrides(requires_par) -> #{<<"require_pushed_authorization_requests">> => true, <<"pushed_authorization_request_endpoint">> => <<"https://localhost:1/par">>};
overrides(no_end_session) -> #{<<"end_session_endpoint">> => delete};
overrides(wrong_issuer) -> #{<<"issuer">> => <<"https://evil.example">>};
overrides(no_iss_parameter) -> #{<<"authorization_response_iss_parameter_supported">> => false};
overrides(no_form_post) -> #{<<"response_modes_supported">> => [<<"query">>]};
overrides(hs256_only) -> #{<<"id_token_signing_alg_values_supported">> => [<<"HS256">>]}.

%% Kill the process registered under a Gleam process name.
kill_named(Name) ->
    case whereis(Name) of
        undefined -> nil;
        Pid -> exit(Pid, kill), nil
    end.

%% Follow an RP-initiated logout URL. Keycloak returns 302 to the
%% post-logout URI when id_token_hint is valid.
keycloak_logout(Url) ->
    {ok, _} = application:ensure_all_started([inets, ssl]),
    case warden_test_browser:get(warden_test_browser:new(), Url) of
        {{Status, Headers, _}, _} when Status >= 300, Status < 400 ->
            case uri_string:parse(proplists:get_value("location", Headers)) of
                #{query := Q} -> {ok, {query, list_to_binary(Q)}};
                _ -> {error, nil}
            end;
        _ ->
            {error, nil}
    end.

%% node-oidc-provider control API.
node_url(Path) -> "https://localhost:19443/__control/" ++ Path.

node_ssl() ->
    [{verify, verify_peer}, {cacerts, [warden_test_pki:ca_der(warden_test_server:pki_dir())]},
     {customize_hostname_check, [{match_fun, public_key:pkix_verify_hostname_match_fun(https)}]}].

node_post(Path, Map) ->
    {ok, _} = application:ensure_all_started([inets, ssl]),
    {ok, {{_, 204, _}, _, _}} = httpc:request(post, {node_url(Path), [], "application/json", iolist_to_binary(json:encode(Map))}, [{ssl, node_ssl()}], []),
    nil.

node_reset() -> node_post("reset", #{}).

%% Actions from Gleam: [{Key, Value}] with binary keys.
node_next(Grant, Actions) ->
    node_post("next", maps:from_list([{<<"grant">>, Grant} | [action(A) || A <- Actions]])).

action({node_id_token, M}) -> {<<"idToken">>, M};
action(node_omit_id_token) -> {<<"omitIdToken">>, true};
action(node_drop_refresh_token) -> {<<"dropRefreshToken">>, true};
action({node_delay_ms, Ms}) -> {<<"delayMs">>, Ms};
action({node_status, S}) -> {<<"status">>, S}.

%% Token-endpoint log: list of {GrantType, ClientId, AssertionVerified | none}.
node_log() ->
    {ok, _} = application:ensure_all_started([inets, ssl]),
    {ok, {{_, 200, _}, _, Body}} = httpc:request(get, {node_url("log"), []}, [{ssl, node_ssl()}], [{body_format, binary}]),
    [ {maps:get(<<"grant_type">>, E, null), maps:get(<<"client_id">>, E, null),
       case maps:get(<<"assertion">>, E, null) of
           null -> <<"none">>;
           #{<<"verified">> := true, <<"alg">> := Alg} -> <<"verified:", Alg/binary>>;
           #{<<"verified">> := false} -> <<"rejected">>
       end}
      || E <- json:decode(Body)].

print(Line) -> io:format(user, "~ts~n", [Line]), nil.

form_login(Url, Prefix, Fields) ->
    {Result, _} = warden_test_browser:form_login(Url, Prefix, [{binary_to_list(K), binary_to_list(V)} || {K, V} <- Fields], 12),
    to_gleam(Result).

worker_kill(Name) ->
    case whereis(Name) of undefined -> nil; Pid -> exit(Pid, kill), nil end.
worker_alive(Name) -> whereis(Name) =/= undefined.
atom_count() -> erlang:system_info(atom_count).
process_count() -> erlang:system_info(process_count).

%% Canned TLS servers for transport tests.
server_start(Cert, Kind) ->
    warden_test_server:start(binary_to_list(Cert), canned(Kind)).
server_url(Server, Path) -> warden_test_server:url(Server, binary_to_list(Path)).
server_requests(Server) -> length(warden_test_server:requests(Server)).
server_stop(Server) -> warden_test_server:stop(Server), nil.
ca_der() -> warden_test_pki:ca_der(warden_test_server:pki_dir()).

json_ok() -> {respond, 200, [{<<"content-type">>, <<"application/json">>}], <<"{\"a\":1}">>}.

canned(ok_json) -> fun(_) -> json_ok() end;
canned(redirect) -> fun(_) -> {respond, 302, [{<<"location">>, <<"https://169.254.169.254/latest">>}], <<>>} end;
canned(declared_oversize) -> fun(_) -> {raw_then_hold, <<"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 1000000000\r\n\r\n">>} end;
canned(endless_chunked) -> fun(_) -> {stream_forever, binary:copy(<<"a">>, 1000)} end;
canned(close_delimited_oversize) -> fun(_) -> {raw, [<<"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\r\n">>, binary:copy(<<"b">>, 10000)]} end;
canned(chunked_ok) -> fun(_) -> {raw, <<"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ntransfer-encoding: chunked\r\n\r\n3\r\n{\"a\r\n4;x=y\r\n\":1}\r\n0\r\nx-trailer: t\r\n\r\n">>} end;
canned(interim) -> fun(_) -> {raw, <<"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok">>} end;
canned(slow) -> fun(_) -> {delay, 3000, json_ok()} end;
canned(many_headers) -> fun(_) -> {raw, [<<"HTTP/1.1 200 OK\r\n">>, [[<<"x-h">>, integer_to_list(N), <<": v\r\n">>] || N <- lists:seq(1, 200)], <<"content-length: 0\r\n\r\n">>]} end;
canned(big_header_line) -> fun(_) -> {raw, [<<"HTTP/1.1 200 OK\r\nx-big: ">>, binary:copy(<<"z">>, 40000), <<"\r\ncontent-length: 0\r\n\r\n">>]} end;
canned(gzip) -> fun(_) -> {respond, 200, [{<<"content-encoding">>, <<"gzip">>}], <<"xx">>} end;
canned(error_body) -> fun(_) -> {respond, 400, [{<<"content-type">>, <<"application/json">>}], <<"{\"error\":\"invalid_grant\",\"error_description\":\"SECRET-TEXT\"}">>} end;
canned(html_error) -> fun(_) -> {respond, 500, [{<<"content-type">>, <<"text/html">>}], <<"<html>SECRET</html>">>} end;
canned(bad_json) -> fun(_) -> {respond, 200, [{<<"content-type">>, <<"application/json">>}], <<"{\"access_token\":\"SECRET\"">>} end;
canned(truncated) -> fun(_) -> {raw, <<"HTTP/1.1 200 OK\r\ncontent-length: 100\r\n\r\nshort">>} end;
canned(bad_status) -> fun(_) -> {raw, <<"NOT HTTP\r\n\r\n">>} end.

%% Call an oidcc adapter term the way oidcc does; summarise the result.
adapter_request({Module, Config}, Url) ->
    case Module:request(get, {binary_to_list(Url), [{"accept", "application/json"}]}, [{timeout, 5000}], [{body_format, binary}], Config) of
        {ok, {{_, Status, _}, _Headers, Body}} -> {Status, Body};
        {error, {warden_transport, Stage, Class}} -> iolist_to_binary([atom_to_list(Stage), ":", atom_to_list(Class)])
    end.

%% A disposable P-256 private JWK (JSON) for private_key_jwt tests.
client_private_jwk() ->
    {_, Map} = jose_jwk:to_map(jose_jwk:generate_key({ec, <<"P-256">>})),
    iolist_to_binary(json:encode(Map#{<<"alg">> => <<"ES256">>, <<"kid">> => <<"disposable">>})).
