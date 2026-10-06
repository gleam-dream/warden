%% Actual refresh responses through pinned oidcc 3.9.0, produced by
%% node-oidc-provider 9.12.2 (scriptable). Raw oidcc, not Warden: this records
%% the backend behaviour Warden's refresh adapter must classify.
-module(node_refresh_probe_test).

-include_lib("eunit/include/eunit.hrl").
-include("../oidcc_records.hrl").

-define(ISSUER, <<"https://localhost:19443">>).
-define(CLIENT, <<"warden-rp">>).
-define(SECRET, <<"warden-node-disposable-secret-0123456789">>).
-define(REDIRECT, <<"https://localhost:1/callback">>).

adapter(Timeout) ->
    warden_test_support:test_adapter(Timeout).

opts() -> opts(10000).
opts(Timeout) -> #{preferred_auth_methods => [client_secret_basic], request_opts => #{http_adapter => adapter(Timeout)}}.

control(Path, Body) ->
    {ok, _} = application:ensure_all_started([inets, ssl]),
    Url = binary_to_list(<<?ISSUER/binary, "/__control/", Path/binary>>),
    Ssl = [{verify, verify_peer}, {cacerts, [warden_test_pki:ca_der(warden_test_server:pki_dir())]},
           {customize_hostname_check, [{match_fun, public_key:pkix_verify_hostname_match_fun(https)}]}],
    {ok, {{_, Status, _}, _, Resp}} = httpc:request(post, {Url, [], "application/json", json:encode(Body)}, [{ssl, Ssl}], [{body_format, binary}]),
    {Status, Resp}.

context() ->
    {ok, _} = application:ensure_all_started(oidcc),
    {ok, Pid} = oidcc_provider_configuration_worker:start_link(#{
        issuer => ?ISSUER,
        provider_configuration_opts => #{request_opts => #{http_adapter => adapter(10000)}},
        backoff_type => random_exponential
    }),
    wait(Pid, 100),
    {ok, Ctx} = oidcc_client_context:from_configuration_worker(Pid, ?CLIENT, ?SECRET),
    #oidcc_client_context{provider_configuration = C} = Ctx,
    {Pid, Ctx#oidcc_client_context{provider_configuration = C#oidcc_provider_configuration{
        pushed_authorization_request_endpoint = undefined, request_parameter_supported = false}}}.

wait(_, 0) -> error(provider_not_ready);
wait(Pid, N) ->
    case oidcc_provider_configuration_worker:get_jwks(Pid) of
        undefined -> timer:sleep(100), wait(Pid, N - 1);
        _ -> ok
    end.

rand() -> base64:encode(crypto:strong_rand_bytes(32), #{mode => urlsafe, padding => false}).

login(Ctx) ->
    Nonce = rand(), Verifier = rand(),
    {ok, Url} = oidcc_authorization:create_redirect_url(Ctx, (opts())#{
        redirect_uri => ?REDIRECT, state => rand(), nonce => Nonce, pkce_verifier => Verifier,
        require_pkce => true, scopes => [openid, <<"email">>, <<"profile">>]}),
    {{query, Query}, _} = warden_test_browser:authorize(warden_test_browser:new(), iolist_to_binary(Url), ?ISSUER),
    #{<<"code">> := Code} = maps:from_list(uri_string:dissect_query(Query)),
    {ok, Token} = oidcc_token:retrieve(Code, Ctx, (opts())#{
        redirect_uri => ?REDIRECT, nonce => Nonce, pkce_verifier => Verifier, require_pkce => true,
        trusted_audiences => [], validate_azp => client_id}),
    Token.

refresh(Ctx, Rt, Sub) -> refresh(Ctx, Rt, Sub, opts()).
refresh(Ctx, Rt, Sub, Opts) ->
    oidcc_token:refresh(Rt, Ctx, Opts#{expected_subject => Sub, trusted_audiences => []}).

probe_test_() ->
    {timeout, 120, fun probe/0}.

probe() ->
    {204, _} = control(<<"reset">>, #{}),
    {Pid, Ctx} = context(),
    #oidcc_token{refresh = #oidcc_token_refresh{token = Rt0}, id = #oidcc_token_id{claims = Claims0}} = login(Ctx),
    Sub = maps:get(<<"sub">>, Claims0),

    %% Present ID token: accepted; refresh token rotated.
    {ok, #oidcc_token{id = #oidcc_token_id{claims = C1}, refresh = #oidcc_token_refresh{token = Rt1}}} = refresh(Ctx, Rt0, Sub),
    ?assertNotEqual(Rt0, Rt1),
    io:format(user, "~nP3 refreshed claims: nonce=~p auth_time_same=~p~n",
        [maps:get(<<"nonce">>, C1, absent), maps:get(<<"auth_time">>, C1, a) =:= maps:get(<<"auth_time">>, Claims0, b)]),

    %% Absent ID token: pinned oidcc returns sub_invalid and discards a
    %% response in which the provider already rotated the refresh token.
    {204, _} = control(<<"next">>, #{grant => <<"refresh_token">>, omitIdToken => true}),
    ?assertEqual({error, sub_invalid}, refresh(Ctx, Rt1, Sub)),
    Lost = refresh(Ctx, Rt1, Sub),
    ?assertMatch({error, {http_error, 400, #{<<"error">> := <<"invalid_grant">>}}}, Lost),

    %% Omitted refresh token: oidcc reports refresh = none (retain is the
    %% caller's decision).
    #oidcc_token{refresh = #oidcc_token_refresh{token = Rt2}} = login(Ctx),
    {204, _} = control(<<"next">>, #{grant => <<"refresh_token">>, dropRefreshToken => true}),
    {ok, Retained} = refresh(Ctx, Rt2, Sub),
    ?assertMatch(#oidcc_token{refresh = none, id = #oidcc_token_id{}}, Retained),

    %% Changed subject: rejected by oidcc as sub_invalid.
    #oidcc_token{refresh = #oidcc_token_refresh{token = Rt3}} = login(Ctx),
    {204, _} = control(<<"next">>, #{grant => <<"refresh_token">>, idToken => <<"changed_sub">>}),
    ?assertEqual({error, sub_invalid}, refresh(Ctx, Rt3, Sub)),

    %% Changed nonce and auth_time: accepted by oidcc (refresh forces
    %% nonce => any); continuity is Warden's check.
    #oidcc_token{refresh = #oidcc_token_refresh{token = Rt4}} = login(Ctx),
    {204, _} = control(<<"next">>, #{grant => <<"refresh_token">>, idToken => <<"changed_nonce">>}),
    {ok, #oidcc_token{id = #oidcc_token_id{claims = C4}, refresh = #oidcc_token_refresh{token = Rt5}}} = refresh(Ctx, Rt4, Sub),
    ?assertEqual(<<"changed-nonce">>, maps:get(<<"nonce">>, C4)),
    {204, _} = control(<<"next">>, #{grant => <<"refresh_token">>, idToken => <<"changed_auth_time">>}),
    {ok, #oidcc_token{refresh = #oidcc_token_refresh{token = Rt6}}} = refresh(Ctx, Rt5, Sub),

    %% Response lost after the provider rotated: transport timeout after send,
    %% and the predecessor is no longer valid.
    {204, _} = control(<<"next">>, #{grant => <<"refresh_token">>, delayMs => 2500}),
    ?assertEqual({error, {warden_transport, sent, timeout}}, refresh(Ctx, Rt6, Sub, opts(800))),
    timer:sleep(2000),
    ?assertMatch({error, {http_error, 400, #{<<"error">> := <<"invalid_grant">>}}}, refresh(Ctx, Rt6, Sub)),

    %% Provider 5xx after processing.
    #oidcc_token{refresh = #oidcc_token_refresh{token = Rt7}} = login(Ctx),
    {204, _} = control(<<"next">>, #{grant => <<"refresh_token">>, status => 503}),
    ?assertMatch({error, {http_error, 503, _}}, refresh(Ctx, Rt7, Sub)),
    unlink(Pid),
    exit(Pid, shutdown).
