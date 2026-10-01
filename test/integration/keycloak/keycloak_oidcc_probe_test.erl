%% Probe P1: exact oidcc 3.9.0 calls, options and return shapes against the
%% pinned Keycloak, through Warden's transport adapter. This module calls raw
%% oidcc (not Warden) to record upstream behaviour; each assertion documents
%% one observed fact that Warden's boundary relies on.
-module(keycloak_oidcc_probe_test).

-include_lib("eunit/include/eunit.hrl").
-include_lib("oidcc/include/oidcc_provider_configuration.hrl").
-include_lib("oidcc/include/oidcc_client_context.hrl").
-include_lib("oidcc/include/oidcc_token.hrl").

-define(ISSUER, <<"https://localhost:18443/realms/warden">>).
-define(CLIENT, <<"warden-rp">>).
-define(SECRET, <<"warden-rp-disposable-secret">>).
-define(REDIRECT, <<"https://localhost:1/callback">>).

adapter() ->
    {warden_http, #{
        cacerts => [warden_test_pki:ca_der(warden_test_server:pki_dir())],
        allow_loopback => true,
        timeout => 10000
    }}.

request_opts() -> #{http_adapter => adapter()}.

auth() -> #{preferred_auth_methods => [client_secret_basic], request_opts => request_opts()}.

worker() ->
    {ok, _} = application:ensure_all_started(oidcc),
    {ok, Pid} = oidcc_provider_configuration_worker:start_link(#{
        issuer => ?ISSUER,
        provider_configuration_opts => #{request_opts => request_opts()},
        backoff_type => random_exponential
    }),
    wait_ready(Pid, 100),
    Pid.

wait_ready(Pid, 0) -> error({provider_not_ready, Pid});
wait_ready(Pid, N) ->
    case {oidcc_provider_configuration_worker:get_provider_configuration(Pid), oidcc_provider_configuration_worker:get_jwks(Pid)} of
        {#oidcc_provider_configuration{}, J} when J =/= undefined -> ok;
        _ -> timer:sleep(100), wait_ready(Pid, N - 1)
    end.

context(Pid) ->
    {ok, Ctx} = oidcc_client_context:from_configuration_worker(Pid, ?CLIENT, ?SECRET),
    Ctx.

%% Remove automatic PAR and request objects so the authorization request is a
%% plain query built from Warden's own parameters.
narrow(#oidcc_client_context{provider_configuration = C} = Ctx) ->
    Ctx#oidcc_client_context{
        provider_configuration = C#oidcc_provider_configuration{
            pushed_authorization_request_endpoint = undefined,
            request_parameter_supported = false
        }
    }.

verifier() -> base64:encode(crypto:strong_rand_bytes(32), #{mode => urlsafe, padding => false}).

auth_url(Ctx, Extra) ->
    Opts = maps:merge(
        #{
            redirect_uri => ?REDIRECT,
            state => <<"state-", (verifier())/binary>>,
            nonce => <<"nonce-", (verifier())/binary>>,
            pkce_verifier => verifier(),
            require_pkce => true,
            scopes => [openid, <<"profile">>, <<"email">>],
            request_opts => request_opts(),
            preferred_auth_methods => [client_secret_basic]
        },
        Extra
    ),
    {ok, Url} = oidcc_authorization:create_redirect_url(Ctx, Opts),
    {iolist_to_binary(Url), Opts}.

login(Ctx, Extra) ->
    {Url, Opts} = auth_url(Ctx, Extra),
    {{query, Query}, _} = warden_test_browser:login(warden_test_browser:new(), Url, "alice", "alice-disposable"),
    Params = maps:from_list(uri_string:dissect_query(Query)),
    {Params, Opts}.

retrieve(Ctx, Code, Opts, Extra) ->
    oidcc_token:retrieve(
        Code,
        Ctx,
        maps:merge(
            #{
                redirect_uri => maps:get(redirect_uri, Opts),
                nonce => maps:get(nonce, Opts),
                pkce_verifier => maps:get(pkce_verifier, Opts),
                require_pkce => true,
                trusted_audiences => [],
                validate_azp => client_id,
                preferred_auth_methods => [client_secret_basic],
                request_opts => request_opts()
            },
            Extra
        )
    ).

probe_test_() ->
    {timeout, 120, fun probe/0}.

probe() ->
    Pid = worker(),
    Ctx = context(Pid),
    Config = Ctx#oidcc_client_context.provider_configuration,

    %% Keycloak advertises PAR; raw create_redirect_url pushes the request.
    ?assertNotEqual(undefined, Config#oidcc_provider_configuration.pushed_authorization_request_endpoint),
    {RawUrl, _} = auth_url(Ctx, #{}),
    RawQuery = maps:from_list(uri_string:dissect_query(lists:last(binary:split(RawUrl, <<"?">>)))),
    ?assert(maps:is_key(<<"request_uri">>, RawQuery)),
    ?assertNot(maps:is_key(<<"code_challenge">>, RawQuery)),

    %% Narrowed context yields a plain S256 authorization request.
    Narrow = narrow(Ctx),
    {PlainUrl, PlainOpts} = auth_url(Narrow, #{}),
    PlainQuery = maps:from_list(uri_string:dissect_query(lists:last(binary:split(PlainUrl, <<"?">>)))),
    Expected = base64:encode(crypto:hash(sha256, maps:get(pkce_verifier, PlainOpts)), #{mode => urlsafe, padding => false}),
    ?assertEqual(<<"S256">>, maps:get(<<"code_challenge_method">>, PlainQuery)),
    ?assertEqual(Expected, maps:get(<<"code_challenge">>, PlainQuery)),
    ?assertEqual(maps:get(state, PlainOpts), maps:get(<<"state">>, PlainQuery)),
    ?assertEqual(<<"openid profile email">>, maps:get(<<"scope">>, PlainQuery)),

    %% A real login returns code, state and RFC 9207 iss in the query.
    {Params, Opts} = login(Narrow, #{}),
    ?assertEqual(?ISSUER, maps:get(<<"iss">>, Params)),
    ?assertEqual(maps:get(state, Opts), maps:get(<<"state">>, Params)),
    Code = maps:get(<<"code">>, Params),
    {ok, Token} = retrieve(Narrow, Code, Opts, #{}),
    #oidcc_token{id = #oidcc_token_id{claims = Claims}, access = #oidcc_token_access{type = Type, expires = Expires}, refresh = Refresh, scope = Scope} = Token,
    ?assertEqual(?ISSUER, maps:get(<<"iss">>, Claims)),
    ?assertEqual(?CLIENT, maps:get(<<"aud">>, Claims)),
    ?assertEqual(maps:get(nonce, Opts), maps:get(<<"nonce">>, Claims)),
    ?assert(is_integer(Expires)),
    ?assertEqual(<<"Bearer">>, Type),
    ?assertMatch(#oidcc_token_refresh{}, Refresh),
    ?assert(lists:member(<<"openid">>, Scope)),
    io:format(user, "~nP1 id claims keys: ~p~nP1 scope: ~p~n", [lists:sort(maps:keys(Claims)), Scope]),


    %% Wrong nonce: validation fails after the code has been consumed.
    {P2, O2} = login(Narrow, #{}),
    WrongNonce = retrieve(Narrow, maps:get(<<"code">>, P2), O2, #{nonce => <<"other">>}),
    ?assertMatch({error, {missing_claim, {<<"nonce">>, <<"other">>}, _}}, WrongNonce),
    {error, {missing_claim, _, LeakedClaims}} = WrongNonce,
    ?assert(is_map(LeakedClaims)),

    %% Wrong verifier: provider rejection.
    {P3, O3} = login(Narrow, #{}),
    BadVerifier = retrieve(Narrow, maps:get(<<"code">>, P3), O3, #{pkce_verifier => verifier()}),
    ?assertMatch({error, {http_error, 400, #{<<"error">> := <<"invalid_grant">>}}}, BadVerifier),

    %% Wrong redirect URI: provider rejection.
    {P4, O4} = login(Narrow, #{}),
    BadRedirect = retrieve(Narrow, maps:get(<<"code">>, P4), O4, #{redirect_uri => <<"https://localhost:2/other">>}),
    ?assertMatch({error, {http_error, 400, #{<<"error">> := _}}}, BadRedirect),

    %% Refresh with the returned token: Keycloak returns an ID token and a
    %% rotated refresh token; the predecessor is then rejected.
    #oidcc_token_refresh{token = Rt1} = Refresh,
    Sub = maps:get(<<"sub">>, Claims),
    {ok, R1} = oidcc_token:refresh(Rt1, Narrow, (auth())#{expected_subject => Sub, trusted_audiences => []}),
    #oidcc_token{id = Id1, refresh = #oidcc_token_refresh{token = Rt2}} = R1,
    ?assertMatch(#oidcc_token_id{}, Id1),
    ?assertNotEqual(Rt1, Rt2),
    #oidcc_token_id{claims = RClaims} = Id1,
    io:format(user, "P1 refresh id claims: nonce=~p auth_time_equal=~p~n", [maps:get(<<"nonce">>, RClaims, absent), maps:get(<<"auth_time">>, RClaims, x) =:= maps:get(<<"auth_time">>, Claims, y)]),
    Stale = oidcc_token:refresh(Rt1, Narrow, (auth())#{expected_subject => Sub}),
    ?assertMatch({error, {http_error, 400, #{<<"error">> := <<"invalid_grant">>}}}, Stale),

    %% Code replay: the provider rejects the second exchange and revokes the
    %% tokens already issued for that code (RFC 6749 section 4.1.2).
    {P5, O5} = login(Narrow, #{}),
    Code5 = maps:get(<<"code">>, P5),
    {ok, #oidcc_token{refresh = #oidcc_token_refresh{token = Rt5}, id = #oidcc_token_id{claims = #{<<"sub">> := Sub5}}}} = retrieve(Narrow, Code5, O5, #{}),
    Replay = retrieve(Narrow, Code5, O5, #{}),
    ?assertMatch({error, {http_error, 400, #{<<"error">> := <<"invalid_grant">>}}}, Replay),
    Revoked = oidcc_token:refresh(Rt5, Narrow, (auth())#{expected_subject => Sub5}),
    ?assertMatch({error, {http_error, 400, #{<<"error">> := <<"invalid_grant">>}}}, Revoked),

    %% Transport failure shape passes through oidcc unchanged.
    Blocked = oidcc_token:refresh(Rt2, Narrow, #{expected_subject => Sub, preferred_auth_methods => [client_secret_basic], request_opts => #{http_adapter => {warden_http, #{allow_loopback => false}}}}),
    ?assertEqual({error, {warden_transport, not_sent, destination_rejected}}, Blocked),

    %% Refresh-token reuse detection revoked the session: its access token is
    %% no longer accepted at userinfo.
    #oidcc_token{access = #oidcc_token_access{token = RevokedAt}} = R1,
    ?assertMatch({error, {http_error, 401, _}}, oidcc_userinfo:retrieve(RevokedAt, Narrow, #{expected_subject => Sub, request_opts => request_opts()})),

    %% Userinfo requires the expected subject and returns a claims map.
    {P6, O6} = login(Narrow, #{}),
    {ok, #oidcc_token{access = #oidcc_token_access{token = At}, id = Id6}} = retrieve(Narrow, maps:get(<<"code">>, P6), O6, #{}),
    {ok, Info} = oidcc_userinfo:retrieve(At, Narrow, #{expected_subject => Sub, request_opts => request_opts()}),
    ?assertEqual(Sub, maps:get(<<"sub">>, Info)),
    WrongSub = oidcc_userinfo:retrieve(At, Narrow, #{expected_subject => <<"someone-else">>, request_opts => request_opts()}),
    io:format(user, "P1 userinfo wrong subject: ~p~n", [WrongSub]),
    ?assertMatch({error, bad_subject}, WrongSub),

    %% Introspection: with the default client_self_only an inactive response
    %% (no client_id) is reported as client_id_mismatch, conflating an
    %% inactive token with an error. client_self_only => false keeps them apart.
    io:format(user, "P1 raw introspection: ~p~n", [oidcc_token_introspection:introspect(At, Narrow, (auth())#{client_self_only => false})]),
    {ok, Active} = oidcc_token_introspection:introspect(At, Narrow, auth()),
    ?assertEqual(true, element(2, Active)),
    io:format(user, "P1 introspection active client_id: ~p~n", [element(3, Active)]),
    ?assertEqual({error, client_id_mismatch}, oidcc_token_introspection:introspect(<<"not-a-token">>, Narrow, auth())),
    {ok, Inactive} = oidcc_token_introspection:introspect(<<"not-a-token">>, Narrow, (auth())#{client_self_only => false}),
    ?assertEqual(false, element(2, Inactive)),

    %% Client credentials returns an access token without an ID token.
    {ok, Cc} = oidcc_token:client_credentials(Narrow, (auth())#{scope => [<<"profile">>]}),
    ?assertMatch(#oidcc_token{id = none, access = #oidcc_token_access{}}, Cc),

    %% P3 (Keycloak): narrowing scope away from openid on refresh still returns
    %% an ID token, so Keycloak cannot produce the absent-ID-token case; the
    %% node-oidc-provider suite reproduces it.
    {P7, O7} = login(Narrow, #{}),
    {ok, #oidcc_token{refresh = #oidcc_token_refresh{token = Rt7}, id = #oidcc_token_id{claims = #{<<"sub">> := Sub7}}}} = retrieve(Narrow, maps:get(<<"code">>, P7), O7, #{}),
    {ok, Narrowed} = oidcc_token:refresh(Rt7, Narrow, (auth())#{expected_subject => Sub7, scope => [<<"profile">>]}),
    ?assertMatch(#oidcc_token{id = #oidcc_token_id{}}, Narrowed),

    %% RP-initiated logout URL.
    #oidcc_token_id{token = IdToken} = Id6,
    {ok, LogoutUrl} = oidcc_logout:initiate_url(IdToken, Narrow, #{post_logout_redirect_uri => ?REDIRECT, state => <<"s">>}),
    ?assertMatch({_, _}, binary:match(iolist_to_binary(LogoutUrl), <<"id_token_hint=">>)),
    unlink(Pid),
    exit(Pid, shutdown).
