%% Probe P2 and V6 transport evidence: the owned oidcc HTTP adapter enforces
%% TLS verification, destination policy, redirects, deadlines and size bounds
%% at runtime against real local TLS servers.
-module(warden_http_test).

-include_lib("eunit/include/eunit.hrl").

cfg(Extra) ->
    maps:merge(
        #{
            cacerts => [warden_test_pki:ca_der(warden_test_server:pki_dir())],
            allow_loopback => true,
            timeout => 2000,
            max_body => 4096
        },
        Extra
    ).

get(Url, Cfg) ->
    warden_http:request(get, {Url, [{"accept", "application/json"}]}, [{timeout, 5000}], [{body_format, binary}], Cfg).

ok_handler(_) -> {respond, 200, [{<<"content-type">>, <<"application/json">>}], <<"{\"a\":1}">>}.

with_server(Cert, Handler, Fun) ->
    Server = warden_test_server:start(Cert, Handler),
    try
        Fun(Server)
    after
        warden_test_server:stop(Server)
    end.

verified_tls_succeeds_test() ->
    with_server("localhost", fun ok_handler/1, fun(S) ->
        {ok, {{_, 200, _}, Headers, Body}} = get(warden_test_server:url(S, "/x"), cfg(#{})),
        ?assertEqual(<<"{\"a\":1}">>, Body),
        ?assertMatch({"content-type", _}, lists:keyfind("content-type", 1, Headers))
    end).

loopback_rejected_by_default_before_connect_test() ->
    with_server("localhost", fun ok_handler/1, fun(S) ->
        Result = get(warden_test_server:url(S, "/x"), cfg(#{allow_loopback => false})),
        ?assertEqual({error, {warden_transport, not_sent, destination_rejected}}, Result),
        timer:sleep(50),
        ?assertEqual([], warden_test_server:requests(S))
    end).

wrong_host_certificate_rejected_test() ->
    with_server("wrong_host", fun ok_handler/1, fun(S) ->
        ?assertEqual(
            {error, {warden_transport, not_sent, tls_rejected}},
            get(warden_test_server:url(S, "/x"), cfg(#{}))
        )
    end).

untrusted_certificate_rejected_test() ->
    with_server("self_signed", fun ok_handler/1, fun(S) ->
        ?assertEqual(
            {error, {warden_transport, not_sent, tls_rejected}},
            get(warden_test_server:url(S, "/x"), cfg(#{}))
        )
    end).

expired_certificate_rejected_test() ->
    with_server("expired", fun ok_handler/1, fun(S) ->
        ?assertEqual(
            {error, {warden_transport, not_sent, tls_rejected}},
            get(warden_test_server:url(S, "/x"), cfg(#{}))
        )
    end).

system_trust_does_not_accept_test_ca_test() ->
    with_server("localhost", fun ok_handler/1, fun(S) ->
        ?assertEqual(
            {error, {warden_transport, not_sent, tls_rejected}},
            get(warden_test_server:url(S, "/x"), cfg(#{cacerts => system}))
        )
    end).

redirect_is_not_followed_test() ->
    Handler = fun(_) -> {respond, 302, [{<<"location">>, <<"https://169.254.169.254/latest">>}], <<>>} end,
    with_server("localhost", Handler, fun(S) ->
        {ok, {{_, 302, _}, _, <<>>}} = get(warden_test_server:url(S, "/x"), cfg(#{})),
        timer:sleep(50),
        ?assertEqual(1, length(warden_test_server:requests(S)))
    end).

declared_oversize_body_rejected_test() ->
    Handler = fun(_) ->
        {raw_then_hold, <<"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 1000000000\r\n\r\n">>}
    end,
    with_server("localhost", Handler, fun(S) ->
        ?assertEqual(
            {error, {warden_transport, sent, body_too_large}},
            get(warden_test_server:url(S, "/x"), cfg(#{}))
        )
    end).

endless_chunked_body_rejected_test() ->
    Handler = fun(_) -> {stream_forever, binary:copy(<<"a">>, 1000)} end,
    with_server("localhost", Handler, fun(S) ->
        ?assertEqual(
            {error, {warden_transport, sent, body_too_large}},
            get(warden_test_server:url(S, "/x"), cfg(#{}))
        )
    end).

close_delimited_oversize_rejected_test() ->
    Handler = fun(_) ->
        {raw, [<<"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\r\n">>, binary:copy(<<"b">>, 10000)]}
    end,
    with_server("localhost", Handler, fun(S) ->
        ?assertEqual(
            {error, {warden_transport, sent, body_too_large}},
            get(warden_test_server:url(S, "/x"), cfg(#{}))
        )
    end).

chunked_body_within_limit_decodes_test() ->
    Handler = fun(_) ->
        {raw, <<"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ntransfer-encoding: chunked\r\n\r\n3\r\n{\"a\r\n4;x=y\r\n\":1}\r\n0\r\nx-trailer: t\r\n\r\n">>}
    end,
    with_server("localhost", Handler, fun(S) ->
        {ok, {{_, 200, _}, _, Body}} = get(warden_test_server:url(S, "/x"), cfg(#{})),
        ?assertEqual(<<"{\"a\":1}">>, Body)
    end).

slow_response_times_out_after_send_test() ->
    Handler = fun(R) -> {delay, 3000, ok_handler(R)} end,
    with_server("localhost", Handler, fun(S) ->
        T0 = erlang:monotonic_time(millisecond),
        Result = get(warden_test_server:url(S, "/x"), cfg(#{timeout => 300})),
        Elapsed = erlang:monotonic_time(millisecond) - T0,
        ?assertEqual({error, {warden_transport, sent, timeout}}, Result),
        ?assert(Elapsed < 1500)
    end).

too_many_headers_rejected_test() ->
    Headers = [[<<"x-h">>, integer_to_list(N), <<": v\r\n">>] || N <- lists:seq(1, 200)],
    Handler = fun(_) -> {raw, [<<"HTTP/1.1 200 OK\r\n">>, Headers, <<"content-length: 0\r\n\r\n">>]} end,
    with_server("localhost", Handler, fun(S) ->
        ?assertEqual(
            {error, {warden_transport, sent, headers_too_large}},
            get(warden_test_server:url(S, "/x"), cfg(#{}))
        )
    end).

oversized_header_line_rejected_test() ->
    Handler = fun(_) ->
        {raw, [<<"HTTP/1.1 200 OK\r\nx-big: ">>, binary:copy(<<"z">>, 40000), <<"\r\ncontent-length: 0\r\n\r\n">>]}
    end,
    with_server("localhost", Handler, fun(S) ->
        {error, {warden_transport, sent, Class}} = get(warden_test_server:url(S, "/x"), cfg(#{})),
        ?assert(lists:member(Class, [headers_too_large, malformed_response]))
    end).

compressed_body_rejected_test() ->
    Handler = fun(_) -> {respond, 200, [{<<"content-encoding">>, <<"gzip">>}], <<"xx">>} end,
    with_server("localhost", Handler, fun(S) ->
        ?assertEqual(
            {error, {warden_transport, sent, unsupported_content_encoding}},
            get(warden_test_server:url(S, "/x"), cfg(#{}))
        )
    end).

plain_http_rejected_test() ->
    ?assertEqual(
        {error, {warden_transport, not_sent, insecure_scheme}},
        get(<<"http://localhost:1/x">>, cfg(#{}))
    ).

userinfo_in_url_rejected_test() ->
    ?assertEqual(
        {error, {warden_transport, not_sent, invalid_destination}},
        get(<<"https://user:pw@localhost:1/x">>, cfg(#{}))
    ).

connection_refused_is_not_sent_test() ->
    {ok, L} = gen_tcp:listen(0, [{ip, {127, 0, 0, 1}}]),
    {ok, Port} = inet:port(L),
    gen_tcp:close(L),
    Url = iolist_to_binary(["https://localhost:", integer_to_list(Port), "/x"]),
    ?assertEqual({error, {warden_transport, not_sent, connection_refused}}, get(Url, cfg(#{}))).

header_injection_rejected_before_send_test() ->
    with_server("localhost", fun ok_handler/1, fun(S) ->
        Result = warden_http:request(
            get,
            {warden_test_server:url(S, "/x"), [{"x-evil", "a\r\nhost: other"}]},
            [],
            [],
            cfg(#{})
        ),
        ?assertEqual({error, {warden_transport, not_sent, invalid_request}}, Result)
    end).

private_resolution_rejected_test() ->
    Resolver = fun(_Host, _T) -> {ok, [{10, 0, 0, 7}]} end,
    ?assertEqual(
        {error, {warden_transport, not_sent, destination_rejected}},
        get(<<"https://idp.example/x">>, cfg(#{resolver => Resolver, allow_loopback => false}))
    ).

mixed_resolution_rejected_test() ->
    Resolver = fun(_Host, _T) -> {ok, [{93, 184, 216, 34}, {169, 254, 169, 254}]} end,
    ?assertEqual(
        {error, {warden_transport, not_sent, destination_rejected}},
        get(<<"https://idp.example/x">>, cfg(#{resolver => Resolver, allow_loopback => false}))
    ).

%% The destination is resolved exactly once and the connection uses an address
%% from that answer, so a rebinding resolver cannot change it after the check.
resolution_happens_once_test() ->
    Counter = counters:new(1, []),
    with_server("localhost", fun ok_handler/1, fun(S) ->
        Resolver = fun(_Host, _T) ->
            counters:add(Counter, 1, 1),
            case counters:get(Counter, 1) of
                1 -> {ok, [{127, 0, 0, 1}]};
                _ -> {ok, [{10, 0, 0, 1}]}
            end
        end,
        {ok, {{_, 200, _}, _, _}} = get(warden_test_server:url(S, "/x"), cfg(#{resolver => Resolver})),
        ?assertEqual(1, counters:get(Counter, 1))
    end).

allowed_hosts_enforced_test() ->
    ?assertEqual(
        {error, {warden_transport, not_sent, destination_rejected}},
        get(<<"https://evil.example/x">>, cfg(#{allowed_hosts => [<<"idp.example">>]}))
    ).

classify_address_test() ->
    Cases = [
        {{8, 8, 8, 8}, public},
        {{127, 0, 0, 1}, loopback},
        {{10, 1, 2, 3}, private},
        {{172, 16, 0, 1}, private},
        {{172, 32, 0, 1}, public},
        {{192, 168, 1, 1}, private},
        {{169, 254, 169, 254}, reserved},
        {{100, 64, 0, 1}, private},
        {{0, 0, 0, 0}, reserved},
        {{224, 0, 0, 1}, reserved},
        {{255, 255, 255, 255}, reserved},
        {{0, 0, 0, 0, 0, 0, 0, 1}, loopback},
        {{0, 0, 0, 0, 0, 16#ffff, 16#a9fe, 16#a9fe}, reserved},
        {{0, 0, 0, 0, 0, 16#ffff, 16#7f00, 1}, loopback},
        {{16#fd00, 0, 0, 0, 0, 0, 0, 1}, private},
        {{16#fe80, 0, 0, 0, 0, 0, 0, 1}, reserved},
        {{16#2606, 16#4700, 0, 0, 0, 0, 0, 1}, public},
        {{16#64, 16#ff9b, 0, 0, 0, 0, 16#0a00, 1}, private}
    ],
    [?assertEqual({A, Expected}, {A, warden_http:classify_address(A)}) || {A, Expected} <- Cases].

%% oidcc routes discovery through the configured adapter and passes the
%% adapter's error term through unchanged.
oidcc_discovery_uses_adapter_test() ->
    Self = self(),
    Handler = fun(#{path := Path}) ->
        Self ! {path, Path},
        {respond, 500, [], <<>>}
    end,
    with_server("localhost", Handler, fun(S) ->
        Issuer = warden_test_server:url(S, ""),
        Denied = oidcc_provider_configuration:load_configuration(Issuer, #{
            request_opts => #{http_adapter => {warden_http, cfg(#{allow_loopback => false})}}
        }),
        ?assertEqual({error, {warden_transport, not_sent, destination_rejected}}, Denied),
        Allowed = oidcc_provider_configuration:load_configuration(Issuer, #{
            request_opts => #{http_adapter => {warden_http, cfg(#{})}}
        }),
        ?assertMatch({error, {http_error, 500, _}}, Allowed),
        receive
            {path, P} -> ?assertEqual(<<"/.well-known/openid-configuration">>, P)
        after 1000 -> error(no_request)
        end
    end).

error_bodies_are_reduced_to_the_oauth_error_code_test() ->
    Handler = fun(_) ->
        {respond, 400, [{<<"content-type">>, <<"application/json">>}],
            <<"{\"error\":\"invalid_grant\",\"error_description\":\"SECRET-TEXT\",\"extra\":\"x\"}">>}
    end,
    with_server("localhost", Handler, fun(S) ->
        {ok, {{_, 400, _}, _, Body}} = get(warden_test_server:url(S, "/x"), cfg(#{})),
        ?assertEqual(#{<<"error">> => <<"invalid_grant">>}, json:decode(Body))
    end).

non_oauth_error_bodies_are_dropped_test() ->
    Handler = fun(_) -> {respond, 500, [{<<"content-type">>, <<"text/html">>}], <<"<html>SECRET</html>">>} end,
    with_server("localhost", Handler, fun(S) ->
        ?assertMatch({ok, {{_, 500, _}, _, <<>>}}, get(warden_test_server:url(S, "/x"), cfg(#{})))
    end).

invalid_json_success_is_malformed_test() ->
    Handler = fun(_) -> {respond, 200, [{<<"content-type">>, <<"application/json">>}], <<"{\"access_token\":\"SECRET\"">>} end,
    with_server("localhost", Handler, fun(S) ->
        ?assertEqual({error, {warden_transport, sent, malformed_response}}, get(warden_test_server:url(S, "/x"), cfg(#{})))
    end).
