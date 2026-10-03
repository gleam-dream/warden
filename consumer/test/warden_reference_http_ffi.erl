%% One HTTPS request trusting a given PEM root, without following redirects:
%% the scripted browser that follows the reference app to the test provider.
-module(warden_reference_http_ffi).
-export([request/4]).

request(Method, Url, Body, CaPem) ->
    {ok, _} = application:ensure_all_started([inets, ssl]),
    CaCerts = [Der || {'Certificate', Der, not_encrypted} <- public_key:pem_decode(CaPem)],
    Options = [
        {autoredirect, false},
        {timeout, 10000},
        {ssl, [
            {verify, verify_peer},
            {cacerts, CaCerts},
            {customize_hostname_check, [{match_fun, public_key:pkix_verify_hostname_match_fun(https)}]}
        ]}
    ],
    Request = case Method of
        get -> {binary_to_list(Url), []};
        post -> {binary_to_list(Url), [], "application/x-www-form-urlencoded", Body}
    end,
    case httpc:request(Method, Request, Options, [{body_format, binary}]) of
        {ok, {{_, Status, _}, Headers, ResponseBody}} ->
            {ok, {Status, [{list_to_binary(K), list_to_binary(V)} || {K, V} <- Headers], ResponseBody}};
        {error, _} ->
            {error, nil}
    end.
