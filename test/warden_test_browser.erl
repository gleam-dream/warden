%% Minimal headless browser for Keycloak's login form, used only by tests.
%%
%% It follows the authorization URL, submits the username/password form with
%% the cookies Keycloak set, and returns the provider's response to the
%% client's redirect URI without contacting that URI:
%%
%%   {query, QueryString}       - 302 to the redirect URI
%%   {form_post, FormBody}      - auto-submitting form_post page
%%   {error, Reason}
%%
%% Browser state (cookies) lives in a map so tests can reuse a session for
%% SSO or simulate separate browsers.
-module(warden_test_browser).

-export([new/0, login/4, get/2, visit/2, authorize/3]).

new() -> #{cookies => #{}}.

http_opts() ->
    Ca = warden_test_pki:ca_der(warden_test_server:pki_dir()),
    [
        {autoredirect, false},
        {timeout, 15000},
        {ssl, [
            {verify, verify_peer},
            {cacerts, [Ca]},
            {customize_hostname_check, [{match_fun, public_key:pkix_verify_hostname_match_fun(https)}]}
        ]}
    ].

%% Complete a Keycloak login. Returns {Result, Browser}.
login(Browser0, AuthorizationUrl, Username, Password) ->
    {ok, _} = application:ensure_all_started([inets, ssl]),
    case get(Browser0, AuthorizationUrl) of
        {{200, _Headers, Html}, Browser1} ->
            case form_action(Html) of
                {ok, Action} ->
                    Body = uri_string:compose_query([{"username", Username}, {"password", Password}, {"credentialId", ""}]),
                    handle_final(post(Browser1, Action, Body), Username);
                error ->
                    {{error, no_login_form}, Browser1}
            end;
        Other ->
            %% SSO: an existing session redirects immediately.
            handle_final(Other, Username)
    end.

visit(Browser, Url) -> get(Browser, Url).

%% Follow provider redirects (headless node-oidc-provider interactions) until
%% the provider answers towards the client: a redirect outside ProviderPrefix
%% or a form_post page. Returns {Result, Browser} like login/4.
authorize(Browser, Url, ProviderPrefix) ->
    {ok, _} = application:ensure_all_started([inets, ssl]),
    follow(get(Browser, Url), Url, ProviderPrefix, 10).

follow({{Status, Headers, _Html}, Browser} = Response, Base, Prefix, N) when Status >= 300, Status < 400, N > 0 ->
    Location = uri_string:resolve(proplists:get_value("location", Headers), to_list(Base)),
    case lists:prefix(to_list(Prefix), Location) of
        true -> follow(get(Browser, Location), Location, Prefix, N - 1);
        false -> handle_final(Response, none)
    end;
follow(Response, _Base, _Prefix, _N) ->
    handle_final(Response, none).

handle_final({{Status, Headers, Html}, Browser}, _Username) ->
    case Status of
        S when S >= 300, S < 400 ->
            Location = proplists:get_value("location", Headers),
            case uri_string:parse(Location) of
                #{query := Query} -> {{query, list_to_binary(Query)}, Browser};
                _ -> {{error, {redirect_without_query, Location}}, Browser}
            end;
        200 ->
            case hidden_inputs(Html) of
                [] -> {{error, {unexpected_page, Status}}, Browser};
                Inputs -> {{form_post, list_to_binary(uri_string:compose_query(Inputs))}, Browser}
            end;
        _ ->
            {{error, {status, Status}}, Browser}
    end.

get(Browser, Url) ->
    request(Browser, get, {to_list(Url), cookie_header(Browser)}).

post(Browser, Url, Body) ->
    request(Browser, post, {to_list(Url), cookie_header(Browser), "application/x-www-form-urlencoded", Body}).

request(Browser, Method, Req) ->
    {ok, {{_, Status, _}, Headers, Body}} = httpc:request(Method, Req, http_opts(), [{body_format, binary}]),
    {{Status, Headers, Body}, store_cookies(Browser, Headers)}.

cookie_header(#{cookies := Cookies}) ->
    case maps:to_list(Cookies) of
        [] -> [];
        List -> [{"cookie", string:join([K ++ "=" ++ V || {K, V} <- List], "; ")}]
    end.

store_cookies(#{cookies := Cookies} = Browser, Headers) ->
    New = lists:foldl(
        fun
            ({"set-cookie", Value}, Acc) ->
                [Pair | _] = string:split(Value, ";"),
                case string:split(Pair, "=") of
                    [K, V] -> Acc#{string:trim(K) => V};
                    _ -> Acc
                end;
            (_, Acc) ->
                Acc
        end,
        Cookies,
        Headers
    ),
    Browser#{cookies := New}.

form_action(Html) ->
    case re:run(Html, <<"<form[^>]*id=\"kc-form-login\"[^>]*action=\"([^\"]+)\"">>, [{capture, all_but_first, binary}]) of
        {match, [Action]} -> {ok, unescape(Action)};
        nomatch -> error
    end.

hidden_inputs(Html) ->
    case re:run(Html, <<"<input type=\"hidden\" name=\"([^\"]+)\" value=\"([^\"]*)\"">>, [global, caseless, {capture, all_but_first, binary}]) of
        {match, Matches} -> [{binary_to_list(N), binary_to_list(unescape(V))} || [N, V] <- Matches];
        nomatch -> []
    end.

unescape(Bin) ->
    lists:foldl(
        fun({From, To}, Acc) -> binary:replace(Acc, From, To, [global]) end,
        Bin,
        [{<<"&amp;">>, <<"&">>}, {<<"&#x3d;">>, <<"=">>}, {<<"&#61;">>, <<"=">>}, {<<"&quot;">>, <<"\"">>}, {<<"&#x2f;">>, <<"/">>}, {<<"&#43;">>, <<"+">>}, {<<"&#x2b;">>, <<"+">>}]
    ).

to_list(B) when is_binary(B) -> binary_to_list(B);
to_list(L) when is_list(L) -> binary_to_list(iolist_to_binary(L)).
