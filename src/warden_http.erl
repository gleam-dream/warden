%% Warden-owned bounded HTTPS transport for oidcc.
%%
%% This module implements the `oidcc_http_adapter` behaviour of oidcc 3.9.0.
%% oidcc keeps protocol work (request construction, JSON decoding, error
%% normalisation); this adapter owns the transport decisions that oidcc
%% leaves to adapters:
%%
%% - HTTPS only, with peer verification, hostname checking and an explicit
%%   trust store. Verification cannot be disabled.
%% - DNS is resolved once; every resolved address must pass the destination
%%   policy, and the connection goes to an address from that same answer, so a
%%   second resolution cannot rebind the destination.
%% - Redirects are never followed; a 3xx response is returned as a response.
%% - Header count, header bytes and body bytes are bounded while reading.
%%   A declared Content-Length above the limit is rejected before reading.
%% - One deadline covers resolution, connection, send and receive.
%% - Failures carry transmission evidence: `not_sent` is returned only when no
%%   request byte can have reached the peer; everything else is `sent`.
%%
%% Errors have the closed shape `{error, {warden_transport, not_sent | sent,
%% Class :: atom()}}` and never contain request or response content.
-module(warden_http).

-feature(maybe_expr, enable).

-behaviour(oidcc_http_adapter).

-export([request/5]).
-export([classify_address/1, default_config/0]).

-define(DEFAULT_TIMEOUT, 10000).
-define(DEFAULT_MAX_BODY, 1048576).
-define(DEFAULT_MAX_HEADERS, 100).
-define(DEFAULT_MAX_HEADER_BYTES, 16384).
-define(MAX_CHUNK_LINE, 1024).
-define(MAX_INTERIM, 5).

default_config() ->
    #{
        cacerts => system,
        allow_loopback => false,
        allow_private => false,
        allowed_hosts => any,
        timeout => ?DEFAULT_TIMEOUT,
        max_body => ?DEFAULT_MAX_BODY,
        max_headers => ?DEFAULT_MAX_HEADERS,
        max_header_bytes => ?DEFAULT_MAX_HEADER_BYTES
    }.

request(Method, Request, HttpOptions, _RequestOptions, Config0) ->
    Config = maps:merge(default_config(), Config0),
    Timeout = min(
        proplists:get_value(timeout, HttpOptions, ?DEFAULT_TIMEOUT),
        maps:get(timeout, Config)
    ),
    Deadline = now_ms() + Timeout,
    Start = erlang:monotonic_time(),
    Result =
        try
            run(Method, Request, Deadline, Config)
        catch
            _:_ -> {error, {warden_transport, sent, internal_error}}
        end,
    observe(Method, Request, Result, Start),
    Result.

run(Method, Request, Deadline, Config) ->
    maybe
        {ok, Url, Headers, Body} ?= split_request(Request),
        {ok, Target} ?= parse_target(Url),
        ok ?= check_host_allowed(Target, Config),
        {ok, Address} ?= resolve(Target, Deadline, Config),
        {ok, Bytes} ?= encode_request(Method, Target, Headers, Body),
        {ok, Socket} ?= connect(Address, Target, Deadline, Config),
        exchange(Socket, Method, Bytes, Deadline, Config)
    end.

%% ---------------------------------------------------------------------------
%% Request shape

split_request({Url, Headers}) ->
    {ok, Url, Headers, none};
split_request({Url, Headers, ContentType, Body}) when
    is_binary(Body) orelse is_list(Body)
->
    {ok, Url, [{"content-type", ContentType} | Headers], Body};
split_request(_) ->
    not_sent(invalid_request).

parse_target(Url0) ->
    try unicode:characters_to_binary(Url0) of
        Url when is_binary(Url) ->
            case uri_string:parse(Url) of
                #{scheme := Scheme, host := Host} = Parts when Host =/= <<>> ->
                    case string:lowercase(Scheme) of
                        <<"https">> ->
                            case maps:is_key(userinfo, Parts) orelse maps:is_key(fragment, Parts) of
                                true ->
                                    not_sent(invalid_destination);
                                false ->
                                    Path =
                                        case maps:get(path, Parts, <<>>) of
                                            <<>> -> <<"/">>;
                                            P -> P
                                        end,
                                    RequestTarget =
                                        case maps:get(query, Parts, undefined) of
                                            undefined -> Path;
                                            Q -> <<Path/binary, "?", Q/binary>>
                                        end,
                                    Port = maps:get(port, Parts, 443),
                                    valid_port(Port, #{
                                        host => string:lowercase(Host),
                                        port => Port,
                                        path => Path,
                                        target => RequestTarget
                                    });
                                _ ->
                                    not_sent(invalid_destination)
                            end;
                        _ ->
                            not_sent(insecure_scheme)
                    end;
                _ ->
                    not_sent(invalid_destination)
            end;
        _ ->
            not_sent(invalid_destination)
    catch
        _:_ -> not_sent(invalid_destination)
    end.

valid_port(Port, Target) when is_integer(Port), Port > 0, Port < 65536 -> {ok, Target};
valid_port(_, _) -> not_sent(invalid_destination).

check_host_allowed(_Target, #{allowed_hosts := any}) ->
    ok;
check_host_allowed(#{host := Host}, #{allowed_hosts := Hosts}) when is_list(Hosts) ->
    case lists:member(Host, [string:lowercase(H) || H <- Hosts]) of
        true -> ok;
        false -> not_sent(destination_rejected)
    end.

%% ---------------------------------------------------------------------------
%% Destination policy

resolve(#{host := Host}, Deadline, Config) ->
    HostString = binary_to_list(Host),
    Addresses =
        case inet:parse_strict_address(strip_brackets(HostString)) of
            {ok, Literal} ->
                {ok, [Literal]};
            {error, _} ->
                lookup(HostString, Deadline, Config)
        end,
    case Addresses of
        {ok, []} ->
            not_sent(resolution_failed);
        {ok, List} ->
            case lists:all(fun(A) -> address_allowed(A, Config) end, List) of
                true -> {ok, hd(List)};
                false -> not_sent(destination_rejected)
            end;
        {error, _} ->
            not_sent(resolution_failed)
    end.

strip_brackets([$[ | Rest]) -> lists:droplast(Rest);
strip_brackets(Host) -> Host.

lookup(Host, Deadline, #{resolver := Resolver}) when is_function(Resolver, 2) ->
    try Resolver(Host, remaining(Deadline)) of
        {ok, List} when is_list(List) -> {ok, List};
        _ -> {error, resolution_failed}
    catch
        _:_ -> {error, resolution_failed}
    end;
lookup(Host, Deadline, _Config) ->
    V4 =
        case inet:getaddrs(Host, inet, remaining(Deadline)) of
            {ok, A4} -> A4;
            {error, _} -> []
        end,
    V6 =
        case inet:getaddrs(Host, inet6, remaining(Deadline)) of
            {ok, A6} -> A6;
            {error, _} -> []
        end,
    {ok, V4 ++ V6}.

address_allowed(Address, Config) ->
    case classify_address(Address) of
        public -> true;
        loopback -> maps:get(allow_loopback, Config);
        private -> maps:get(allow_private, Config);
        _ -> false
    end.

%% Classify an address as `public`, `loopback`, `private` (RFC 1918, unique
%% local, shared/CGNAT) or `reserved` (never a valid provider destination).
classify_address({0, _, _, _}) -> reserved;
classify_address({10, _, _, _}) -> private;
classify_address({100, B, _, _}) when B >= 64, B =< 127 -> private;
classify_address({127, _, _, _}) -> loopback;
classify_address({169, 254, _, _}) -> reserved;
classify_address({172, B, _, _}) when B >= 16, B =< 31 -> private;
classify_address({192, 0, 0, _}) -> reserved;
classify_address({192, 0, 2, _}) -> reserved;
classify_address({192, 88, 99, _}) -> reserved;
classify_address({192, 168, _, _}) -> private;
classify_address({198, B, _, _}) when B =:= 18; B =:= 19 -> reserved;
classify_address({198, 51, 100, _}) -> reserved;
classify_address({203, 0, 113, _}) -> reserved;
classify_address({A, _, _, _}) when A >= 224 -> reserved;
classify_address({A, B, C, D} = V4) when
    is_integer(A), is_integer(B), is_integer(C), is_integer(D)
->
    case lists:all(fun(X) -> X >= 0 andalso X =< 255 end, tuple_to_list(V4)) of
        true -> public;
        false -> reserved
    end;
classify_address({0, 0, 0, 0, 0, 0, 0, 0}) -> reserved;
classify_address({0, 0, 0, 0, 0, 0, 0, 1}) -> loopback;
classify_address({0, 0, 0, 0, 0, 16#ffff, Hi, Lo}) -> classify_embedded(Hi, Lo);
classify_address({16#64, 16#ff9b, 0, 0, 0, 0, Hi, Lo}) -> classify_embedded(Hi, Lo);
classify_address({16#100, 0, 0, 0, _, _, _, _}) -> reserved;
classify_address({16#2001, 16#db8, _, _, _, _, _, _}) -> reserved;
classify_address({16#2002, _, _, _, _, _, _, _}) -> reserved;
classify_address({A, _, _, _, _, _, _, _}) when A band 16#fe00 =:= 16#fc00 -> private;
classify_address({A, _, _, _, _, _, _, _}) when A band 16#ffc0 =:= 16#fe80 -> reserved;
classify_address({A, _, _, _, _, _, _, _}) when A band 16#ff00 =:= 16#ff00 -> reserved;
classify_address({A, _, _, _, _, _, _, _}) when A band 16#e000 =:= 16#2000 -> public;
classify_address(_) -> reserved.

classify_embedded(Hi, Lo) ->
    classify_address({Hi bsr 8, Hi band 255, Lo bsr 8, Lo band 255}).

%% ---------------------------------------------------------------------------
%% Encoding

encode_request(Method, #{host := Host, port := Port, target := Target}, Headers, Body) ->
    maybe
        {ok, MethodBin} ?= method(Method),
        {ok, HeaderLines} ?= encode_headers(Headers, []),
        HostHeader =
            case Port of
                443 -> Host;
                _ -> <<Host/binary, ":", (integer_to_binary(Port))/binary>>
            end,
        BodyBin =
            case Body of
                none -> none;
                _ -> iolist_to_binary(Body)
            end,
        LengthLine =
            case BodyBin of
                none -> [];
                _ -> [<<"content-length: ">>, integer_to_binary(byte_size(BodyBin)), <<"\r\n">>]
            end,
        ok ?= no_control(Target),
        {ok, [
            MethodBin,
            <<" ">>,
            Target,
            <<" HTTP/1.1\r\nhost: ">>,
            HostHeader,
            <<"\r\nconnection: close\r\nuser-agent: warden\r\n">>,
            LengthLine,
            HeaderLines,
            <<"\r\n">>,
            case BodyBin of
                none -> <<>>;
                _ -> BodyBin
            end
        ]}
    end.

method(get) -> {ok, <<"GET">>};
method(post) -> {ok, <<"POST">>};
method(head) -> {ok, <<"HEAD">>};
method(_) -> not_sent(invalid_request).

encode_headers([], Acc) ->
    {ok, lists:reverse(Acc)};
encode_headers([{Name0, Value0} | Rest], Acc) ->
    Name = string:lowercase(iolist_to_binary(Name0)),
    Value = iolist_to_binary(Value0),
    case Name of
        N when N =:= <<"host">>; N =:= <<"content-length">>; N =:= <<"connection">>; N =:= <<"transfer-encoding">> ->
            encode_headers(Rest, Acc);
        _ ->
            maybe
                ok ?= no_control(Name),
                ok ?= no_control(Value),
                encode_headers(Rest, [[Name, <<": ">>, Value, <<"\r\n">>] | Acc])
            end
    end;
encode_headers(_, _) ->
    not_sent(invalid_request).

no_control(Bin) ->
    case binary:match(Bin, [<<"\r">>, <<"\n">>, <<0>>]) of
        nomatch -> ok;
        _ -> not_sent(invalid_request)
    end.

%% ---------------------------------------------------------------------------
%% Connection

connect(Address, #{host := Host, port := Port}, Deadline, Config) ->
    maybe
        {ok, CaCerts} ?= cacerts(Config),
        HostString = binary_to_list(Host),
        NameOptions =
            case inet:parse_strict_address(strip_brackets(HostString)) of
                {ok, _} -> [{server_name_indication, disable}];
                {error, _} -> [{server_name_indication, HostString}]
            end,
        Options =
            [
                binary,
                {active, false},
                {packet, raw},
                {verify, verify_peer},
                {cacerts, CaCerts},
                {depth, 10},
                {versions, ['tlsv1.3', 'tlsv1.2']},
                {log_level, warning},
                {customize_hostname_check, [
                    {match_fun, public_key:pkix_verify_hostname_match_fun(https)}
                ]}
            ] ++ NameOptions,
        case remaining(Deadline) of
            0 ->
                not_sent(timeout);
            Remaining ->
                %% A TLS handshake completes before any request byte is written,
                %% so every failure here is pre-transmission.
                case ssl:connect(Address, Port, Options, Remaining) of
                    {ok, Socket} ->
                        {ok, Socket};
                    {error, timeout} ->
                        not_sent(timeout);
                    {error, {tls_alert, _}} ->
                        not_sent(tls_rejected);
                    {error, {options, _}} ->
                        not_sent(invalid_tls_configuration);
                    {error, econnrefused} ->
                        not_sent(connection_refused);
                    {error, _} ->
                        not_sent(connection_failed)
                end
        end
    end.

cacerts(#{cacerts := system}) ->
    try public_key:cacerts_get() of
        [_ | _] = Certs -> {ok, Certs};
        _ -> not_sent(no_trust_anchors)
    catch
        _:_ -> not_sent(no_trust_anchors)
    end;
cacerts(#{cacerts := [_ | _] = Certs}) ->
    {ok, Certs};
cacerts(_) ->
    not_sent(no_trust_anchors).

%% ---------------------------------------------------------------------------
%% Exchange

exchange(Socket, Method, Bytes, Deadline, Config) ->
    try
        case ssl:send(Socket, Bytes) of
            ok ->
                receive_response(Socket, Method, Deadline, Config);
            {error, _} ->
                sent(send_failed)
        end
    after
        ssl:close(Socket)
    end.

receive_response(Socket, Method, Deadline, Config) ->
    MaxHeaderBytes = maps:get(max_header_bytes, Config),
    ok = ssl:setopts(Socket, [{packet, http_bin}, {packet_size, MaxHeaderBytes}]),
    maybe
        {ok, {Status, Reason}} ?= read_status(Socket, Deadline, ?MAX_INTERIM),
        {ok, Headers} ?= read_headers(Socket, Deadline, Config, [], 0),
        ok = ssl:setopts(Socket, [{packet, raw}, {packet_size, 0}]),
        {ok, Body} ?= read_body(Socket, Method, Status, Headers, Deadline, Config),
        {ok, {{"HTTP/1.1", Status, Reason}, Headers, Body}}
    end.

read_status(Socket, Deadline, Interim) ->
    case recv(Socket, Deadline) of
        {ok, {http_response, _Version, Status, _Reason}} when
            Status >= 100, Status < 200, Interim > 0
        ->
            %% Interim responses carry headers that are read and discarded.
            case skip_headers(Socket, Deadline, 0) of
                ok -> read_status(Socket, Deadline, Interim - 1);
                Error -> Error
            end;
        {ok, {http_response, _Version, Status, Reason}} when Status >= 200, Status < 600 ->
            {ok, {Status, binary_to_list(Reason)}};
        {ok, _Other} ->
            sent(malformed_response);
        {error, Class} ->
            sent(Class)
    end.

skip_headers(Socket, Deadline, Count) when Count < ?DEFAULT_MAX_HEADERS ->
    case recv(Socket, Deadline) of
        {ok, http_eoh} -> ok;
        {ok, {http_header, _, _, _, _}} -> skip_headers(Socket, Deadline, Count + 1);
        {ok, _} -> sent(malformed_response);
        {error, Class} -> sent(Class)
    end;
skip_headers(_, _, _) ->
    sent(headers_too_large).

read_headers(Socket, Deadline, Config, Acc, Bytes) ->
    case recv(Socket, Deadline) of
        {ok, http_eoh} ->
            {ok, lists:reverse(Acc)};
        {ok, {http_header, _, Name0, _, Value}} ->
            Name = header_name(Name0),
            NewBytes = Bytes + length(Name) + byte_size(Value),
            case
                length(Acc) >= maps:get(max_headers, Config) orelse
                    NewBytes > maps:get(max_header_bytes, Config)
            of
                true -> sent(headers_too_large);
                false -> read_headers(Socket, Deadline, Config, [{Name, Value} | Acc], NewBytes)
            end;
        {ok, {http_error, _}} ->
            sent(malformed_response);
        {ok, _} ->
            sent(malformed_response);
        {error, Class} ->
            sent(Class)
    end.

header_name(Name) when is_atom(Name) -> string:lowercase(atom_to_list(Name));
header_name(Name) when is_binary(Name) -> string:lowercase(binary_to_list(Name)).

read_body(_Socket, head, _Status, _Headers, _Deadline, _Config) ->
    {ok, <<>>};
read_body(_Socket, _Method, Status, _Headers, _Deadline, _Config) when
    Status =:= 204; Status =:= 304
->
    {ok, <<>>};
read_body(Socket, _Method, _Status, Headers, Deadline, Config) ->
    Max = maps:get(max_body, Config),
    maybe
        ok ?= identity_encoding(Headers),
        case {header_values("transfer-encoding", Headers), header_values("content-length", Headers)} of
            {[], []} ->
                read_until_close(Socket, Deadline, Max, <<>>);
            {[], Lengths} ->
                case parse_content_length(Lengths) of
                    {ok, Length} when Length > Max -> sent(body_too_large);
                    {ok, Length} -> read_exact(Socket, Length, Deadline, <<>>);
                    error -> sent(malformed_response)
                end;
            {[Encoding], []} ->
                case string:lowercase(string:trim(Encoding)) of
                    <<"chunked">> -> read_chunked(Socket, Deadline, Max, <<>>, <<>>);
                    _ -> sent(unsupported_transfer_encoding)
                end;
            _ ->
                sent(malformed_response)
        end
    end.

identity_encoding(Headers) ->
    case header_values("content-encoding", Headers) of
        [] -> ok;
        [Value] ->
            case string:lowercase(string:trim(Value)) of
                <<"identity">> -> ok;
                _ -> sent(unsupported_content_encoding)
            end;
        _ -> sent(unsupported_content_encoding)
    end.

header_values(Name, Headers) ->
    [V || {N, V} <- Headers, N =:= Name].

parse_content_length(Values) ->
    Parsed = [catch binary_to_integer(string:trim(V)) || V <- Values],
    case lists:usort(Parsed) of
        [Length] when is_integer(Length), Length >= 0 -> {ok, Length};
        _ -> error
    end.

read_exact(_Socket, 0, _Deadline, Acc) ->
    {ok, Acc};
read_exact(Socket, Length, Deadline, Acc) ->
    case recv(Socket, Deadline) of
        {ok, Data} when byte_size(Data) =< Length ->
            read_exact(Socket, Length - byte_size(Data), Deadline, <<Acc/binary, Data/binary>>);
        {ok, _TooMuch} ->
            sent(malformed_response);
        {error, closed} ->
            sent(truncated_body);
        {error, Class} ->
            sent(Class)
    end.

read_until_close(Socket, Deadline, Max, Acc) ->
    case recv(Socket, Deadline) of
        {ok, Data} when byte_size(Acc) + byte_size(Data) > Max ->
            sent(body_too_large);
        {ok, Data} ->
            read_until_close(Socket, Deadline, Max, <<Acc/binary, Data/binary>>);
        {error, closed} ->
            {ok, Acc};
        {error, Class} ->
            sent(Class)
    end.

%% Chunked decoding over a raw byte buffer. `Buffer` holds unparsed bytes and
%% `Acc` the decoded body; both are bounded by the body limit plus one read.
read_chunked(Socket, Deadline, Max, Buffer, Acc) ->
    case binary:split(Buffer, <<"\r\n">>) of
        [Line, Rest] ->
            case chunk_size(Line) of
                {ok, 0} ->
                    finish_trailers(Socket, Deadline, Rest, Acc);
                {ok, Size} when byte_size(Acc) + Size > Max ->
                    sent(body_too_large);
                {ok, Size} ->
                    chunk_data(Socket, Deadline, Max, Size, Rest, Acc);
                error ->
                    sent(malformed_response)
            end;
        [_] when byte_size(Buffer) > ?MAX_CHUNK_LINE ->
            sent(malformed_response);
        [_] ->
            case recv(Socket, Deadline) of
                {ok, Data} -> read_chunked(Socket, Deadline, Max, <<Buffer/binary, Data/binary>>, Acc);
                {error, closed} -> sent(truncated_body);
                {error, Class} -> sent(Class)
            end
    end.

chunk_data(Socket, Deadline, Max, Size, Buffer, Acc) when byte_size(Buffer) >= Size + 2 ->
    case Buffer of
        <<Chunk:Size/binary, "\r\n", Rest/binary>> ->
            read_chunked(Socket, Deadline, Max, Rest, <<Acc/binary, Chunk/binary>>);
        _ ->
            sent(malformed_response)
    end;
chunk_data(Socket, Deadline, Max, Size, Buffer, Acc) ->
    case recv(Socket, Deadline) of
        {ok, Data} -> chunk_data(Socket, Deadline, Max, Size, <<Buffer/binary, Data/binary>>, Acc);
        {error, closed} -> sent(truncated_body);
        {error, Class} -> sent(Class)
    end.

chunk_size(Line) ->
    [Hex | _Extensions] = binary:split(Line, <<";">>),
    Trimmed = string:trim(Hex),
    case byte_size(Trimmed) of
        N when N > 0, N =< 8 ->
            try
                {ok, binary_to_integer(Trimmed, 16)}
            catch
                _:_ -> error
            end;
        _ ->
            error
    end.

%% Trailers after the last chunk are read and discarded within the chunk-line
%% bound; the body is complete once the empty line arrives.
finish_trailers(Socket, Deadline, Buffer, Acc) ->
    case Buffer of
        <<"\r\n", _/binary>> ->
            {ok, Acc};
        _ ->
            case binary:match(Buffer, <<"\r\n\r\n">>) of
                {_, _} ->
                    {ok, Acc};
                nomatch when byte_size(Buffer) > ?MAX_CHUNK_LINE ->
                    sent(malformed_response);
                nomatch ->
                    case recv(Socket, Deadline) of
                        {ok, Data} -> finish_trailers(Socket, Deadline, <<Buffer/binary, Data/binary>>, Acc);
                        {error, closed} -> {ok, Acc};
                        {error, Class} -> sent(Class)
                    end
            end
    end.

recv(Socket, Deadline) ->
    case remaining(Deadline) of
        0 ->
            {error, timeout};
        Remaining ->
            case ssl:recv(Socket, 0, Remaining) of
                {ok, Data} -> {ok, Data};
                {error, timeout} -> {error, timeout};
                {error, closed} -> {error, closed};
                {error, emsgsize} -> {error, headers_too_large};
                {error, {invalid_packet, _}} -> {error, headers_too_large};
                {error, _} -> {error, receive_failed}
            end
    end.

%% ---------------------------------------------------------------------------
%% Helpers

not_sent(Class) -> {error, {warden_transport, not_sent, Class}}.
sent(Class) -> {error, {warden_transport, sent, Class}}.

now_ms() -> erlang:monotonic_time(millisecond).

remaining(Deadline) -> max(0, Deadline - now_ms()).

%% Telemetry carries only method, host, path, status or failure class and
%% duration. Queries, headers and bodies are never observed.
observe(Method, Request, Result, Start) ->
    Url = element(1, Request),
    Meta0 =
        try uri_string:parse(unicode:characters_to_binary(Url)) of
            #{host := Host} = Parts -> #{host => Host, path => maps:get(path, Parts, <<>>)};
            _ -> #{}
        catch
            _:_ -> #{}
        end,
    Meta1 = Meta0#{method => Method},
    Meta =
        case Result of
            {ok, {{_, Status, _}, _, _}} -> Meta1#{status => Status};
            {error, {warden_transport, Stage, Class}} -> Meta1#{stage => Stage, failure => Class};
            _ -> Meta1
        end,
    Duration = erlang:monotonic_time() - Start,
    telemetry:execute([warden, http, request], #{duration => Duration}, Meta).
