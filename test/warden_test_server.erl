%% Scriptable local HTTPS server for transport and provider tests.
%%
%% `start(CertName, Handler)` listens on 127.0.0.1 with a certificate from the
%% disposable test PKI. For every connection it reads one HTTP/1.1 request,
%% reports it to the owner as `{warden_test_request, Ref, Request}` and replies
%% according to `Handler(Request)`:
%%
%%   {respond, Status, Headers, Body}  - complete response with content-length
%%   {raw, Iodata}                     - raw bytes, then close
%%   {raw_then_hold, Iodata}           - raw bytes, keep the socket open
%%   {stream_forever, Chunk}           - chunked body that never ends
%%   {delay, Ms, Reply}                - wait, then reply
%%   close                             - close without replying
-module(warden_test_server).

-export([start/2, start/3, stop/1, port/1, url/2, pki_dir/0, requests/1]).

pki_dir() ->
    Dir = "build/test-pki",
    case filelib:is_file(filename:join(Dir, "ca.pem")) of
        true -> list_to_binary(Dir);
        false -> warden_test_pki:generate(Dir)
    end.

start(CertName, Handler) ->
    start(CertName, Handler, #{}).

start(CertName, Handler, _Opts) ->
    Dir = binary_to_list(pki_dir()),
    Owner = self(),
    Ref = make_ref(),
    {ok, _} = application:ensure_all_started(ssl),
    {ok, Listen} = ssl:listen(0, [
        binary,
        {active, false},
        {reuseaddr, true},
        {ip, {127, 0, 0, 1}},
        {certfile, filename:join(Dir, CertName ++ ".pem")},
        {keyfile, filename:join(Dir, CertName ++ ".key")},
        {versions, ['tlsv1.3', 'tlsv1.2']}
    ]),
    {ok, {_, Port}} = ssl:sockname(Listen),
    Acceptor = spawn(fun() -> accept_loop(Listen, Handler, Owner, Ref) end),
    ok = ssl:controlling_process(Listen, Acceptor),
    #{listen => Listen, port => Port, acceptor => Acceptor, ref => Ref}.

stop(#{acceptor := Acceptor, listen := Listen}) ->
    exit(Acceptor, kill),
    catch ssl:close(Listen),
    ok.

port(#{port := Port}) -> Port.

url(#{port := Port}, Path) ->
    iolist_to_binary(["https://localhost:", integer_to_list(Port), Path]).

%% Collect the requests reported so far for this server.
requests(#{ref := Ref}) ->
    collect(Ref, []).

collect(Ref, Acc) ->
    receive
        {warden_test_request, Ref, Request} -> collect(Ref, [Request | Acc])
    after 0 -> lists:reverse(Acc)
    end.

accept_loop(Listen, Handler, Owner, Ref) ->
    case ssl:transport_accept(Listen) of
        {ok, Transport} ->
            Pid = spawn(fun() -> serve(Transport, Handler, Owner, Ref) end),
            _ = ssl:controlling_process(Transport, Pid),
            Pid ! go,
            accept_loop(Listen, Handler, Owner, Ref);
        {error, _} ->
            ok
    end.

serve(Transport, Handler, Owner, Ref) ->
    receive
        go -> ok
    end,
    case ssl:handshake(Transport, 5000) of
        {ok, Socket} ->
            case read_request(Socket) of
                {ok, Request} ->
                    Owner ! {warden_test_request, Ref, Request},
                    reply(Socket, Handler(Request));
                _ ->
                    ok
            end,
            catch ssl:close(Socket);
        _ ->
            ok
    end.

read_request(Socket) ->
    ok = ssl:setopts(Socket, [{packet, http_bin}]),
    case ssl:recv(Socket, 0, 5000) of
        {ok, {http_request, Method, {abs_path, Path}, _}} ->
            Headers = read_headers(Socket, []),
            ok = ssl:setopts(Socket, [{packet, raw}]),
            Length =
                case lists:keyfind(<<"content-length">>, 1, Headers) of
                    {_, L} -> binary_to_integer(L);
                    false -> 0
                end,
            Body =
                case Length of
                    0 -> <<>>;
                    _ -> {ok, B} = ssl:recv(Socket, Length, 5000), B
                end,
            {ok, #{method => Method, path => Path, headers => Headers, body => Body}};
        _ ->
            error
    end.

read_headers(Socket, Acc) ->
    case ssl:recv(Socket, 0, 5000) of
        {ok, {http_header, _, Name, _, Value}} ->
            Key = string:lowercase(
                case Name of
                    A when is_atom(A) -> atom_to_binary(A);
                    B -> B
                end
            ),
            read_headers(Socket, [{Key, Value} | Acc]);
        {ok, http_eoh} ->
            lists:reverse(Acc);
        _ ->
            lists:reverse(Acc)
    end.

reply(Socket, {delay, Ms, Reply}) ->
    timer:sleep(Ms),
    reply(Socket, Reply);
reply(Socket, {respond, Status, Headers, Body}) ->
    BodyBin = iolist_to_binary(Body),
    ssl:send(Socket, [
        <<"HTTP/1.1 ">>,
        integer_to_list(Status),
        <<" X\r\n">>,
        [[N, <<": ">>, V, <<"\r\n">>] || {N, V} <- Headers],
        <<"content-length: ">>,
        integer_to_list(byte_size(BodyBin)),
        <<"\r\nconnection: close\r\n\r\n">>,
        BodyBin
    ]);
reply(Socket, {raw, Bytes}) ->
    ssl:send(Socket, Bytes);
reply(Socket, {raw_then_hold, Bytes}) ->
    ssl:send(Socket, Bytes),
    timer:sleep(60000);
reply(Socket, {stream_forever, Chunk}) ->
    ssl:send(Socket, <<"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ntransfer-encoding: chunked\r\n\r\n">>),
    stream_forever(Socket, iolist_to_binary(Chunk));
reply(_Socket, close) ->
    ok.

stream_forever(Socket, Chunk) ->
    Size = integer_to_list(byte_size(Chunk), 16),
    case ssl:send(Socket, [Size, <<"\r\n">>, Chunk, <<"\r\n">>]) of
        ok -> stream_forever(Socket, Chunk);
        _ -> ok
    end.
