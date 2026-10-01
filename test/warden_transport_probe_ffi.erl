%% TLS probe servers for transport tests: a capturing server (request heads,
%% connection count, keep-alive) and a silent server that never reads.
-module(warden_transport_probe_ffi).
-export([capture_server/3, heads/1, connections/1, close_connections/1,
         silent_server/2, stop/1, mailbox_size/0, try_bind/2, kill_children/1]).

%% A TLS server on Address:Port (0 = any) that records every request head,
%% answers 200 "ok" with keep-alive, and counts accepted connections.
capture_server(Address, Port, Name) ->
    {ok, _} = application:ensure_all_started(ssl),
    Self = self(),
    Pid = spawn(fun() ->
        Tab = ets:new(probe, [public, bag]),
        {ok, L} = ssl:listen(Port, family(Address) ++ [binary, {active, false}, {ip, Address},
            {reuseaddr, true} | certs(Name)]),
        {ok, {_, P}} = ssl:sockname(L),
        Self ! {self(), ready, P, Tab},
        accept(L, Tab)
    end),
    receive {Pid, ready, P, Tab} -> {P, {Pid, Tab}} after 5000 -> error(timeout) end.

accept(L, Tab) ->
    case ssl:transport_accept(L) of
        {ok, T} ->
            Owner = spawn(fun() -> receive go -> ok end, serve(T, Tab) end),
            ok = ssl:controlling_process(T, Owner),
            Owner ! go,
            accept(L, Tab);
        _ -> ok
    end.

serve(T, Tab) ->
    case ssl:handshake(T, 5000) of
        {ok, S} ->
            ets:insert(Tab, {connection, S}),
            loop(S, Tab, <<>>);
        _ -> ok
    end.

loop(S, Tab, Buffer) ->
    case binary:split(Buffer, <<"\r\n\r\n">>) of
        [Head, Rest] ->
            ets:insert(Tab, {head, Head}),
            ok = ssl:send(S, <<"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok">>),
            loop(S, Tab, Rest);
        _ ->
            case ssl:recv(S, 0, 30000) of
                {ok, Data} -> loop(S, Tab, <<Buffer/binary, Data/binary>>);
                _ -> ssl:close(S)
            end
    end.

heads({_, Tab}) -> [H || {head, H} <- ets:lookup(Tab, head)].
connections({_, Tab}) -> length(ets:lookup(Tab, connection)).
close_connections({_, Tab}) ->
    [ssl:close(S) || {connection, S} <- ets:lookup(Tab, connection)],
    nil.

%% A TLS server that completes the handshake and never reads.
silent_server(Name, _) ->
    {ok, _} = application:ensure_all_started(ssl),
    Self = self(),
    Pid = spawn(fun() ->
        {ok, L} = ssl:listen(0, [binary, {active, false}, {ip, {127,0,0,1}} | certs(Name)]),
        {ok, {_, P}} = ssl:sockname(L),
        Self ! {self(), ready, P},
        hold(L, [])
    end),
    receive {Pid, ready, P} -> {P, {Pid, none}} after 5000 -> error(timeout) end.

hold(L, Held) ->
    case ssl:transport_accept(L) of
        {ok, T} ->
            case ssl:handshake(T, 5000) of
                {ok, S} -> hold(L, [S | Held]);
                _ -> hold(L, Held)
            end;
        _ -> ok
    end.

stop({Pid, _}) -> exit(Pid, kill), nil.

%% Whether Address:Port can be bound by this user (e.g. 443).
try_bind(Address, Port) ->
    case gen_tcp:listen(Port, family(Address) ++ [{ip, Address}, {reuseaddr, true}]) of
        {ok, S} -> gen_tcp:close(S), true;
        _ -> false
    end.

%% Messages in the caller's mailbox, excluding the test server's own
%% request notifications ({warden_test_request, _, _}).
mailbox_size() ->
    {messages, Ms} = process_info(self(), messages),
    length([M || M <- Ms, not is_tuple(M) orelse element(1, M) =/= warden_test_request]).

certs(Name) ->
    Dir = "build/test-pki/",
    [{certfile, Dir ++ binary_to_list(Name) ++ ".pem"},
     {keyfile, Dir ++ binary_to_list(Name) ++ ".key"}].

family(Address) when tuple_size(Address) =:= 8 -> [inet6];
family(_) -> [].

%% Kill every child of a supervisor (to exercise restarts).
kill_children(Sup) ->
    [exit(Pid, kill) || {_, Pid, _, _} <- supervisor:which_children(Sup), is_pid(Pid)],
    nil.
