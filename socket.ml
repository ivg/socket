open Lwt
open Lwt_io
open Lwt_log

let section = Section.make "Socket"

module Address = struct
  type name = string
  type port = string
  type comm_flags = NoResolve  | Listen
  type inet_proto = Udp | Tcp
  type inet_flags = Proto of inet_proto
  type unix_flags = Set

  let localhost = "127.0.0.1"
  let any_host = ""
  let any_port = ""

  type inet
  type unix
  type 'a f =
    | Comm: comm_flags -> 'a f
    | Inet: inet_flags -> inet f
    | Unix: unix_flags -> unix f

  type 'a flags = 'a f list

  type t = Unix.addr_info

  let (&&) (type t) (fs1 : t flags) (fs2 : t flags) : t flags =
    (fs1 @ fs2)

  let flags = List.concat

  let listen = [Comm Listen]
  let noresolve = [Comm NoResolve]
  let tcp = [Inet (Proto Tcp)]
  let udp = [Inet (Proto Udp)]
  let unix = [Unix Set]

  let ai_flags (type t) (flags : t f) =
    let open Unix in match flags with
    | Inet (Proto Udp) -> [AI_FAMILY PF_INET;AI_SOCKTYPE SOCK_DGRAM]
    | Inet (Proto Tcp) -> [AI_FAMILY PF_INET;AI_SOCKTYPE SOCK_STREAM]
    | Unix _ -> []
    | Comm NoResolve -> [AI_NUMERICHOST]
    | Comm Listen    -> [AI_PASSIVE]


  exception No_host


  let is_unix flags =
    let is_unix (type t) (flags : t f) = match flags with
      | Unix _ -> true
      | _ -> false in
    List.exists is_unix flags

  let is_local s =
    let open Unix in match s.ai_addr with
    | ADDR_UNIX _ -> true
    | ADDR_INET (inet,_) -> List.mem inet [
        inet_addr_loopback;
        inet6_addr_any;
        inet_addr_any;
        inet6_addr_any
      ]


  let create ?(flags=[]) ?(port=any_port) name =
    if is_unix flags
    then return Unix.({
        ai_family = PF_UNIX;
        ai_socktype = SOCK_STREAM;
        ai_protocol = 0;
        ai_addr = ADDR_UNIX name;
        ai_canonname = name;
      })
    else
      let ai = List.map ai_flags flags |> List.concat in
      match_lwt Lwt_unix.getaddrinfo name port ai with
      | addr::_ -> return addr
      | [] -> fail No_host

  let any_tcp = Unix.({
      ai_family = PF_INET;
      ai_socktype = SOCK_STREAM;
      ai_protocol = 0;
      ai_addr = ADDR_INET (inet_addr_any, 0);
      ai_canonname = "localhost";
    })

  let any_udp = Unix.({
      ai_family = PF_INET;
      ai_socktype = SOCK_DGRAM;
      ai_protocol = 0;
      ai_addr = ADDR_INET (inet_addr_any, 0);
      ai_canonname = "localhost";
    })


  let to_addr_info addr = addr
  let of_addr_info addr = addr

  let family addr = Unix.(addr.ai_family)
  let socktype addr = Unix.(addr.ai_socktype)
  let canonname addr = Unix.(addr.ai_canonname)

  let string_of_addr addr =
    let open Unix in match addr.ai_addr with
    | ADDR_UNIX name -> name
    | ADDR_INET (inet_addr,port) ->
      let host = if is_local addr
        then gethostname () else string_of_inet_addr inet_addr in
      Printf.sprintf "%s:%d" host port

  let scheme_of_address addr =
    let open Unix in
    match addr.ai_family, addr.ai_socktype with
    | PF_INET,SOCK_STREAM     -> "tcp://"
    | PF_INET,SOCK_DGRAM      -> "udp://"
    | PF_INET,SOCK_RAW        -> "raw://"
    | PF_INET,SOCK_SEQPACKET  -> "packet://"
    | PF_INET6,SOCK_STREAM    -> "tcp6://"
    | PF_INET6,SOCK_DGRAM     -> "udp6://"
    | PF_INET6,SOCK_RAW       -> "raw6://"
    | PF_INET6,SOCK_SEQPACKET -> "packet6://"
    | PF_UNIX,_               -> "unix://"

  let to_string addr = scheme_of_address addr ^ string_of_addr addr
end

type address = Address.t

module Connection = struct
  type t = {
    socket: Lwt_unix.file_descr;
    ichan: Lwt_io.input_channel Lazy.t;
    ochan: Lwt_io.output_channel Lazy.t;
    close: unit Lwt.t Lazy.t;
    on_closed: unit Lwt.t;
    close_mx: Lwt_mutex.t;
  }

  let create socket =
    let ochan_closed, notify_ochan_closed = task () in
    let ichan_closed, notify_ichan_closed = task () in
    let on_closed, connection_closed = task () in
    let close_socket = lazy (
      try_lwt
        Lwt_unix.close socket
      with exn -> error ~exn ~section "failed to close socket") in
    async (fun () ->
       ( ochan_closed <&> ichan_closed) >> Lazy.force close_socket);
    let shutdown closed cmd = lazy begin
      let () = try
          Lwt_unix.shutdown socket cmd;
      with
      | Unix.Unix_error (Unix.ENOTCONN, _, _) -> ()
      | exn -> ign_error ~exn ~section "failed to shutdown socket" in
      wakeup closed ();
      return_unit
    end in
    let channel close mode =
      lazy (of_fd ~mode ~close:(fun () -> Lazy.force close) socket) in
    let shutdown_ichan =
      shutdown notify_ichan_closed Unix.SHUTDOWN_RECEIVE in
    let shutdown_ochan =
      shutdown notify_ochan_closed Unix.SHUTDOWN_SEND in
    let close = lazy
      (Lazy.force shutdown_ochan >>
       Lazy.force shutdown_ichan >>
       return (wakeup connection_closed ())) in
    {
      socket; close; on_closed;
      ichan = channel shutdown_ichan Lwt_io.input;
      ochan = channel shutdown_ochan Lwt_io.output;
      close_mx = Lwt_mutex.create ();
    }

  let input_channel t = Lazy.force t.ichan
  let output_channel t = Lazy.force t.ochan
  let to_fd t = t.socket
  let close t =
    let close_if_forced chan =
      if Lazy.is_val chan
      then Lwt_io.close (Lazy.force chan)
      else return_unit in
    Lwt_mutex.with_lock t.close_mx (fun () ->
        close_if_forced t.ochan >>
        close_if_forced t.ichan >>
        Lazy.force t.close)

  let on_close t = t.on_closed

  let restart_on_eintr f x  =
    try_lwt
      f x
    with
    | Unix.Unix_error (Unix.EINTR, _, _) -> f x
    | exn -> fail exn

  let rec perform_io op buf off = function
    | 0 -> return_unit
    | bytes -> let f () = op buf off bytes in
      match_lwt restart_on_eintr f () with
      | 0 -> fail End_of_file
      | n -> perform_io op buf (off+n) (bytes-n)

  module type Buffer = sig
    type t
    val blit: t -> int -> t -> int -> int -> unit
    val read: Lwt_unix.file_descr -> t -> int -> int -> int Lwt.t
    val write: Lwt_unix.file_descr -> t -> int -> int -> int Lwt.t
    val blit_of_bytes: Lwt_bytes.t -> int -> t -> int -> int -> unit
  end

  module StrBuf = struct
    type t = string
    let blit = String.blit
    let read = Lwt_unix.read
    let write = Lwt_unix.write
    let blit_of_bytes = Lwt_bytes.blit_bytes_string
  end

  module BytesBuf = struct
    type t = Lwt_bytes.t
    let blit = Lwt_bytes.blit
    let read = Lwt_bytes.read
    let write = Lwt_bytes.write
    let blit_of_bytes = blit
  end

  module BigIO(Buffer : Buffer) = struct
    let read conn buf off size =
      let open Lwt_io in
      let take_from_buffer ch =
        let len = min size (ch.da_max - ch.da_ptr) in
        Buffer.blit_of_bytes ch.da_buffer ch.da_ptr buf off len;
        return len in
      let ichan = Lazy.force conn.ichan in
      lwt bytes_read = direct_access ichan take_from_buffer in
      let cpos = position ichan in
      let read = Buffer.read conn.socket in
      set_position ichan Int64.(add cpos (of_int bytes_read)) >>
      perform_io read buf (off+bytes_read) (size-bytes_read)

    let write conn buf off size =
      lwt () = if Lazy.is_val conn.ochan
        then Lwt_io.flush (Lazy.force conn.ochan)
        else return_unit in
      let write = Buffer.write conn.socket in
      perform_io write buf off size
  end

  module BytesIO = BigIO(BytesBuf)
  module StringIO = BigIO(StrBuf)


  let establish dst =
    let fd = Lwt_unix.(
        socket dst.ai_family dst.ai_socktype dst.ai_protocol) in
    try_lwt Lwt_unix.(connect fd dst.ai_addr) >> return (create fd)
    with exn ->
      (try_lwt Lwt_unix.close fd with _ -> return_unit) >> fail exn

  let getsockname conn = Lwt_unix.getsockname conn.socket
  let getpeername conn = Lwt_unix.getpeername conn.socket
  let get_credentials conn = Lwt_unix.get_credentials conn.socket

  module Options = struct
    open Lwt_unix
    type _ t =
      | Bool: socket_bool_option -> bool t
      | Int : socket_int_option -> int t
      | OptInt: socket_optint_option -> int option t
      | Float: socket_float_option -> float t

    let debug = Bool SO_DEBUG
    let broadcast = Bool SO_BROADCAST
    let reuseaddr = Bool SO_REUSEADDR
    let keepalive = Bool SO_KEEPALIVE
    let dontroute = Bool SO_DONTROUTE
    let oobinline = Bool SO_OOBINLINE
    let acceptconn = Bool SO_ACCEPTCONN
    let tcp_nodelay = Bool TCP_NODELAY
    let ipv6_only = Bool IPV6_ONLY
    let sndbuf = Int SO_SNDBUF
    let rcvbuf = Int SO_RCVBUF
    let error = Int SO_ERROR
    let socktype = Int SO_TYPE
    let rcvlowat = Int SO_RCVLOWAT
    let sndlowat = Int SO_SNDLOWAT
    let linger = OptInt SO_LINGER
    let rcvtimeo = Float SO_RCVTIMEO
    let sndtimeo = Float SO_SNDTIMEO

    let set (type a) conn (opt : a t ) (v : a) = match opt with
      | Bool opt -> setsockopt conn.socket opt v
      | Int  opt -> setsockopt_int conn.socket opt v
      | OptInt opt -> setsockopt_optint conn.socket opt v
      | Float opt -> setsockopt_float conn.socket opt v

    let get: type a. _ -> a t -> a = fun conn -> function
      | Bool opt -> getsockopt conn.socket opt
      | Int  opt -> getsockopt_int conn.socket opt
      | OptInt opt -> getsockopt_optint conn.socket opt
      | Float opt -> getsockopt_float conn.socket opt
  end
end

module Options = Connection.Options

type conn = Connection.t
type server = {
  connections: unit -> int;
  address: Unix.addr_info;
  shutdown : unit Lazy.t;
}

let shutdown server = Lazy.force server.shutdown


(* simulates accept function for connectionless sockets (udp).
   Implementation: peek a message from a client, then connect the
   socket to the peer's address and return the address with the
   provided socket.  If the socket is already connected, then
   block.
*)
let udp_accept sock =
  try_lwt
    let _ = Lwt_unix.getpeername sock in
    let inf,_ = wait () in
    inf
  with Unix.Unix_error (Unix.ENOTCONN,_,_) ->
    let hdr = Lwt_bytes.create 0 in
    lwt n,cli = Lwt_bytes.recvfrom sock hdr 0 0 [Unix.MSG_PEEK] in
    Lwt_unix.connect sock cli >> return (sock,cli)

let free_addr addr =
  try_lwt let open Lwt_unix in match addr with
    | ADDR_UNIX path when path <> "" && path.[0] <> '\x00' ->
      unlink path
    | _ -> return_unit
  with exn -> error ~exn "unlink failed"


let listen ?(max_queue=5) s f =
  let sock = Lwt_unix.(
      socket s.ai_family s.ai_socktype s.ai_protocol) in
  let is_udp = Unix.(s.ai_socktype = SOCK_DGRAM) in
  Lwt_unix.setsockopt sock Unix.SO_REUSEADDR true;
  Lwt_unix.(bind sock s.ai_addr) ;
  if not  is_udp then
    Lwt_unix.listen sock max_queue;
  let free_addr = lazy (free_addr s.Unix.ai_addr) in
  let exit_hook =
    Lwt_sequence.add_r
      (fun () -> Lazy.force free_addr) Lwt_main.exit_hooks in
  let abort_waiter, abort_wakener = wait () in
  let abort_waiter = abort_waiter >> return `Shutdown in
  let clients = Lwt_sequence.create () in
  let accept = if is_udp then udp_accept else Lwt_unix.accept in
  let rec loop () =
    try_lwt pick [accept sock >|= (fun x -> `Accept x); abort_waiter]
      >>= function
      | `Accept(fd, addr) ->
        (try  Lwt_unix.set_close_on_exec fd
         with Invalid_argument _ -> ());
        let cli = Connection.create fd in
        let self = Lwt_sequence.add_r cli clients in
        async (fun () ->
            lwt () = try_lwt
                f cli
              with exn -> error ~section ~exn "closing with error" in
            lwt () = Connection.close cli in
            return (Lwt_sequence.remove self));
        loop ()
      | `Shutdown ->
        lwt () = Lwt_unix.close sock in
        let closings =
          Lwt_sequence.fold_l
            (fun cli ts -> Connection.close cli :: ts) clients [] in
        lwt () = join closings in
        Lwt_sequence.remove exit_hook;
        Lazy.force free_addr
    with exn -> error ~exn ~section "failed" in
  async loop;
  let sockaddr = Lwt_unix.getsockname sock in
  let address = Unix.({s with ai_addr = sockaddr}) in
  let connections () = Lwt_sequence.length clients in
  {connections; address; shutdown = lazy (wakeup abort_wakener ())}

let server_address server = server.address
let clients server = server.connections ()

let establish_server addr f =
  listen addr (fun conn ->
      let ic = Connection.input_channel conn in
      let oc = Connection.output_channel conn in
      f (ic,oc))


let connect dst = Connection.establish dst


module IO = struct

  type ('a,'b) t = {
    get: unit -> 'a Lwt.t;
    put: 'b -> unit Lwt.t;
  }

  let create conn ~get ~put = {
    get = (fun () -> get conn);
    put = (fun v  ->
        lwt () = put conn v in
        Lwt_io.flush (Connection.output_channel conn) );
  }

  let make_io conn ~get ~put =
    create conn
      ~get:(fun conn -> get (Connection.input_channel conn))
      ~put:(fun conn v  -> put (Connection.output_channel conn) v)

  let marshaled ?flags conn = make_io conn
      ~get:Lwt_io.read_value
      ~put:(fun chan v -> Lwt_io.write_value chan ?flags v)

  let byte_stream conn =
    make_io conn ~get:Lwt_io.read_char ~put:Lwt_io.write_char

  module type Numbers = sig
    val int_stream:     conn -> (int,   int)   t
    val int32_stream:   conn -> (int32, int32) t
    val int64_stream:   conn -> (int64, int64) t
    val float32_stream: conn -> (float, float) t
    val float64_stream: conn -> (float, float) t
  end

  let rec module_of_endianess endianess =
    let open Lwt_io in match endianess with
    | Little_endian -> (module LE : NumberIO)
    | Big_endian    -> (module BE : NumberIO)

  module MakeNumbers (IO : NumberIO) = struct
    open IO
    let int_stream conn =
      make_io conn ~get:read_int ~put:write_int
    let int32_stream conn =
      make_io conn ~get:read_int32 ~put:write_int32
    let int64_stream conn =
      make_io conn ~get:read_int64 ~put:write_int64
    let float32_stream conn =
      make_io conn ~get:read_float32 ~put:write_float32
    let float64_stream conn =
      make_io conn ~get:read_float64 ~put:write_float64
  end

  module LE = MakeNumbers(Lwt_io.LE)
  module BE = MakeNumbers(Lwt_io.BE)
  module NativeIO = MakeNumbers(Lwt_io)
  include NativeIO


  let stream_of_io ?(on_error=fun _ -> return_unit) t =
    let of_user,to_client = Lwt_stream.create () in
    let of_client,to_user = Lwt_stream.create () in
    let reader_t () =
      let rec loop () =
        lwt v = t.get () in
        to_user (Some v);
        loop () in
      try_lwt loop () with
      | End_of_file
      | Lwt_io.Channel_closed _ -> return_unit
      | exn -> on_error exn
      finally return (to_user None) in
    let write_t () = Lwt_stream.iter_s t.put of_user in
    async (fun () ->
        try_lwt reader_t () <?> write_t ()
        with exn -> fatal ~exn "stream_of_io"
        finally
          to_client None;
          return_unit);
    of_client,to_client

  module Any = struct
    let say t arg =
      lwt () = t.put arg in
      t.get ()

    let ask t arg =
      lwt r  = t.get () in
      lwt () = t.put arg in
      return r

    let get t = t.get ()

    let put t v = t.put v
  end

  exception Protocol_error

  type ('a,'b) expect = 'a -> 'b option

  module Expect = struct
    type ('a,'b) t = ('a,'b) expect
    let const v v' = if v = v' then Some () else None
    let any v = Some v
  end


  module Exceptionless = struct
    let say t arg expect = Any.say t arg >|= expect
    let ask t arg expect = Any.ask t arg >|= expect
    let get t expect = Any.get t >|= expect
    let put = Any.put
  end

  let try_exn f expect =
    match_lwt f expect with
    | Some r -> return r
    | None -> fail Protocol_error

  let say t arg = Exceptionless.say t arg |> try_exn
  let ask t arg = Exceptionless.ask t arg |> try_exn
  let get t = Exceptionless.get t |> try_exn
  let put = Any.put



end


type buf = Lwt_bytes.t
let write_bytes = Connection.BytesIO.write
let read_bytes  = Connection.BytesIO.read
let write_string = Connection.StringIO.write
let read_string  = Connection.StringIO.read

type ('a,'b) io = ('a,'b) IO.t
type ('a,'b) expect = ('a,'b) IO.Expect.t

