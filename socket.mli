(** High-level library dealing with low-level sockets. *)

type server
type conn
type address = Unix.addr_info
type ('a,'b) expect = 'a -> 'b option
type ('a,'b) io

val listen: address -> (conn -> unit Lwt.t) -> server
val connect: address -> conn Lwt.t
val shutdown: server -> unit
val server_address: server -> address
val clients: server -> int

val establish_server:
  address ->
  (Lwt_io.input_channel * Lwt_io.output_channel -> unit Lwt.t) ->
  server

module Options : sig
  type 'a t
  val debug: bool t
  val broadcast: bool t
  val reuseaddr: bool t
  val keepalive: bool t
  val dontroute: bool t
  val oobinline: bool t
  val acceptconn: bool t
  val tcp_nodelay: bool t
  val ipv6_only: bool t
  val sndbuf: int t
  val rcvbuf: int t
  val error: int t
  val socktype: int t
  val rcvlowat: int t
  val sndlowat: int t
  val linger: int option t
  val rcvtimeo: float t
  val sndtimeo: float t
  val get: conn -> 'a t -> 'a
  val set: conn -> 'a t -> 'a -> unit
end

module Address : sig
  type t = address
  type 'a flags
  type unix
  type inet
  type name = string
  type port = string
  exception No_host

  val localhost: name
  val any_host: name
  val any_port: port

  val flags: 'a flags list -> 'a flags
  val (&&): 'a flags -> 'a flags -> 'a flags

  val unix: unix flags
  val udp: inet flags
  val tcp: inet flags
  val listen: 'a flags
  val noresolve: 'a flags

  val create: ?flags:('a flags) -> ?port:port -> name -> t Lwt.t
  val any_tcp: t
  val any_udp: t

  val of_addr_info: Unix.addr_info -> t
  val to_addr_info: t -> Unix.addr_info

  val family: t -> Unix.socket_domain
  val socktype: t -> Unix.socket_type
  val canonname: t -> string
  val to_string: t -> string

  val is_local: t -> bool
end

module Connection : sig
  open Lwt_io
  type t = conn

  val establish: address -> t Lwt.t
  val create: Lwt_unix.file_descr -> conn
  val input_channel: t -> input_channel
  val output_channel: t -> output_channel
  val getsockname: t -> Lwt_unix.sockaddr
  val getpeername: t -> Lwt_unix.sockaddr
  val get_credentials: t -> Lwt_unix.credentials
  val close: t -> unit Lwt.t
  val on_close: t -> unit Lwt.t
end

module IO : sig
  type ('a,'b) t = ('a,'b) io
  exception Protocol_error

  val create: conn ->
    get:(conn -> 'a Lwt.t) ->
    put:(conn -> 'b -> unit Lwt.t) -> ('a,'b) t

  val marshaled: ?flags:Marshal.extern_flags list -> conn -> ('a,'b) t
  val byte_stream: conn -> (char, char) t

  module type Numbers = sig
    val int_stream:     conn -> (int,   int) t
    val int32_stream:   conn -> (int32, int32) t
    val int64_stream:   conn -> (int64, int64) t
    val float32_stream: conn -> (float, float) t
    val float64_stream: conn -> (float, float) t
  end
  module BE : Numbers
  module LE : Numbers
  include Numbers

  val stream_of_io: ('a,'b) t -> 'a Lwt_stream.t * ('b option -> unit)

  module Expect : sig
    type ('a,'b) t  = ('a,'b) expect
    val const: 'a -> ('a,unit) t
    val any: ('a,'a) t
  end

  val say: ('a,'b) io -> 'b -> ('a,'c) expect -> 'c Lwt.t
  val ask: ('a,'b) io -> 'b -> ('a,'c) expect -> 'c Lwt.t
  val get: ('a,_) io -> ('a,'c) expect -> 'c Lwt.t
  val put: (_,'b) io -> 'b -> unit Lwt.t


  module Exceptionless : sig
    val say: ('a,'b) io -> 'b -> ('a,'c) expect -> 'c option Lwt.t
    val ask: ('a,'b) io -> 'b -> ('a,'c) expect -> 'c option Lwt.t
    val get: ('a,_) io -> ('a,'c) expect -> 'c option Lwt.t
    val put: (_,'b) io -> 'b -> unit Lwt.t
  end

  module Any : sig
    val say: ('a,'b) io -> 'b -> 'a Lwt.t
    val ask: ('a,'b) io -> 'b -> 'a Lwt.t
    val get: ('a,_) io -> 'a Lwt.t
    val put: (_,'b) io -> 'b -> unit Lwt.t
  end

  type buf = Lwt_bytes.t
  val read_bytes:  conn -> buf -> int -> int -> unit Lwt.t
  val write_bytes: conn -> buf -> int -> int -> unit Lwt.t
  val read_string:  conn -> string -> int -> int -> unit Lwt.t
  val write_string: conn -> string -> int -> int -> unit Lwt.t

end





