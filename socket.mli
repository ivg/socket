(** High-level library dealing with low-level sockets. *)

type server
(** a server  *)

type conn
(** a connection handler *)

type address = Unix.addr_info
(** address of a socket  *)

type ('a,'b) expect = 'a -> 'b option
(** value inspector.
    tries to inject value of type ['a] to type ['b]
*)

type ('a,'b) io
(** a type-safe buffered input/output channel.  That reads values of
    type ['a] and writes values of type ['b] *)

val listen: ?max_queue:int -> address -> (conn -> unit Lwt.t) -> server
(** [listen address on_connection] establishes a server at the
    specified [address]. On each new connection function
    [on_connection] is called. *)

val establish_server:
  address ->
  (Lwt_io.input_channel * Lwt_io.output_channel -> unit Lwt.t) ->
  server
(** [establish_server address on_connection] establishes a server at
    the specified [address]. On each new connection function
    [on_connection] is called.  *)

val connect: address -> conn Lwt.t
(** [connect address] establishes a connection to the specified
    [address] *)

val shutdown: server -> unit
(** [shutdown server] stops listening and closes all active
    connections  *)

val server_address: server -> address
(** [server_address server] returns an address on which the [server]
    is listening *)

val clients: server -> int
(** [clients server] returns current number of clients of the
    [server] *)

(** Socket options  *)
module Options : sig
  type 'a t
  (** Abstract socket option  *)

  val get: conn -> 'a t -> 'a
  (** [get conn option] retrieve the value of socket [option] *)

  val set: conn -> 'a t -> 'a -> unit
  (** [set conn option value] set the [value] of socket [option] *)

  (** {4 Options}  *)
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
end

(** Socket addresses  *)
module Address : sig
  type t = address

  type 'a flags
  (** address flags  *)

  (** {4 Address families}  *)
  type unix    (** AF_UNIX  *)
  type inet    (** AF_INET  *)

  type name = string
  type port = string

  exception No_host
  (** [No_host] when a specified address doesn't specify a host *)

  val create: ?flags:('a flags) -> ?port:port -> name -> t Lwt.t
  (** [create ~flags ~port name] resolves [name] (and optional [port])
      against specified set of flags. Raises [No_host] if name is
      unresolvable.  *)

  (** {4 Predefined addresses}  *)
  val any_tcp: t
  (** a listening address on an unspecified tcp port *)

  val any_udp: t
  (** a listening address on an unspecified udp port *)

  (** {4 Conversions to and from Unix.addr_info}  *)
  val of_addr_info: Unix.addr_info -> t
  val to_addr_info: t -> Unix.addr_info

  (** {4 Address accessors}  *)
  val family: t -> Unix.socket_domain
  val socktype: t -> Unix.socket_type
  val canonname: t -> string

  val to_string: t -> string
  (** pretty-prints address to string  *)

  (** {4 Some predefined hosts and ports}  *)

  val localhost: name     (** A localhost  *)
  val any_host: name      (** Any host (usefull for servers) *)
  val any_port: port      (** Any port (usefull for servers) *)

  (** {4 Flag combinators}  *)

  val flags: 'a flags list -> 'a flags
  (** [flags flag_list] combines [flag_list] to a sigle flag.  *)

  val (&&): 'a flags -> 'a flags -> 'a flags
  (** [flag1 && flag2] combines two flags  *)

  (** {4 Predefined flags}  *)

  val unix: unix flags
  (** [unix] unix-family socket  *)

  val udp: inet flags
  (** [udp] udp socket of the inet family  *)

  val tcp: inet flags
  (** [tcp] tcp socket of the inet family  *)

  val listen: 'a flags
  (** a listening socket  *)

  val noresolve: 'a flags
  (** do not resolve names  *)

  val is_local: t -> bool
  (** [is_local address] is true if address is a some kind of
      localhost address (unix sockets are considered local too)
  *)
end

(** Connection operations  *)
module Connection : sig
  open Lwt_io
  type t = conn

  val establish: address -> t Lwt.t
  (** [establish addr] is the synonym to [connect] *)
  val create: Lwt_unix.file_descr -> conn
  (** [create fd] creates a connection from a file descriptor
      [fd]. Note: it is better not *)

  val input_channel: t -> input_channel
  (** [input_channel connection] creates an input channel from the
      [connection] *)
  val output_channel: t -> output_channel
  (** [output_channel connection] creates an output channel from the
      [connection] *)

  val getsockname: t -> Lwt_unix.sockaddr
  (** returns a socket address of a local end  *)

  val getpeername: t -> Lwt_unix.sockaddr
  (** returns a socket address of a remote end  *)

  val get_credentials: t -> Lwt_unix.credentials
  (** returns a credentials, assosiated with a connection  *)

  val close: t -> unit Lwt.t
  (** closes connection, properly shutting down a session  *)

  val on_close: t -> unit Lwt.t
  (** a thread that will terminate when the connection is closed  *)

end

(** Type-safe input/output  *)
module IO : sig

  type ('a,'b) t = ('a,'b) io
  (** a duplex channel, that produces values of type ['a] and consumes
  values of type ['b]  *)


  exception Protocol_error
  (** this exception should be thrown in a case of protocol
      violations.  *)

  val create: conn ->
    get:(conn -> 'a Lwt.t) ->
    put:(conn -> 'b -> unit Lwt.t) -> ('a,'b) t
  (** [create conn ~get ~put] a generic funciton to create io
      channels. Function [get] and [put] are used to receive and send
      data from a connection. *)

  val marshaled: ?flags:Marshal.extern_flags list -> conn -> ('a,'b) t
  (** [marshaled ~flags conn] created i/o channel using default OCaml
      marshalizer *)

  val byte_stream: conn -> (char, char) t
  (** [byte_stream conn] a byte channel.  *)

  (** Number channels  *)
  module type Numbers = sig
    val int_stream:     conn -> (int,   int) t
    val int32_stream:   conn -> (int32, int32) t
    val int64_stream:   conn -> (int64, int64) t
    val float32_stream: conn -> (float, float) t
    val float64_stream: conn -> (float, float) t
  end

  (** Big endian *)
  module BE : Numbers
  (** Little endian  *)
  module LE : Numbers

  (** Native endian  *)
  include Numbers

  val stream_of_io: ?on_error:(exn -> unit Lwt.t) ->
    ('a,'b) t -> 'a Lwt_stream.t * ('b option -> unit)
  (** [stream_of_io ~on_error io] converts an i/o channel to
      Lwt_stream.t *)

  (** Protocol inspectors.  *)
  module Expect : sig
    type ('a,'b) t  = ('a,'b) expect
    val const: 'a -> ('a,unit) t
    (** [const v] expects value [v] *)
    val any: ('a,'a) t
    (** [any] expects any value  *)
  end

  (** {4 High-level dialogs, using i/o channels}  *)
  val say: ('a,'b) io -> 'b -> ('a,'c) expect -> 'c Lwt.t
  (** [say io request expect] says a [request] and expects a response
      by [expect] *)
  val ask: ('a,'b) io -> 'b -> ('a,'c) expect -> 'c Lwt.t
  (** [ask io response expect] expects a request from a remote peer
      and replies by a response.  *)
  val get: ('a,_) io -> ('a,'c) expect -> 'c Lwt.t
  (** [get io expect] get a value expecting [expect] *)
  val put: (_,'b) io -> 'b -> unit Lwt.t
  (** [put io value] puts a value to channel  *)

  (** Dialogs that do not raise exceptions  *)
  module Exceptionless : sig
    val say: ('a,'b) io -> 'b -> ('a,'c) expect -> 'c option Lwt.t
    val ask: ('a,'b) io -> 'b -> ('a,'c) expect -> 'c option Lwt.t
    val get: ('a,_) io -> ('a,'c) expect -> 'c option Lwt.t
    val put: (_,'b) io -> 'b -> unit Lwt.t
  end

  (** Straigt-forward dialogs without expects   *)
  module Any : sig
    val say: ('a,'b) io -> 'b -> 'a Lwt.t
    val ask: ('a,'b) io -> 'b -> 'a Lwt.t
    val get: ('a,_) io -> 'a Lwt.t
    val put: (_,'b) io -> 'b -> unit Lwt.t
  end
end


(** { 4 Direct unbuffered i/o } *)

type buf = Lwt_bytes.t
(** default buffer  *)

val read_bytes:  conn -> buf -> int -> int -> unit Lwt.t
(** [read_bytes conn buf off len] reads [len] bytes from [conn] and
    copy them to [buf] starting with offset [off].  *)

val write_bytes: conn -> buf -> int -> int -> unit Lwt.t
(** [write_bytes conn buf off len] write [len] bytes from buffer
    [buf], starting with offset [off] to connection [conn] *)

val read_string:  conn -> string -> int -> int -> unit Lwt.t
(** [read_string conn buf off len] reads [len] bytes from [conn] and
    copy them to [buf] starting with offset [off].  *)

val write_string: conn -> string -> int -> int -> unit Lwt.t
(** [write_string conn buf off len] write [len] bytes from buffer
    [buf], starting with offset [off] to connection [conn] *)





