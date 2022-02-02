#ifndef TBQUIC_QUIC_ERROR_H_
#define TBQUIC_QUIC_ERROR_H_

//RFC 9000 Section 20
/*
 * An endpoint uses this with CONNECTION_CLOSE to signal that the connection is
 *      being closed abruptly in the absence of any error.
 */
#define QUIC_ERR_NO_ERROR (0x00)

/*
 * The endpoint encountered an internal error
 *      and cannot continue with the connection.
 */
#define QUIC_ERR_INTERNAL_ERROR (0x01)

/*
 * The server refused to accept a new connection.
 */
#define QUIC_ERR_CONNECTION_REFUSED (0x02)

/*
 * An endpoint received more data than it permitted in its advertised
 *      data limits.
 */
#define QUIC_ERR_FLOW_CONTROL_ERROR (0x03)

/*
 * An endpoint received a frame for a stream identifier that exceeded its
 *      advertised stream limit for the corresponding stream type.
 */
#define QUIC_ERR_STREAM_LIMIT_ERROR (0x04)

/*
 * An endpoint received a frame for a stream that was not in a state that
 *      permitted that frame
 */
#define QUIC_ERR_STREAM_STATE_ERROR (0x05)

/*
 * (1) An endpoint received a STREAM frame containing data that exceeded the
 *      previously established final size, 
 * (2) an endpoint received a STREAM frame or a RESET_STREAM frame containing
 *      a final size that was lower than the size of stream data that was
 *      already received, or
 * (3) an endpoint received a STREAM frame or a RESET_STREAM frame containing
 *      a different final size to the one already established.
 */
#define QUIC_ERR_FINAL_SIZE_ERROR (0x06)

/*
 * An endpoint received a frame that was badly formatted -- for instance,
 *      a frame of an unknown type or an ACK frame that has more
 *      acknowledgment ranges than the remainder of the packet could carry.
 */
#define QUIC_ERR_FRAME_ENCODING_ERROR (0x07)

/*
 * An endpoint received transport parameters that were badly formatted,
 *      included an invalid value, omitted a mandatory transport parameter,
 *      included a forbidden transport parameter, or were otherwise in error.
 */
#define QUIC_ERR_TRANSPORT_PARAMETER_ERROR (0x08)

/*
 * The number of connection IDs provided by the peer exceeds the advertised
 *      active_connection_id_limit.
 */
#define QUIC_ERR_CONNECTION_ID_LIMIT_ERROR (0x09)

/*
 * An endpoint detected an error with protocol compliance that was not covered
 *      by more specific error codes.
 */
#define QUIC_ERR_PROTOCOL_VIOLATION (0x0a)

/*
 * A server received a client Initial that contained an invalid Token field.
 */
#define QUIC_ERR_INVALID_TOKEN (0x0b)

/*
 * The application or application protocol caused the connection to be closed.
 */
#define QUIC_ERR_APPLICATION_ERROR (0x0c)

/*
 * An endpoint has received more data in CRYPTO frames than it can buffer.
 */
#define QUIC_ERR_CRYPTO_BUFFER_EXCEEDED (0x0d)

/*
 * An endpoint detected errors in performing key updates,
 */
#define QUIC_ERR_KEY_UPDATE_ERROR (0x0e)

/*
 * An endpoint has reached the confidentiality or integrity limit for the
 *      AEAD algorithm used by the given connection.
 */
#define QUIC_ERR_AEAD_LIMIT_REACHED (0x0f)

/*
 * An endpoint has determined that the network path is incapable of
 *      supporting QUIC.  An endpoint is unlikely to receive a
 *      CONNECTION_CLOSE frame carrying this code except when
 *      the path does not support a large enough MTU.
 */
#define QUIC_ERR_NO_VIABLE_PATH (0x10)

/*
   CRYPTO_ERROR (0x0100-0x01ff):  The cryptographic handshake failed.  A
      range of 256 values is reserved for carrying error codes specific
      to the cryptographic handshake that is used.  Codes for errors
      occurring when TLS is used for the cryptographic handshake are
      described in Section 4.8 of [QUIC-TLS].
*/


#endif
