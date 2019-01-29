from _sequoia import ffi, lib
from .glue import sq_str

class Error(Exception):
    @classmethod
    def _from(cls, o):
        if o == ffi.NULL:
            return MalformedValue()

        status = lib.pgp_error_status(o)
        return _status_map[status](o)

    @classmethod
    def _last(cls, ctx):
        if not ctx:
            return MalformedValue()
        return Error._from(lib.sq_context_last_error(ctx.ref()))

class MalformedValue(Error, ValueError):
    def __init__(self, message="Malformed value"):
        super(MalformedValue, self).__init__(message)

class SQError(Error):
    def __init__(self, o):
        self.__o = ffi.gc(o, lib.pgp_error_free)
        super(SQError, self).__init__(sq_str(lib.pgp_error_to_string(self.__o)))

class Success(SQError):
    pass

class UnknownError(SQError):
    pass

class NetworkPolicyViolation(SQError):
    pass

class IoError(SQError):
    pass

class InvalidOperataion(SQError):
    pass

class MalformedPacket(SQError):
    pass

class UnsupportedHashAlgorithm(SQError):
    pass

class UnsupportedSymmetricAlgorithm(SQError):
    pass

class InvalidPassword(SQError):
    pass

class InvalidSessionKey(SQError):
    pass

_status_map = {
    lib.PGP_STATUS_SUCCESS: Success,
    lib.PGP_STATUS_UNKNOWN_ERROR: UnknownError,
    lib.PGP_STATUS_NETWORK_POLICY_VIOLATION: NetworkPolicyViolation,
    lib.PGP_STATUS_IO_ERROR: IoError,
    lib.PGP_STATUS_INVALID_OPERATION: InvalidOperataion,
    lib.PGP_STATUS_MALFORMED_PACKET: MalformedPacket,
    lib.PGP_STATUS_UNSUPPORTED_HASH_ALGORITHM: UnsupportedHashAlgorithm,
    lib.PGP_STATUS_UNSUPPORTED_SYMMETRIC_ALGORITHM: UnsupportedSymmetricAlgorithm,
    lib.PGP_STATUS_INVALID_PASSWORD: InvalidPassword,
    lib.PGP_STATUS_INVALID_SESSION_KEY: InvalidSessionKey,
}
