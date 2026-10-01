//// Raw authorization-response parsing (query string or form-post body).
////
//// Parsing is total and strict: duplicated parameters, a missing or empty
//// state, a missing or empty code, a response carrying both `code` and
//// `error`, oversized input and bytes outside the RFC 6749 value syntax are
//// rejected before any store is consulted.

import gleam/bit_array
import gleam/dict.{type Dict}
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string
import gleam/uri

pub const max_input_bytes = 16_384

const max_value_bytes = 4096

pub type Parsed {
  CodeResponse(state: String, code: String, issuer: Option(String))
  ErrorResponse(state: String, error: String, issuer: Option(String))
}

pub type Malformed {
  InputTooLarge
  InvalidEncoding
  DuplicateParameter
  MissingState
  MissingCode
  EmptyCode
  AmbiguousResponse
  InvalidParameterValue
}

pub fn parse(input: String, form_encoded: Bool) -> Result(Parsed, Malformed) {
  use <- guard(
    bit_array.byte_size(bit_array.from_string(input)) > max_input_bytes,
    InputTooLarge,
  )
  // Query and form body share one encoding; `form_encoded` only records
  // which one the caller received.
  let _ = form_encoded
  use pairs <- result.try(decode_pairs(input))
  use params <- result.try(unique(pairs))
  use state <- result.try(required(params, "state", MissingState))
  use issuer <- result.try(optional(params, "iss"))
  case dict.get(params, "code"), dict.get(params, "error") {
    Ok(_), Ok(_) -> Error(AmbiguousResponse)
    Ok(""), Error(_) -> Error(EmptyCode)
    Ok(code), Error(_) -> {
      use <- guard(!vschar(code), InvalidParameterValue)
      Ok(CodeResponse(state:, code:, issuer:))
    }
    Error(_), Ok(error) -> {
      use <- guard(error == "" || !nqschar(error), InvalidParameterValue)
      Ok(ErrorResponse(state:, error:, issuer:))
    }
    Error(_), Error(_) -> Error(MissingCode)
  }
}

fn guard(
  condition: Bool,
  error: e,
  next: fn() -> Result(a, e),
) -> Result(a, e) {
  case condition {
    True -> Error(error)
    False -> next()
  }
}

fn decode_pairs(input: String) -> Result(List(#(String, String)), Malformed) {
  input
  |> string.split("&")
  |> list.filter(fn(segment) { segment != "" })
  |> list.try_map(fn(segment) {
    let #(key, value) = case string.split_once(segment, "=") {
      Ok(pair) -> pair
      Error(Nil) -> #(segment, "")
    }
    use key <- result.try(decode_component(key))
    use value <- result.try(decode_component(value))
    Ok(#(key, value))
  })
}

/// `application/x-www-form-urlencoded`, for both the query and the form body
/// (RFC 6749 Appendix B): '+' is a space and every '%' starts a two-digit
/// hexadecimal escape.
fn decode_component(raw: String) -> Result(String, Malformed) {
  use <- guard(
    !escapes_well_formed(bit_array.from_string(raw)),
    InvalidEncoding,
  )
  string.replace(raw, "+", " ")
  |> uri.percent_decode
  |> result.replace_error(InvalidEncoding)
}

fn escapes_well_formed(bytes: BitArray) -> Bool {
  case bytes {
    <<>> -> True
    <<"%", a, b, rest:bytes>> -> hex(a) && hex(b) && escapes_well_formed(rest)
    <<"%", _:bytes>> -> False
    <<_, rest:bytes>> -> escapes_well_formed(rest)
    _ -> False
  }
}

fn hex(byte: Int) -> Bool {
  { byte >= 0x30 && byte <= 0x39 }
  || { byte >= 0x41 && byte <= 0x46 }
  || { byte >= 0x61 && byte <= 0x66 }
}

fn unique(
  pairs: List(#(String, String)),
) -> Result(Dict(String, String), Malformed) {
  list.try_fold(pairs, dict.new(), fn(acc, pair) {
    let #(key, value) = pair
    case dict.has_key(acc, key) {
      True -> Error(DuplicateParameter)
      False -> Ok(dict.insert(acc, key, value))
    }
  })
}

fn required(
  params: Dict(String, String),
  key: String,
  missing: Malformed,
) -> Result(String, Malformed) {
  case dict.get(params, key) {
    Ok("") | Error(Nil) -> Error(missing)
    Ok(value) ->
      case vschar(value) {
        True -> Ok(value)
        False -> Error(InvalidParameterValue)
      }
  }
}

fn optional(
  params: Dict(String, String),
  key: String,
) -> Result(Option(String), Malformed) {
  case dict.get(params, key) {
    Error(Nil) -> Ok(None)
    Ok("") -> Error(InvalidParameterValue)
    Ok(value) ->
      case vschar(value) {
        True -> Ok(Some(value))
        False -> Error(InvalidParameterValue)
      }
  }
}

/// RFC 6749 Appendix A VSCHAR (%x20-7E), bounded length.
fn vschar(value: String) -> Bool {
  let bytes = bit_array.from_string(value)
  bit_array.byte_size(bytes) <= max_value_bytes
  && all_bytes(bytes, fn(b) { b >= 0x20 && b <= 0x7E })
}

/// RFC 6749 Appendix A NQSCHAR (%x21 / %x23-5B / %x5D-7E) for `error`.
fn nqschar(value: String) -> Bool {
  let bytes = bit_array.from_string(value)
  bit_array.byte_size(bytes) <= 256
  && all_bytes(bytes, fn(b) {
    b == 0x21 || { b >= 0x23 && b <= 0x5B } || { b >= 0x5D && b <= 0x7E }
  })
}

fn all_bytes(bytes: BitArray, check: fn(Int) -> Bool) -> Bool {
  case bytes {
    <<>> -> True
    <<b, rest:bytes>> -> check(b) && all_bytes(rest, check)
    _ -> False
  }
}
