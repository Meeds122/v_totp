module v_totp

import time
import encoding.base32
import encoding.binary
import net.http { url_encode_form_data, parse_form }
import strconv { atoi }
import math { count_digits }

import crypto.rand
import crypto.hmac
import crypto.sha1
// import crypto.sha256
// import crypto.sha512

// Number of hex digits to generate for the secret. 
// Both Arch and Gentoo's docs suggest 16 bytes.
// More is better, I think and 20 becomes 32 characters of base32 without padding.
// It also happens to be 160 bits, or, the length of the default SHA1 hash used in the HMAC algorithm.
const secret_length := 20 

const default_algorithm := 'SHA1'
const default_digits := 6
const default_period := 30

// The types are generic to both TOTP and HOTP as I was working off of specifications. 
// This library only supports TOTP because why would I support a worse, less secure alternative?

enum Type as u8 {
	totp
	hotp
}

struct Label {
	issuer_prefix 	string
	account 		string
}

pub struct TOTP {
	type 		Type		= Type.totp					// This is a TOTP module :P
	label 		Label
	secret		string
	issuer		string									// Optional. Needs to match Label.issuer_prefix if included.
	algorithm	string		= v_totp.default_algorithm	// Default is SHA1
	digits		int			= v_totp.default_digits
	period		int			= v_totp.default_period		// Optional for TOTP. Default 30
pub:
	// TOTP Are URIs which can be converted into QR Codes. See: https://wiki.archlinux.org/title/Initiative_for_Open_Authentication
	uri			string
}

// --------------------
// -- v_totp methods --
// --------------------

// TODO, generating bad codes still. Probably need to figure out an HMAC buffer of the endianness
pub fn (t TOTP) valid_code (code int) !bool {
	mut h := []u8{}
	match t.algorithm {
		'SHA1' { h = sha1_hmac(t.secret, t.period, time.now().unix()) or { return err } }
		else { return error('Error: Hash algorithm not implemented') }
	}
	generated_code := truncate(h, t.digits) or { return err }
	$dbg
	return i64(code) == i64(generated_code)
}

// Create the most basic TOTP using defaults.
pub fn new_totp (issuer string, account_name string) !TOTP {
	l := Label{
			issuer_prefix: issuer
			account: account_name
	}
	s := url_encode(base32.encode(rand.bytes(v_totp.secret_length) or { return err }).bytestr())
	
	uri_map := {
		'secret': s
		'issuer': l.issuer_prefix
		'digits': v_totp.default_digits.str()
		'algorithm': v_totp.default_algorithm
		'period': v_totp.default_period.str()
	}

	return TOTP{
		label: l
		secret: s
		issuer: l.issuer_prefix
		uri: 'otpauth://${Type.totp}/${url_encode(l.issuer_prefix)}:${url_encode(l.account)}?${url_encode_form_data(uri_map)}'
	}
}

pub fn parse_totp_uri (uri string) !TOTP {
	// Validate head is a TOTP URI
	if uri[..15] != 'otpauth://totp/' {
		return error('Error: Provided string is not TOTP URI.')
	}

	mut colon_break := 0
	mut question_break := 0
	
	for i in 15..uri.len {
		match uri[i].ascii_str() {
			':' { colon_break = i}
			'?' { question_break = i}
			else { continue }
		}
	}

	if (question_break == 0) || (colon_break == 0) {
		return error('Error: Parsing, provided string is misshaped.')
	}

	issuer := url_decode(uri[15..colon_break])
	account := url_decode(uri[colon_break+1..question_break])
	form := parse_form(uri[question_break+1..])

	return TOTP{
		label: Label{
			issuer_prefix: issuer
			account: account
		}
		secret: form['secret'] or { return error('Error: Parsing, could not parse secret') }
		issuer: form['issuer'] or { '' }
		algorithm: form['algorithm'] or { v_totp.default_algorithm }
		digits: atoi(form['digits'] or { v_totp.default_digits.str() }) or { return error('Error: Parsing, digits not int') }
		period: atoi(form['period'] or { v_totp.default_period.str() }) or { return error('Error: Parsing, period not int') }
		uri: uri
	}
}

// --------------------------
// -- RFC Based Algorithms --
// -------------------------- 

// https://www.rfc-editor.org/rfc/rfc6238
// https://www.rfc-editor.org/rfc/rfc4226

pub fn sha1_hmac (k string, period int, epoch_time i64) ![]u8 {

	if epoch_time < 0 {
		return error( 'Error: HMAC, epoch_time < 0')
	}
	// unsafe { *(&u32(a.data)) }
	t := u64((epoch_time - 0) / period)
	time_bytes := binary.big_endian_get_u64(t)
	h := hmac.new(k.bytes(), time_bytes, sha1.sum, 160)
	return h
}

// Supports all HMACs which create more than 20 bytes or 160 bits
// Supports digits 6 - 8
// Called the DT function in RFC4226 and RFC6238
pub fn truncate (h []u8, digits int) !u32 {
	if h.len < 20 {
		return error('Error: Truncate, provided hash is less than 20 bytes.')
	}
	if (digits < 6) || (digits > 8) {
		return error('Error: Truncate, digits not 6, 7, 8')
	}
	// Based on the RFC4226 algorithm. 
	offset := h[h.len-1] & 0xf
	subset := [
		h[offset] & 0x7f,
		h[offset+1],
		h[offset+2],
		h[offset+3]
	]
	compressed_subset := binary.big_endian_u32(subset)
	// math.powi returns an i64. This is faster and simpler because digits is constrained.
	mut result := u32(0)
	match digits {
		6 { result = compressed_subset % 1_000_000 }
		7 { result = compressed_subset % 10_000_000 }
		8 { result = compressed_subset % 100_000_000 }
		else { return error('Error: Truncate, digits not 6, 7, 8')}
	}
	return result
}

// --------------------------
// -- URL Encoding Helpers -- 
// --------------------------

const reserved_chars = {
	// RFC3986 Reserved
	'!': '%21'
	'#': '%23'
	'$': '%24'
	'&': '%26'
	"'": '%27'
	'(': '%28'
	')': '%29'
	'*': '%2A'
	'+': '%2B'
	',': '%2C'
	'/': '%2F'
	':': '%3A'
	';': '%3B'
	'=': '%3D'
	'?': '%3F'
	'@': '%40'
	'[': '%5B'
	']': '%5D'
	// Character data commonly URI encoded
	' ': '%20'
	'"': '%22'
	'%': '%25'
	'-': '%2D'
	'.': '%2E'
	'<': '%3C'
	'>': '%3E'
	'\\': '%5C'
	'^': '%5E'
	'_': '%5F'
	'`': '%60'
	'{': '%7B'
	'}': '%7D'
	'|': '%7C'
	'~': '%7E'
}

pub fn url_encode (text string) string {

	mut return_text := ''

	for i in 0..text.len {
		if text[i].ascii_str() in v_totp.reserved_chars.keys() {
			return_text += v_totp.reserved_chars[text[i].ascii_str()]
		}
		else {
			return_text += text[i].ascii_str()
		}
	}
	return return_text
}

pub fn url_decode (text string) string {

	mut reversed_chars := map[string]string{}

	for key, value in v_totp.reserved_chars{
		reversed_chars[value] = key
	}

	mut return_text := ''
	mut i := 0
	for i < text.len {
		if text[i].ascii_str() == '%' {
			val := '${text[i].ascii_str()}${text[i+1].ascii_str()}${text[i+2].ascii_str()}'
			return_text += reversed_chars[val] or { val } // No key found
			i += 3
		}
		else{
			return_text += text[i].ascii_str()
			i += 1
		}
	}

	return return_text
}