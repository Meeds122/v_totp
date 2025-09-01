module main

import time
import os { input }

import v_totp

fn main() {
	t := v_totp.new_totp('test_iss', 'test_acc')!
	println(t)
	s := input('TOTP: ')
	println(t.valid_code(s.int())!)
}