import v_totp

fn test_totp_gen_and_parse(){
	t := v_totp.new_totp('Test Corp', 'testuser')!
	assert t.uri.len > 0
	p := v_totp.parse_totp_uri(t.uri)!
	assert p.uri.len > 0
}