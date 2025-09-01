import v_totp

fn test_truncate(){
	mut bytes := [u8(145), 178, 231, 186, 107, 69, 174, 5, 71, 37, 172, 10, 253, 225, 104, 30, 1, 159, 74, 22]
	assert v_totp.truncate(bytes, 6)! == u32(97829)
	assert v_totp.truncate(bytes, 7)! == u32(2097829)
	assert v_totp.truncate(bytes, 8)! == u32(72097829)
}