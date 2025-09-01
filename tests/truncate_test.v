import v_totp

fn test_truncate(){
	mut bytes := [u8(145), 178, 231, 186, 107, 69, 174, 5, 71, 37, 172, 10, 253, 225, 104, 30, 1, 159, 74, 22]
	assert v_totp.truncate(bytes, 6)! == u32(9)
}