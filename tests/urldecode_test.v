import v_totp

fn test_url_decode() {
	assert v_totp.url_decode('This%20should%20be%20URL%20Encoded%20%3A%29%20LOL') == 'This should be URL Encoded :) LOL'
}