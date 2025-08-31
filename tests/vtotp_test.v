import v_totp

fn test_url_encode() {
	assert v_totp.url_encode('This should be URL Encoded :) LOL') == 'This%20should%20be%20URL%20Encoded%20%3A%29%20LOL'
}