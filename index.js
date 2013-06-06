var Ber = require("asn1").Ber,// Actually need DER, but I can't find a lib for this.
	createPublicKeyBuffer,
	getPublicKeyAndExponent,
	Keypair = require("keypair"),
	writeKey,
	writePKCS1RSAHeader;

createPublicKeyBuffer = function (keypair) {
	// Keypair library gives us a regular RSA Public Key, we need just the base64 encoded section.
	var keyArray = keypair.public.split("\n"),
		keySlice = 1,
		keyString;

	while (keyArray[keyArray.length - keySlice] === "") {
		keySlice++;
	}

	keyString = keyArray.slice(1, keyArray.length - keySlice).join("");
	return new Buffer(keyString, "base64");
};

getPublicKeyAndExponent = function (keyBuffer) {
	var asnReader = new Ber.Reader(keyBuffer),
		exponent,
		key;

	asnReader.readSequence();

	// Fetch the key as a Buffer, expecting an Integer tag.
	key = asnReader.readString(Ber.Integer, true);
	exponent = asnReader.readInt();

	return {
		"exponent": exponent,
		"key": key
	};
};

writePKCS1RSAHeader = function (writer) {
	writer.startSequence();
		// PKCS OID (http://www.oid-info.com/get/1.2.840.113549.1.1.1)
		writer.writeOID("1.2.840.113549.1.1.1");
		writer.writeNull();
	writer.endSequence();
};

writeKey = function (writer, key) {
	writer.startSequence(Ber.BitString);
		// Bit Strings can be fragmented, so we need an extra Byte to say how many bits left over in the last octet.
		// In DER, fragmentation is forbidden, so this is always 0x00
		writer.writeByte(0x00);
		writer.startSequence();
			writer.writeBuffer(key.key, Ber.Integer);
			writer.writeInt(key.exponent);
		writer.endSequence();
	writer.endSequence();
};

module.exports = function () {
	var asnWriter = new Ber.Writer(),
		keypair = Keypair(),
		publicKey;

	publicKey = getPublicKeyAndExponent(createPublicKeyBuffer(keypair));

	asnWriter.startSequence();
		writePKCS1RSAHeader(asnWriter);
		writeKey(asnWriter, publicKey);
	asnWriter.endSequence();

	// Re-attach the standard public key wrapper
	return ("-----BEGIN RSA PUBLIC KEY-----\r\n" +
			asnWriter.buffer.toString("base64") +
			"\r\n-----END RSA PUBLIC KEY-----"
	);
};
