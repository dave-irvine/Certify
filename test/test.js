var assert = require("assert"),
	Ber = require("../node_modules/asn1").Ber,
	Certify = require("../index.js");

describe("Certify", function () {
	describe("certify()", function () {
		var key;

		before(function () {
			key = Certify();
		});

		it("should return a string", function () {
			assert.equal(typeof(key), "string");
		});

		describe("X.509", function () {
			var reader;

			before(function () {
				var buff,
					keyArr = key.split("\n"),
					keyStr = keyArr.slice(1, keyArr.length - 1).join("");

				buff = new Buffer(keyStr, "base64");
				reader = new Ber.Reader(buff);
				reader.readSequence();
			});

			describe("SubjectPublicKeyInfo", function () {
				var peek;

				before(function () {
					reader.readSequence();
				});

				it("should contain an OID", function () {
					peek = reader.peek();

					assert.equal(peek, Ber.OID);
				});

				it("should contain the proper OID for PKCS1", function () {
					var oid = reader.readOID();
					assert.equal(oid, "1.2.840.113549.1.1.1");
				});

				it("should contain a Null", function () {
					peek = reader.peek();

					assert.equal(peek, Ber.Null);

					// Read the byte because peek does not.
					reader.readByte();
					// Read into the next byte.
					reader.readByte();
				});

				it("should contain a BitString", function () {
					peek = reader.peek();

					assert.equal(peek, Ber.BitString);
					// Read BitString sequence.
					reader.readSequence();
					reader.readByte();
				});

				describe("SubjectPublicKey", function () {
					before(function () {
						reader.readSequence();
					});

					it("should contain an Int representation of the Key", function () {
						peek = reader.peek();

						assert.equal(peek, Ber.Integer);

						// Read Integer as a String
						reader.readString(Ber.Integer);
					});

					it("should contain an Int representation of the Exponent", function () {
						peek = reader.peek();

						assert.equal(peek, Ber.Integer);
					});

					it("should have the default Exponent", function () {
						var exponent = reader.readInt();

						assert.equal(exponent, 65537);
					});
				});
			});
		});
	});
});