

// Convert a hex string to a byte array
function hexToBytes(hex) {
    for (var bytes = [], c = 0; c < hex.length; c += 2)
    bytes.push(parseInt(hex.substr(c, 2), 16));
    return bytes;
}

function byteToHex(byte) {
  // convert the possibly signed byte (-128 to 127) to an unsigned byte (0 to 255).
  // if you know, that you only deal with unsigned bytes (Uint8Array), you can omit this line
  const unsignedByte = byte & 0xff;

  // If the number can be represented with only 4 bits (0-15),
  // the hexadecimal representation of this number is only one char (0-9, a-f).
  if (unsignedByte < 16) {
    return '0' + unsignedByte.toString(16);
  } else {
    return unsignedByte.toString(16);
  }
}


var a = "ffffffffffff88e640ba80170806000108000604000188e640ba80170a1150010000000000000a1153d3";
var b = new Uint8Array(hexToBytes(a));

class SimpleField {
	toString() {
		return this.data.toString();
	}
}

class Byte extends SimpleField {
	constructor (inp) {
		super();
		this.data = inp[0];
		this.length = 1;
	}
}

class Short extends SimpleField {
	constructor (inp) {
		super();
		this.data = inp[0]*256 + inp[1];
		this.length = 2;
	}
}

class MAC extends SimpleField {
	constructor (inp) {
		super();
		var res = "";
		for (var i = 0; i < 6; i++) {
			if (i !== 0)
				res += ":";
			res += byteToHex(inp[i]);
		}
		this.data = res;
		this.length = 6;
	}
}

class IP extends SimpleField {
	constructor (inp) {
		super();
		var res = "";
		for (var i = 0; i < 4; i++) {
			if (i !== 0)
				res += ".";
			res += inp[i].toString();
		}
		this.data = res;
		this.length = 4;
	}
}

function readPacket(data, fields) {
	var idx = 0;
	var fieldResults = [];
	var ref;

	for (var field of fields) {
		ref = data.slice(idx);

		var res = new field(ref);
		fieldResults.push(res);
		idx += res.length;
	}
	ref = data.slice(idx);
	return [fieldResults, ref];
}

function genFields(f, names) {
	var i = 0;
	var res = {};
	for (var name of names) {
		res[name] = f[i].data;
		i++;
	}
	return res;
}

function readPacketObj(data, descr) {
	var [res, dataNew] = readPacket(data, Object.values(descr));
	var fields = genFields(res, Object.keys(descr));

	return [fields, dataNew];
}

function readArp(data) {
	var [fields, _] = readPacketObj(data, {
		hwType: Short,
		protocolType: Short,
		hwSize: Byte,
		protocolSize: Byte,
		opcode: Short,
		senderMAC: MAC,
		senderIP: IP,
		targetMAC: MAC,
		targetIP: IP
	});

	return [fields, null, null];
}

function readEther(data) {
	var [fields, dataNew] = readPacketObj(data, {
		dest: MAC,
		src: MAC,
		type: Short
	});

	var next = null;

	if (fields.type === 0x0806)
		next = readArp;

	return [fields, dataNew, next]
}

var data = b;

var fun = readEther;

while (fun !== null) {
	// console.log(data);
	var [fields, data, fun] = fun(data);
	console.log(fields);
}
