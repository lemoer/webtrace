

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


var packets = [
	new Uint8Array(hexToBytes("ffffffffffff88e640ba80170806000108000604000188e640ba80170a1150010000000000000a1153d3")),
	new Uint8Array(hexToBytes("33330000000188e640baa01786dd600366fe00703afffe800000000000008ae640fffebaa017ff020000000000000000000000000001860081ff4000012c0000000000000000030440c00000012c00000096000000002a02079000ff10170000000000000000030440c00000012c0000009600000000fdcaffee00080017000000000000000019030000000000c8fdcaffee000800170000000000000001010188e640baa017"))
];

class SimpleField {
	toString() {
		return this.data.toString();
	}
}

function Const(ret)  {
	return class extends SimpleField {
		constructor (inp) {
			super();
			this.data = ret;
			this.length = 0;
		}
	};
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

class Word extends SimpleField {
	constructor (inp) {
		super();
		this.data = inp[0]*(256**3) + inp[1]*(256**2) + inp[2]*(256**1) + inp[3];
		this.length = 4;
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

class IP6 extends SimpleField {
	constructor (inp) {
		super();
		var res = "";
		for (var i = 0; i < 16; i++) {
			if (i !== 0 && i % 2 == 0)
				res += ":";
			res += byteToHex(inp[i]);
		}
		this.data = res;
		this.length = 16;
	}
}

function readStream(data, fields) {
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

function readStreamObj(data, descr) {
	var [res, dataNew] = readStream(data, Object.values(descr));
	var fields = genFields(res, Object.keys(descr));

	return [fields, dataNew];
}

function readArp(data) {
	var [fields, _] = readStreamObj(data, {
		layerName: Const("ARP"),
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

function readIP6(data) {
	var [fields, dataNew] = readStreamObj(data, {
		layerName: Const("IPv6"),
		version_trafficClass_flowLabel: Word,
		payloadLength: Short,
		nextHeader: Byte,
		hopLimit: Byte,
		srcIP6: IP6,
		destIP6: IP6
	});

	return [fields, dataNew, readUnknown];
}

function readUnknown(data) {
	var fields = {
		layerName: "Unknown Payload",
		length: data.length
	};

	return [fields, null, null];
}

function readEther(data) {
	var [fields, dataNew] = readStreamObj(data, {
		layerName: Const("Ethernet"),
		dest: MAC,
		src: MAC,
		type: Short
	});

	var next = readUnknown;

	switch (fields.type) {
		case 0x0806:
			next = readArp;
			break;
		case 0x86dd:
			next = readIP6;
			break;
	}

	return [fields, dataNew, next]
}

function readPacket(data) {
	var fun = readEther;

	while (fun !== null) {
		// console.log(data);
		var [fields, data, fun] = fun(data);
		console.log(fields);
	}
}

function getPacketProto(data) {
	var fun = readEther;
	var fields = "Unknown Payload";

	while (fun !== null) {
		var [fieldsNew, data, fun] = fun(data);

		if (fieldsNew.layerName !== "Unknown Payload")
			fields = fieldsNew;
	}

	return fields.layerName;
}

for (var pkt of packets) {
	console.log(getPacketProto(pkt) + ":");
	readPacket(pkt);
	console.log("------");
}
