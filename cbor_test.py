from cbor2 import loads
payload = '81bf626469782433313331333133312d333133312d333133312d333133312d333133313331333133313331656c696e6b7385a464687265666d2f6f69632f7365632f646f786d627274816a6f69632e722e646f786d626966816f6f69632e69662e626173656c696e656170bf62626d0163736563f4ffa464687265666e2f6f69632f7365632f7073746174627274816b6f69632e722e7073746174626966816f6f69632e69662e626173656c696e656170bf62626d0163736563f4ffa46468726566662f6f69632f6462727481686f69632e776b2e64626966826f6f69632e69662e626173656c696e65686f69632e69662e726170bf62626d0163736563f4ffa46468726566662f6f69632f7062727481686f69632e776b2e70626966826f6f69632e69662e626173656c696e65686f69632e69662e726170bf62626d0163736563f4ffa46468726566682f612f6c69676874627274826a636f72652e6c6967687470636f72652e6272696768746c69676874626966826f6f69632e69662e626173656c696e65696f69632e69662e6c6c6170bf62626d0363736563f4ffff'
# payload = 'bf636e6f6e1a1a89ddbc6374746c181e63747267e06272746a636f72652e6c69676874ff' # parses as a dictionary containing a resource type, but not an href field.
# payload = 'e1fedbc0'
# payload = '81bf626469782466393132383163382d373632662d343030642d386264332d383234613236366331653333656c696e6b7385a464687265666d2f6f69632f7365632f646f786d627274816a6f69632e722e646f786d626966816f6f69632e69662e626173656c696e656170bf62626d0163736563f4ffa464687265666e2f6f69632f7365632f7073746174627274816b6f69632e722e7073746174626966816f6f69632e69662e626173656c696e656170bf62626d0163736563f4ffa46468726566662f6f69632f6462727481686f69632e776b2e64626966826f6f69632e69662e626173656c696e65686f69632e69662e726170bf62626d0163736563f4ffa46468726566662f6f69632f7062727481686f69632e776b2e70626966826f6f69632e69662e626173656c696e65686f69632e69662e726170bf62626d0163736563f4ffa46468726566682f612f6c69676874627274816a636f72652e6c69676874626966816f6f69632e69662e626173656c696e656170bf62626d0363736563f4ffff'
# payload = 'bf636e6f6e1a33cd532f6374746c181e63747267e0627274696f69632e776b2e6164ff'
payload_object = loads(bytes.fromhex(payload))
# print(repr(payload_object))
for link in payload_object[0]['links']:
    print(repr(link))
