import os, sys
import requests
import time, datetime
import asyncio, aiohttp
import base64, json, jwt

from protobuf import *
from protobuf.change_wishlist_pb2 import *
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from google.protobuf.timestamp_pb2 import Timestamp
from protobuf_decoder.protobuf_decoder import Parser


class AddFr:
	def __init__(self):
		pass
	
	
	def fix_hex(self, hex):
		hex = hex.lower().replace(" ", "")
		
		return hex
	
	
	def dec_to_hex(self, decimal):
		decimal = hex(decimal)
		final_result = str(decimal)[2:]
		if len(final_result) == 1:
			final_result = "0" + final_result
			return final_result
		
		else:
			return final_result
	
	
	def encode_varint(self, number):
		if number < 0:
			raise ValueError("Number must be non-negative")
		
		encoded_bytes = []
		
		while True:
			byte = number & 0x7F
			number >>= 7
		
			if number:
				byte |= 0x80
			encoded_bytes.append(byte)
			
			if not number:
				break
		
		return bytes(encoded_bytes)
	
	
	def create_varint_field(self, field_number, value):
		field_header = (field_number << 3) | 0# Varint wire type is 0
		return self.encode_varint(field_header) + self.encode_varint(value)
	
	
	def create_length_delimited_field(self, field_number, value):
		field_header = (field_number << 3) | 2# Length-delimited wire type is 2
		encoded_value = value.encode() if isinstance(value, str) else value
		return self.encode_varint(field_header) + self.encode_varint(len(encoded_value)) + encoded_value
	
	
	def create_protobuf_packet(self, fields):
		packet = bytearray()
		
		for field, value in fields.items():
			if isinstance(value, dict):
				nested_packet = self.create_protobuf_packet(value)
				packet.extend(self.create_length_delimited_field(field, nested_packet))
			
			elif isinstance(value, int):
				packet.extend(self.create_varint_field(field, value))
			
			elif isinstance(value, str) or isinstance(value, bytes):
				packet.extend(self.create_length_delimited_field(field, value))
		
		return packet
	
	
	def parse_my_message(self, serialized_data):
		# Parse the serialized data into a MyMessage object
		my_message = my_message_pb2.MyMessage()
		my_message.ParseFromString(serialized_data)
		
		# Extract the fields
		timestamp = my_message.field21
		key = my_message.field22
		iv = my_message.field23
		
		# Convert timestamp to a single integer
		timestamp_obj = Timestamp()
		timestamp_obj.FromNanoseconds(timestamp)
		timestamp_seconds = timestamp_obj.seconds
		timestamp_nanos = timestamp_obj.nanos
		
		# Combine seconds and nanoseconds into a single integer
		combined_timestamp = timestamp_seconds * 1_000_000_000 + timestamp_nanos
		
		return combined_timestamp, key, iv
	
	
	def parse_results(self, parsed_results):
		result_dict = {}
		
		for result in parsed_results:
			field_data = {}
			field_data["wire_type"] = result.wire_type
			
			if result.wire_type == "varint":
				field_data["data"] = result.data
			
			if result.wire_type == "string":
				field_data["data"] = result.data
			
			if result.wire_type == "bytes":
				field_data["data"] = result.data
			
			elif result.wire_type == "length_delimited":
				field_data["data"] = self.parse_results(result.data.results)
			
			result_dict[result.field] = field_data
		
		return result_dict
	
	
	def parsed_results_to_dict(self, parsed_results):
		result_dict = {}
		for parsed_result in parsed_results.results:
			if hasattr(parsed_result.data, "results"):
				result_dict[parsed_result.field] = self.parsed_results_to_dict(parsed_result.data)
			
			else:
				result_dict[parsed_result.field] = parsed_result.data
	
		return result_dict
	
	
	def Decrypt_API(self, cipher_text):
		key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
		iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
		cipher = AES.new(key, AES.MODE_CBC, iv)
		plain_text = unpad(cipher.decrypt(bytes.fromhex(cipher_text)), AES.block_size)
		
		return plain_text.hex()
	
	
	def Encrypt_API(self, plain_text):
		plain_text = bytes.fromhex(plain_text)
		key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
		iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
		cipher = AES.new(key, AES.MODE_CBC, iv)
		cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
		
		return cipher_text.hex()
	
	
	def Decrypt_Packet(self, packet, key, iv):
		packet = bytes.fromhex(packet)
		key, iv = key, iv
		cipher = AES.new(key, AES.MODE_CBC, iv)
		plain_text = unpad(cipher.decrypt(packet), AES.block_size)
		
		return plain_text.hex()
	
	
	def Encrypt_Packet(self, plain_text, key, iv):
		plain_text = bytes.fromhex(plain_text)
		key, iv = key, iv
		cipher = AES.new(key, AES.MODE_CBC, iv)
		cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
		
		return cipher_text.hex()
	
	
	def Decrypt_ID(self, encoded_bytes):
		encoded_bytes = bytes.fromhex(encoded_bytes)
		number, shift = 0, 0
		
		for byte in encoded_bytes:
			value = byte & 0x7F
			number |= value << shift
			shift += 7
			
			if not byte & 0x80:
				break
			
		return number
	
	
	def Encrypt_ID(self, number):
		number = int(number)
		encoded_bytes = []
		
		while True:
			byte = number & 0x7F
			number >>= 7
			
			if number:
				byte |= 0x80
			encoded_bytes.append(byte)
			
			if not number:
				break
		
		return bytes(encoded_bytes).hex()
	
	

	def RequestAddingFriend(self, account_id, player_id, token):
		fields = {
			1: int(account_id),
			2: int(player_id),
			3: 3
		}
		
		payload = self.create_protobuf_packet(fields)
		payload = payload.hex()
		payload = self.Encrypt_API(payload)
		payload = bytes.fromhex(payload)
		
		headers = {
			"Expect": "100-continue",
			"Authorization": "Bearer " + token,
			"X-Unity-Version": "2018.4.11f1",
			"X-GA": "v1 1",
			"ReleaseVersion": "OB49",
			"Connection": "Close",
			"Content-Type": "application/x-www-form-urlencoded",
			"Content-Length": str(len(payload)),
			"User-Agent": "Dalvik/2.1.0 (Linux; U; Android 10; RMX1821 Build/QP1A.190711.020)",
			"Host": "clientbp.ggblueshark.com",
			"Accept-Encoding": "gzip"
		}
		
		response = requests.post("https://clientbp.ggblueshark.com/RequestAddingFriend", headers=headers, data=payload)
		
		return response.content