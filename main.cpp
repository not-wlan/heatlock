#include "IceKey.h"

#include <cstdio>
#include <cstdint>
#include <vector>
#include <fstream>
#include <iterator>
#include <algorithm>

#include <phnt_windows.h>
#include <phnt.h>

#pragma comment(lib, "ntdll.lib")
#define INRANGE(x,a,b)		(x >= a && x <= b) 
#define getBits( x )		(INRANGE(x,'0','9') ? (x - '0') : ((x&(~0x20)) - 'A' + 0xa))
#define getByte( x )		(getBits(x[0]) << 4 | getBits(x[1]))

// Credits: learn_more
PBYTE find_pattern(const PBYTE rangeStart, const PBYTE rangeEnd, const char* pattern)
{
	const unsigned char* pat = reinterpret_cast<const unsigned char*>(pattern);
	PBYTE firstMatch = 0;
	for (PBYTE pCur = rangeStart; pCur < rangeEnd; ++pCur) {
		if (*(PBYTE)pat == (BYTE)'\?' || *pCur == getByte(pat)) {
			if (!firstMatch) {
				firstMatch = pCur;
			}
			pat += (*(PWORD)pat == (WORD)'\?\?' || *(PBYTE)pat != (BYTE)'\?') ? 3 : 2;
			if (!*pat) {
				return firstMatch;
			}
		}
		else if (firstMatch) {
			pCur = firstMatch;
			pat = reinterpret_cast<const unsigned char*>(pattern);
			firstMatch = 0;
		}
	}
	return NULL;
}

int main(int argc, char** argv) {
	if (argc != 3) {
		std::puts("usage: heatlock.exe <vac module> <ice key>");
		return EXIT_FAILURE;
	}

	std::vector<uint8_t> buffer{};
	uint8_t raw_key[8] = {};

	// TODO: Find out if there's a better way of parsing this...
	auto converted = sscanf_s(argv[2], "%02hhX %02hhX %02hhX %02hhX %02hhX %02hhX %02hhX %02hhX", 
		&raw_key[0],
		&raw_key[1],
		&raw_key[2],
		&raw_key[3],
		&raw_key[4],
		&raw_key[5],
		&raw_key[6],
		&raw_key[7]
	);

	if(converted != 8) {
		std::puts("usage: heatlock.exe <vac module> <ice key>");
		return EXIT_FAILURE;
	}

	if (auto stream = std::ifstream{ argv[1], std::ios_base::binary | std::ios_base::in }; stream.good()) {
		// Load the module into a buffer so we can run our transformations on it
		stream.unsetf(std::ios_base::skipws);
		buffer.insert(buffer.begin(), std::istream_iterator<std::uint8_t>{stream},
			std::istream_iterator<std::uint8_t>{});
	} else {
		std::fprintf(stderr, "[!] Couldn't open \"%s\"!", argv[1]);
		return EXIT_FAILURE;
	}

	// All VAC modules use a n of 1
	IceKey k{ 1 };

	// Load the modules as a mapped image so we can do our pointer math easier.
	// This is harmless since VAC modules don't have an entry point set and won't do
	// anything unless you call _runfunc@20 explicitly.
	const auto handle = LoadLibraryA(argv[1]);

	DWORD size;
	if(const auto nt_headers = RtlImageNtHeader(handle)) {
		size = nt_headers->OptionalHeader.SizeOfImage;
	} else {
		std::fprintf(stderr, "[!] \"%s\" is not a valid VAC module!\n", argv[1]);
		return EXIT_FAILURE;
	}

	auto encrypted_size = (DWORD*)find_pattern((PBYTE)handle, (PBYTE)handle + size, "68 ? ? ? ? 8B D1");

	if(encrypted_size == nullptr) {
		std::fprintf(stderr, "[!] Couldn't get encrypted payload size...\n");
		return EXIT_FAILURE;
	}

	encrypted_size = (DWORD*)(((uintptr_t)encrypted_size) + 1);
	std::printf("[+] Encryptded size: 0x%08lX\n", *encrypted_size);

	auto encrypted_payload = find_pattern((PBYTE)handle, (PBYTE)handle + size, "B9 ? ? ? ? 68");

	if (encrypted_payload == nullptr) {
		std::fprintf(stderr, "[!] Couldn't get encrypted payload...\n");
		return EXIT_FAILURE;
	}

	encrypted_payload += 1;
	encrypted_payload = (PBYTE)*(DWORD*)encrypted_payload;
	std::printf("[+] Encrypted payload: 0x%p\n", encrypted_payload);

	auto ice_key = find_pattern((PBYTE)handle, (PBYTE)handle + size, "A3 ? ? ? ? C7");

	if (ice_key == nullptr) {
		std::fprintf(stderr, "[!] Couldn't get primary ice key...\n");
		return EXIT_FAILURE;
	}

	ice_key += 1;
	ice_key = (PBYTE)*(DWORD*)ice_key;
	ice_key += 0x10;

	std::printf("[+] Primary ICE key: ");
	for (auto i = 0u; i < 8; i++) {
		std::printf("%02hhX ", ice_key[i]);
	}

	// Set the primary ICE key as current key
	k.set(ice_key);
	// Decrypt the secondary ICE key from the runfunc
	k.decrypt(&raw_key[0], &raw_key[0]);

	std::printf("\n[+] Secondary ICE key: ");
	for (auto && i : raw_key) {
		std::printf("%02hhX ", i);
	}

	// There's no integrity check so we'll just have to trust that it worked.
	k.set(raw_key);

	// Search for the encrypted payload in the file
	// This is pretty slow and can probably be replaced with a few simple PE tricks
	const auto result = std::search(buffer.begin(), buffer.end(), &encrypted_payload[0], &encrypted_payload[*encrypted_size]);

	// Decrypt the payload in the memory mapped file we loaded with LoadLibrary
	// This is fine since the section is writable. This is actually how the VAC module does it too.
	// We iterate with steps of 8 since that's the blocksize of the ICE encryption.
	for (auto i = 0u; i < *encrypted_size; i += 8) {
		k.decrypt(&encrypted_payload[i], &encrypted_payload[i]);
	}

	if (result != std::end(buffer)) {
		std::memcpy(&*result, &encrypted_payload[0], *encrypted_size);
		auto outfile = std::string{ argv[1] } + ".decr.dll";
		if(auto out = std::ofstream{outfile, std::ios_base::binary | std::ios_base::out}; out.good()) {
			out.write(
				reinterpret_cast<const char*>(&buffer[0]),
				buffer.size()
			);
		} else {
			std::fprintf(stderr, "[!] Couldn't write to file \"%s\"\n", outfile.c_str());
			return EXIT_FAILURE;
		}
	} else {
		std::fprintf(stderr, "[!] Couldn't find encrypted payload in the flat file!\n");
		return EXIT_FAILURE;
	}
	getchar();
	return EXIT_SUCCESS;
}
